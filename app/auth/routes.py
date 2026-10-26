"""Authentication, two-factor, and account-security routes."""

from __future__ import annotations

import time
from datetime import timedelta
from urllib.parse import urlparse

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import lazyload

from app.auth.forms import (
    ChangePasswordForm,
    DisableTwoFactorForm,
    LoginForm,
    RegistrationForm,
    SetupTwoFactorForm,
    TwoFactorForm,
)
from app.extensions import db, limiter
from app.models.common import utcnow
from app.models.roles import Role
from app.models.security import PasswordReset, RecoveryCode
from app.models.user import User
from app.security.audit import log_event, record_login_attempt
from app.security.encryption import (
    SecretDecryptionError,
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    hash_recovery_code,
)
from app.security.passwords import (
    hash_password,
    upgrade_password_hash,
    validate_password_policy,
    verify_dummy_password,
    verify_password,
)
from app.security.totp import (
    build_provisioning_uri,
    create_totp_secret,
    qr_code_data_uri,
    verify_totp_code,
)

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _normalise_identifier(value: str) -> str:
    return value.strip().lower()


def _find_user(identifier: str) -> User | None:
    normalised = _normalise_identifier(identifier)
    return db.session.scalar(
        db.select(User).where(
            or_(
                func.lower(User.username) == normalised,
                func.lower(User.email) == normalised,
            )
        )
    )


def _safe_next_url(target: str | None) -> str | None:
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return None
    return target[:2048]


def _post_auth_redirect(user: User, next_url: str | None = None):
    if user.must_change_password:
        return redirect(url_for("auth.change_password"))
    if user.requires_2fa_setup:
        return redirect(url_for("auth.setup_2fa"))
    safe_next = _safe_next_url(next_url)
    if safe_next:
        return redirect(safe_next)
    return redirect(url_for("dashboard.index"))


def _complete_login(user: User, *, method: str) -> None:
    session.clear()
    login_user(user, remember=False, fresh=True)
    session.permanent = True
    session["auth_version"] = user.auth_version
    session["last_activity"] = time.time()

    user.last_login_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    user.two_factor_failed_count = 0
    user.two_factor_locked_until = None

    record_login_attempt(
        identifier=user.username,
        successful=True,
        reason="success",
        user_id=user.id,
        attempt_type=method,
    )
    log_event(
        "auth.login_success",
        actor_user_id=user.id,
        target_user_id=user.id,
        details={"method": method},
    )
    db.session.commit()


def _record_2fa_failure(user: User, *, method: str, reason: str) -> None:
    user.two_factor_failed_count = int(user.two_factor_failed_count or 0) + 1
    max_attempts = int(current_app.config["TOTP_MAX_FAILED_ATTEMPTS"])
    if user.two_factor_failed_count >= max_attempts:
        user.two_factor_locked_until = utcnow() + timedelta(
            minutes=int(current_app.config["TOTP_LOCKOUT_MINUTES"])
        )
    record_login_attempt(
        identifier=user.username,
        successful=False,
        reason=reason,
        user_id=user.id,
        attempt_type=method,
    )
    log_event(
        "auth.two_factor_failed",
        actor_user_id=user.id,
        target_user_id=user.id,
        outcome="failure",
        details={"method": method, "reason": reason},
    )
    db.session.commit()


def _expired_temporary_credential(user: User) -> bool:
    if not user.must_change_password:
        return False
    reset = db.session.scalar(
        db.select(PasswordReset)
        .where(
            PasswordReset.user_id == user.id,
            PasswordReset.used_at.is_(None),
        )
        .order_by(PasswordReset.created_at.desc())
    )
    return bool(reset and reset.expires_at < utcnow())


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        email = form.email.data.strip().lower()
        password = form.password.data

        existing = db.session.scalar(
            db.select(User).where(
                or_(
                    func.lower(User.username) == username,
                    func.lower(User.email) == email,
                )
            )
        )
        if existing:
            flash("That username or email is already registered.", "error")
            return render_template("auth/register.html", form=form)

        policy_errors = validate_password_policy(password, username=username, email=email)
        if policy_errors:
            for error in policy_errors:
                flash(error, "error")
            return render_template("auth/register.html", form=form)

        role = db.session.scalar(db.select(Role).where(Role.name == "INPUTER"))
        if role is None:
            current_app.logger.error("INPUTER role is missing from reference data")
            flash("Registration is temporarily unavailable.", "error")
            return render_template("auth/register.html", form=form), 503

        encoded_hash, pepper_version = hash_password(password)
        user = User(
            username=username,
            email=email,
            password_hash=encoded_hash,
            password_pepper_version=pepper_version,
            role=role,
            is_active=True,
        )
        try:
            db.session.add(user)
            db.session.flush()
            log_event(
                "auth.registration",
                actor_user_id=user.id,
                target_user_id=user.id,
                details={"role": role.name},
            )
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That username or email is already registered.", "error")
            return render_template("auth/register.html", form=form)
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Registration transaction failed")
            flash("Account creation failed. Please try again later.", "error")
            return render_template("auth/register.html", form=form), 500

        flash("Account created. Sign in to continue.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute;60 per hour", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    next_url = request.args.get("next") or request.form.get("next")

    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        password = form.password.data
        user = _find_user(identifier)

        if user is None:
            verify_dummy_password(password)
            record_login_attempt(
                identifier=_normalise_identifier(identifier),
                successful=False,
                reason="unknown_identifier",
            )
            log_event(
                "auth.login_failed",
                outcome="failure",
                details={"reason": "unknown_identifier"},
            )
            db.session.commit()
            flash("Invalid username/email or password.", "error")
            return render_template("auth/login.html", form=form, next_url=next_url), 401

        now = utcnow()
        if user.locked_until and user.locked_until <= now:
            user.failed_login_count = 0
            user.locked_until = None

        if user.is_locked:
            record_login_attempt(
                identifier=user.username,
                successful=False,
                reason="account_locked",
                user_id=user.id,
            )
            log_event(
                "auth.login_blocked",
                actor_user_id=user.id,
                target_user_id=user.id,
                outcome="failure",
                details={"reason": "account_locked"},
            )
            db.session.commit()
            flash("Invalid username/email or password.", "error")
            return render_template("auth/login.html", form=form, next_url=next_url), 401

        if not verify_password(password, user.password_hash, user.password_pepper_version):
            user.failed_login_count = int(user.failed_login_count or 0) + 1
            max_attempts = int(current_app.config["LOGIN_MAX_FAILED_ATTEMPTS"])
            if user.failed_login_count >= max_attempts:
                user.locked_until = utcnow() + timedelta(
                    minutes=int(current_app.config["LOGIN_LOCKOUT_MINUTES"])
                )
            record_login_attempt(
                identifier=user.username,
                successful=False,
                reason="invalid_password",
                user_id=user.id,
            )
            log_event(
                "auth.login_failed",
                actor_user_id=user.id,
                target_user_id=user.id,
                outcome="failure",
                details={"reason": "invalid_password"},
            )
            db.session.commit()
            flash("Invalid username/email or password.", "error")
            return render_template("auth/login.html", form=form, next_url=next_url), 401

        if not user.is_active:
            record_login_attempt(
                identifier=user.username,
                successful=False,
                reason="inactive_account",
                user_id=user.id,
            )
            log_event(
                "auth.login_blocked",
                actor_user_id=user.id,
                target_user_id=user.id,
                outcome="failure",
                details={"reason": "inactive_account"},
            )
            db.session.commit()
            flash("Invalid username/email or password.", "error")
            return render_template("auth/login.html", form=form, next_url=next_url), 401

        if _expired_temporary_credential(user):
            record_login_attempt(
                identifier=user.username,
                successful=False,
                reason="expired_temporary_credential",
                user_id=user.id,
            )
            log_event(
                "auth.login_blocked",
                actor_user_id=user.id,
                target_user_id=user.id,
                outcome="failure",
                details={"reason": "expired_temporary_credential"},
            )
            db.session.commit()
            flash(
                "This temporary password has expired. Contact an administrator.",
                "error",
            )
            return render_template("auth/login.html", form=form, next_url=next_url), 401

        user.failed_login_count = 0
        user.locked_until = None
        upgrade_password_hash(user, password)

        if user.totp_enabled:
            session.clear()
            session.permanent = True
            session["pre_2fa_user_id"] = user.id
            session["pre_2fa_started"] = time.time()
            session["pre_2fa_auth_version"] = user.auth_version
            safe_next = _safe_next_url(next_url)
            if safe_next:
                session["post_auth_next"] = safe_next
            record_login_attempt(
                identifier=user.username,
                successful=False,
                reason="primary_factor_ok",
                user_id=user.id,
                attempt_type="password",
            )
            log_event(
                "auth.primary_factor_ok",
                actor_user_id=user.id,
                target_user_id=user.id,
                details={"method": "password"},
            )
            db.session.commit()
            return redirect(url_for("auth.verify_2fa"))

        _complete_login(user, method="password")
        flash("Signed in successfully.", "success")
        return _post_auth_redirect(user, next_url)

    return render_template("auth/login.html", form=form, next_url=next_url)


@bp.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute;40 per hour", methods=["POST"])
def verify_2fa():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    pending_id = session.get("pre_2fa_user_id")
    started = session.get("pre_2fa_started")
    if not pending_id or not started:
        flash("Sign in to continue.", "warning")
        return redirect(url_for("auth.login"))

    try:
        elapsed = time.time() - float(started)
    except (TypeError, ValueError):
        elapsed = current_app.config["PRE_2FA_LIFETIME"].total_seconds() + 1
    if elapsed > current_app.config["PRE_2FA_LIFETIME"].total_seconds():
        session.clear()
        flash("Verification expired. Sign in again.", "warning")
        return redirect(url_for("auth.login"))

    pending_user = db.session.get(User, int(pending_id))
    if (
        pending_user is None
        or not pending_user.is_active
        or session.get("pre_2fa_auth_version") != pending_user.auth_version
    ):
        session.clear()
        flash("Verification is no longer valid. Sign in again.", "warning")
        return redirect(url_for("auth.login"))

    form = TwoFactorForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            db.select(User)
            .where(User.id == int(pending_id))
            .options(lazyload(User.role))
            .with_for_update(of=User)
            .execution_options(populate_existing=True)
        )
        if user is None or not user.totp_enabled or not user.totp_secret_enc:
            session.clear()
            flash("Verification is unavailable. Sign in again.", "warning")
            return redirect(url_for("auth.login"))

        if user.is_two_factor_locked:
            record_login_attempt(
                identifier=user.username,
                successful=False,
                reason="two_factor_locked",
                user_id=user.id,
                attempt_type="two_factor",
            )
            log_event(
                "auth.two_factor_blocked",
                actor_user_id=user.id,
                target_user_id=user.id,
                outcome="failure",
                details={"reason": "two_factor_locked"},
            )
            db.session.commit()
            flash("Invalid or expired authentication code.", "error")
            return render_template("auth/verify_2fa.html", form=form), 401

        supplied = form.code.data.strip()
        method = "recovery_code"
        success = False
        matched_counter = None
        failure_reason = "invalid_code"

        if supplied.isdigit() and len(supplied) == 6:
            method = "totp"
            try:
                secret = decrypt_secret(user.totp_secret_enc)
                result = verify_totp_code(
                    secret,
                    supplied,
                    last_counter=user.totp_last_counter,
                    interval=int(current_app.config["TOTP_INTERVAL"]),
                    digits=int(current_app.config["TOTP_DIGITS"]),
                    valid_window=int(current_app.config["TOTP_VALID_WINDOW"]),
                )
            except SecretDecryptionError:
                current_app.logger.error("TOTP secret decryption failed during login")
                result = None
            if result and result.valid:
                success = True
                matched_counter = result.counter
            elif result and result.reason == "replay":
                failure_reason = "totp_replay"
        else:
            normalised = "".join(character for character in supplied if character.isalnum())
            if len(normalised) >= 16:
                code_hash = hash_recovery_code(supplied)
                recovery = db.session.scalar(
                    db.select(RecoveryCode).where(
                        RecoveryCode.user_id == user.id,
                        RecoveryCode.code_hash == code_hash,
                        RecoveryCode.used_at.is_(None),
                    )
                )
                if recovery is not None:
                    recovery.used_at = utcnow()
                    recovery.used_ip = request.remote_addr
                    success = True
            if not success:
                failure_reason = "invalid_recovery_code"

        if success:
            if matched_counter is not None:
                user.totp_last_counter = int(matched_counter)
            user.two_factor_failed_count = 0
            user.two_factor_locked_until = None
            next_url = _safe_next_url(session.get("post_auth_next"))
            _complete_login(user, method=method)
            flash("Two-factor authentication verified.", "success")
            return _post_auth_redirect(user, next_url)

        _record_2fa_failure(user, method=method, reason=failure_reason)
        flash("Invalid or expired authentication code.", "error")
        return render_template("auth/verify_2fa.html", form=form), 401

    return render_template("auth/verify_2fa.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user.id
    log_event(
        "auth.logout",
        actor_user_id=user_id,
        target_user_id=user_id,
    )
    db.session.commit()
    logout_user()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not verify_password(
            form.current_password.data,
            current_user.password_hash,
            current_user.password_pepper_version,
        ):
            log_event(
                "account.password_change_failed",
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                outcome="failure",
                details={"reason": "invalid_current_password"},
            )
            db.session.commit()
            flash("Current password is incorrect.", "error")
            return render_template("auth/change_password.html", form=form), 400

        new_password = form.new_password.data
        if new_password == form.current_password.data:
            flash("Choose a password different from the current password.", "error")
            return render_template("auth/change_password.html", form=form), 400

        policy_errors = validate_password_policy(
            new_password,
            username=current_user.username,
            email=current_user.email,
        )
        if policy_errors:
            for error in policy_errors:
                flash(error, "error")
            return render_template("auth/change_password.html", form=form), 400

        encoded_hash, pepper_version = hash_password(new_password)
        current_user.password_hash = encoded_hash
        current_user.password_pepper_version = pepper_version
        current_user.password_changed_at = utcnow()
        current_user.must_change_password = False
        current_user.invalidate_sessions()
        session["auth_version"] = current_user.auth_version

        active_reset = db.session.scalar(
            db.select(PasswordReset)
            .where(
                PasswordReset.user_id == current_user.id,
                PasswordReset.used_at.is_(None),
            )
            .order_by(PasswordReset.created_at.desc())
        )
        if active_reset:
            active_reset.used_at = utcnow()

        log_event(
            "account.password_changed",
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
        )
        db.session.commit()
        flash("Password updated successfully.", "success")

        if current_user.requires_2fa_setup:
            return redirect(url_for("auth.setup_2fa"))
        return redirect(url_for("auth.account"))

    return render_template("auth/change_password.html", form=form)


@bp.route("/account")
@login_required
def account():
    active_recovery_codes = db.session.scalar(
        db.select(db.func.count())
        .select_from(RecoveryCode)
        .where(
            RecoveryCode.user_id == current_user.id,
            RecoveryCode.used_at.is_(None),
        )
    )
    disable_form = DisableTwoFactorForm()
    return render_template(
        "auth/account.html",
        active_recovery_codes=active_recovery_codes,
        disable_form=disable_form,
    )


@bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if current_user.totp_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("auth.account"))

    if not current_user.totp_secret_enc:
        secret = create_totp_secret()
        current_user.totp_secret_enc = encrypt_secret(secret)
        db.session.commit()
    else:
        try:
            secret = decrypt_secret(current_user.totp_secret_enc)
        except SecretDecryptionError:
            current_app.logger.error("Pending TOTP secret could not be decrypted; replacing")
            secret = create_totp_secret()
            current_user.totp_secret_enc = encrypt_secret(secret)
            db.session.commit()

    provisioning_uri = build_provisioning_uri(
        secret,
        username=current_user.username,
        issuer=str(current_app.config["TOTP_ISSUER"]),
    )
    qr_uri = qr_code_data_uri(provisioning_uri)
    form = SetupTwoFactorForm()

    if form.validate_on_submit():
        result = verify_totp_code(
            secret,
            form.code.data,
            last_counter=current_user.totp_last_counter,
            interval=int(current_app.config["TOTP_INTERVAL"]),
            digits=int(current_app.config["TOTP_DIGITS"]),
            valid_window=int(current_app.config["TOTP_VALID_WINDOW"]),
        )
        if not result.valid:
            log_event(
                "auth.two_factor_setup_failed",
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                outcome="failure",
                details={"reason": result.reason},
            )
            db.session.commit()
            flash("Invalid authentication code. Try again.", "error")
            return render_template(
                "auth/setup_2fa.html",
                form=form,
                qr_uri=qr_uri,
                manual_secret=secret,
            ), 400

        current_user.totp_enabled = True
        current_user.totp_confirmed_at = utcnow()
        current_user.totp_last_counter = int(result.counter or 0)
        current_user.two_factor_failed_count = 0
        current_user.two_factor_locked_until = None

        db.session.execute(
            db.delete(RecoveryCode).where(RecoveryCode.user_id == current_user.id)
        )
        recovery_codes = generate_recovery_codes(
            int(current_app.config["RECOVERY_CODE_COUNT"])
        )
        for code in recovery_codes:
            db.session.add(
                RecoveryCode(
                    user_id=current_user.id,
                    code_hash=hash_recovery_code(code),
                )
            )
        log_event(
            "auth.two_factor_enabled",
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            details={"method": "totp"},
        )
        db.session.commit()
        return render_template(
            "auth/setup_2fa_complete.html",
            recovery_codes=recovery_codes,
        )

    return render_template(
        "auth/setup_2fa.html",
        form=form,
        qr_uri=qr_uri,
        manual_secret=secret,
    )


@bp.post("/2fa/disable")
@login_required
def disable_2fa():
    if current_user.is_privileged:
        abort(403)
    if not current_user.totp_enabled:
        flash("Two-factor authentication is not enabled.", "info")
        return redirect(url_for("auth.account"))

    form = DisableTwoFactorForm()
    if not form.validate_on_submit():
        flash("Provide your password and a valid authentication code.", "error")
        return redirect(url_for("auth.account"))

    if not verify_password(
        form.password.data,
        current_user.password_hash,
        current_user.password_pepper_version,
    ):
        log_event(
            "auth.two_factor_disable_failed",
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            outcome="failure",
            details={"reason": "invalid_password"},
        )
        db.session.commit()
        flash("Password or authentication code is invalid.", "error")
        return redirect(url_for("auth.account"))

    assert current_user.totp_secret_enc is not None
    try:
        secret = decrypt_secret(current_user.totp_secret_enc)
    except SecretDecryptionError:
        current_app.logger.error("TOTP secret decryption failed during disable")
        flash("Two-factor settings could not be read. Contact an administrator.", "error")
        return redirect(url_for("auth.account"))

    result = verify_totp_code(
        secret,
        form.code.data,
        last_counter=current_user.totp_last_counter,
        interval=int(current_app.config["TOTP_INTERVAL"]),
        digits=int(current_app.config["TOTP_DIGITS"]),
        valid_window=int(current_app.config["TOTP_VALID_WINDOW"]),
    )
    if not result.valid:
        log_event(
            "auth.two_factor_disable_failed",
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            outcome="failure",
            details={"reason": "invalid_code"},
        )
        db.session.commit()
        flash("Password or authentication code is invalid.", "error")
        return redirect(url_for("auth.account"))

    current_user.totp_last_counter = int(result.counter or 0)
    current_user.totp_enabled = False
    current_user.totp_secret_enc = None
    current_user.totp_confirmed_at = None
    current_user.two_factor_failed_count = 0
    current_user.two_factor_locked_until = None
    db.session.execute(
        db.delete(RecoveryCode).where(RecoveryCode.user_id == current_user.id)
    )
    current_user.invalidate_sessions()
    session["auth_version"] = current_user.auth_version
    log_event(
        "auth.two_factor_disabled",
        actor_user_id=current_user.id,
        target_user_id=current_user.id,
    )
    db.session.commit()
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("auth.account"))
