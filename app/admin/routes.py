"""Administrative user, security, audit, and record-management routes."""

from __future__ import annotations

from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.admin.forms import (
    AdminPasswordResetForm,
    AdminTwoFactorResetForm,
    CreateUserForm,
    RecordForm,
)
from app.extensions import db
from app.models.common import utcnow
from app.models.record import UserRecord
from app.models.roles import Role
from app.models.security import AuditLog, PasswordReset, RecoveryCode
from app.models.user import User
from app.security.audit import log_event
from app.security.decorators import permission_required
from app.security.passwords import (
    generate_temporary_password,
    hash_password,
    validate_password_policy,
    verify_password,
)
from app.security.rbac import assignable_role_names

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _target_or_404(user_id: int) -> User:
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    return user


def _enforce_manageable(target: User) -> None:
    if target.role.rank > current_user.role.rank:
        abort(403)


def _enforce_not_self(target: User) -> None:
    if target.id == current_user.id:
        flash("Use your own account settings for this action.", "error")
        abort(400)


def _active_administrator_count(excluding_id: int | None = None) -> int:
    statement = (
        db.select(db.func.count())
        .select_from(User)
        .join(Role)
        .where(Role.name == "ADMINISTRATOR", User.is_active.is_(True))
    )
    if excluding_id is not None:
        statement = statement.where(User.id != excluding_id)
    return int(db.session.scalar(statement) or 0)


def _available_roles() -> list[Role]:
    names = assignable_role_names(current_user.role.rank)
    return list(
        db.session.scalars(
            db.select(Role).where(Role.name.in_(names)).order_by(Role.rank.asc())
        )
    )


@bp.get("/")
@permission_required("admin.view")
def dashboard():
    active_users = int(
        db.session.scalar(
            db.select(db.func.count()).select_from(User).where(User.is_active.is_(True))
        )
        or 0
    )
    locked_users = int(
        db.session.scalar(
            db.select(db.func.count())
            .select_from(User)
            .where(User.locked_until.is_not(None), User.locked_until > utcnow())
        )
        or 0
    )
    two_factor_users = int(
        db.session.scalar(
            db.select(db.func.count())
            .select_from(User)
            .where(User.totp_enabled.is_(True))
        )
        or 0
    )
    recent_events = list(
        db.session.scalars(
            db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(8)
        )
    )
    return render_template(
        "admin/dashboard.html",
        active_users=active_users,
        locked_users=locked_users,
        two_factor_users=two_factor_users,
        recent_events=recent_events,
    )


@bp.get("/users")
@permission_required("users.view")
def users():
    user_rows = list(
        db.session.scalars(db.select(User).order_by(User.created_at.desc()))
    )
    available_roles = _available_roles() if current_user.has_permission("users.manage") else []
    return render_template(
        "admin/users.html",
        users=user_rows,
        available_roles=available_roles,
    )


@bp.route("/users/create", methods=["GET", "POST"])
@permission_required("users.manage")
def create_user():
    available_roles = _available_roles()
    form = CreateUserForm()
    form.role_id.choices = [(role.id, role.name) for role in available_roles]

    if form.validate_on_submit():
        selected_role = db.session.get(Role, form.role_id.data)
        if selected_role is None or selected_role.name not in assignable_role_names(
            current_user.role.rank
        ):
            abort(403)

        username = form.username.data.strip().lower()
        email = form.email.data.strip().lower()
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
            return render_template(
                "admin/user_create.html", form=form, available_roles=available_roles
            )

        temporary_password = generate_temporary_password()
        for _ in range(5):
            if not validate_password_policy(
                temporary_password, username=username, email=email
            ):
                break
            temporary_password = generate_temporary_password()

        encoded_hash, pepper_version = hash_password(temporary_password)
        user = User(
            username=username,
            email=email,
            password_hash=encoded_hash,
            password_pepper_version=pepper_version,
            role=selected_role,
            is_active=True,
            must_change_password=True,
        )
        try:
            db.session.add(user)
            db.session.flush()
            log_event(
                "admin.user_created",
                actor_user_id=current_user.id,
                target_user_id=user.id,
                details={"role": selected_role.name},
            )
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That username or email is already registered.", "error")
            return render_template(
                "admin/user_create.html", form=form, available_roles=available_roles
            )
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Administrative user creation failed")
            flash("The account could not be created.", "error")
            return (
                render_template(
                    "admin/user_create.html",
                    form=form,
                    available_roles=available_roles,
                ),
                500,
            )

        return render_template(
            "admin/user_created.html",
            created_user=user,
            temporary_password=temporary_password,
        )

    return render_template(
        "admin/user_create.html", form=form, available_roles=available_roles
    )


@bp.post("/users/<int:user_id>/toggle")
@permission_required("users.manage")
def toggle_user(user_id: int):
    target = _target_or_404(user_id)
    _enforce_manageable(target)
    _enforce_not_self(target)

    if (
        target.is_active
        and target.role.name == "ADMINISTRATOR"
        and _active_administrator_count(excluding_id=target.id) == 0
    ):
        flash("The last active administrator cannot be deactivated.", "error")
        return redirect(url_for("admin.users"))

    target.is_active = not target.is_active
    if not target.is_active:
        target.invalidate_sessions()
    log_event(
        "admin.user_activated" if target.is_active else "admin.user_deactivated",
        actor_user_id=current_user.id,
        target_user_id=target.id,
    )
    db.session.commit()
    flash(
        f"Account {target.username} is now "
        f"{'active' if target.is_active else 'deactivated'}.",
        "success",
    )
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/role")
@permission_required("users.manage", "roles.assign")
def change_role(user_id: int):
    target = _target_or_404(user_id)
    _enforce_manageable(target)
    _enforce_not_self(target)

    try:
        role_id = int(request.form.get("role_id", ""))
    except (TypeError, ValueError):
        abort(400)
    new_role = db.session.get(Role, role_id)
    if new_role is None:
        abort(400)
    if new_role.name not in assignable_role_names(current_user.role.rank):
        abort(403)

    if (
        target.role.name == "ADMINISTRATOR"
        and new_role.name != "ADMINISTRATOR"
        and target.is_active
        and _active_administrator_count(excluding_id=target.id) == 0
    ):
        flash("The last active administrator cannot be demoted.", "error")
        return redirect(url_for("admin.users"))

    old_role = target.role.name
    target.role = new_role
    target.invalidate_sessions()
    log_event(
        "admin.user_role_changed",
        actor_user_id=current_user.id,
        target_user_id=target.id,
        details={"from": old_role, "to": new_role.name},
    )
    db.session.commit()
    flash(f"Role updated for {target.username}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/reset-password", methods=["GET", "POST"])
@permission_required("users.manage")
def reset_password(user_id: int):
    target = _target_or_404(user_id)
    _enforce_manageable(target)
    _enforce_not_self(target)

    form = AdminPasswordResetForm()
    if form.validate_on_submit():
        if not verify_password(
            form.current_password.data,
            current_user.password_hash,
            current_user.password_pepper_version,
        ):
            log_event(
                "admin.password_reset_failed",
                actor_user_id=current_user.id,
                target_user_id=target.id,
                outcome="failure",
                details={"reason": "administrator_reauthentication_failed"},
            )
            db.session.commit()
            flash("Your current password is incorrect.", "error")
            return render_template(
                "admin/reset_password.html", form=form, target=target
            ), 400

        temporary_password = generate_temporary_password()
        for _ in range(5):
            if not validate_password_policy(
                temporary_password, username=target.username, email=target.email
            ):
                break
            temporary_password = generate_temporary_password()

        encoded_hash, pepper_version = hash_password(temporary_password)
        target.password_hash = encoded_hash
        target.password_pepper_version = pepper_version
        target.must_change_password = True
        target.password_changed_at = utcnow()
        target.invalidate_sessions()

        now = utcnow()
        existing_resets = db.session.scalars(
            db.select(PasswordReset).where(
                PasswordReset.user_id == target.id,
                PasswordReset.used_at.is_(None),
            )
        )
        for existing in existing_resets:
            existing.used_at = now

        db.session.add(
            PasswordReset(
                user_id=target.id,
                performed_by_id=current_user.id,
                method="administrative",
                reason=form.reason.data.strip(),
                expires_at=now
                + timedelta(hours=int(current_app.config["PASSWORD_RESET_TTL_HOURS"])),
            )
        )
        log_event(
            "admin.password_reset",
            actor_user_id=current_user.id,
            target_user_id=target.id,
            details={"method": "administrative"},
        )
        db.session.commit()
        return render_template(
            "admin/password_reset_result.html",
            target=target,
            temporary_password=temporary_password,
        )

    return render_template("admin/reset_password.html", form=form, target=target)


@bp.route("/users/<int:user_id>/reset-2fa", methods=["GET", "POST"])
@permission_required("users.manage", "security.manage")
def reset_two_factor(user_id: int):
    target = _target_or_404(user_id)
    _enforce_manageable(target)
    _enforce_not_self(target)

    form = AdminTwoFactorResetForm()
    if form.validate_on_submit():
        if not verify_password(
            form.current_password.data,
            current_user.password_hash,
            current_user.password_pepper_version,
        ):
            log_event(
                "admin.two_factor_reset_failed",
                actor_user_id=current_user.id,
                target_user_id=target.id,
                outcome="failure",
                details={"reason": "administrator_reauthentication_failed"},
            )
            db.session.commit()
            flash("Your current password is incorrect.", "error")
            return render_template(
                "admin/reset_2fa.html", form=form, target=target
            ), 400

        target.totp_secret_enc = None
        target.totp_enabled = False
        target.totp_confirmed_at = None
        target.totp_last_counter = -1
        target.two_factor_failed_count = 0
        target.two_factor_locked_until = None
        target.invalidate_sessions()
        db.session.execute(
            db.delete(RecoveryCode).where(RecoveryCode.user_id == target.id)
        )
        log_event(
            "admin.two_factor_reset",
            actor_user_id=current_user.id,
            target_user_id=target.id,
            details={"reason": form.reason.data.strip()},
        )
        db.session.commit()
        flash(
            f"Two-factor authentication reset for {target.username}. "
            "The account must enrol again where required.",
            "success",
        )
        return redirect(url_for("admin.users"))

    return render_template("admin/reset_2fa.html", form=form, target=target)


@bp.get("/audit")
@permission_required("audit.view")
def audit_log():
    entries = list(
        db.session.scalars(
            db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)
        )
    )
    return render_template("admin/audit.html", entries=entries)


@bp.get("/records")
@permission_required("records.moderate")
def records():
    record_rows = list(
        db.session.scalars(
            db.select(UserRecord).order_by(UserRecord.updated_at.desc()).limit(200)
        )
    )
    return render_template("admin/records.html", records=record_rows)


@bp.route("/records/<int:record_id>/edit", methods=["GET", "POST"])
@permission_required("records.moderate")
def edit_record(record_id: int):
    record = db.session.get(UserRecord, record_id)
    if record is None:
        abort(404)

    form = RecordForm(obj=record)
    if form.validate_on_submit():
        record.title = form.title.data.strip()
        record.content = form.content.data.strip()
        log_event(
            "admin.record_updated",
            actor_user_id=current_user.id,
            target_user_id=record.owner_id,
            details={"record_id": record.id},
        )
        db.session.commit()
        flash("Record updated.", "success")
        return redirect(url_for("admin.records"))

    return render_template("admin/edit_record.html", form=form, record=record)
