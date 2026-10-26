"""Operational CLI commands, including one-time administrator bootstrap."""

from __future__ import annotations

import hmac
import os
import re
from urllib.parse import urlsplit

import click
from email_validator import EmailNotValidError, validate_email
from flask import current_app
from flask.cli import with_appcontext
from sqlalchemy.exc import IntegrityError, OperationalError

from app.extensions import db
from app.models.roles import Role
from app.models.security import AuditLog
from app.models.user import User
from app.security.passwords import hash_password, validate_password_policy
from app.security.rbac import PRIVILEGED_ROLES
from app.services.rbac_seed import seed_reference_data

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")


def _normalise_username(value: str) -> str:
    return value.strip().lower()


def _normalise_email(value: str) -> str:
    try:
        result = validate_email(value.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise click.ClickException("Enter a valid email address.") from exc
    return result.normalized.lower()


def _bootstrap_password_errors(
    password: str,
    *,
    username: str,
    email: str,
    allow_weak: bool,
) -> list[str]:
    errors = validate_password_policy(password, username=username, email=email)
    if allow_weak:
        blocking_phrases = (
            "at least",
            "no more",
            "invalid character",
            "must not contain",
            "too common",
        )
        return [
            error
            for error in errors
            if any(phrase in error for phrase in blocking_phrases)
        ]
    return errors


@click.command("create-admin")
@click.option("--username", help="Administrator username. Prompted when omitted.")
@click.option("--email", help="Administrator email address. Prompted when omitted.")
@click.option(
    "--allow-weak-temporary-password",
    is_flag=True,
    help=(
        "Permit a temporary password that does not meet the full composition "
        "policy. A password change and 2FA setup are still mandatory."
    ),
)
@with_appcontext
def create_admin_command(
    username: str | None,
    email: str | None,
    allow_weak_temporary_password: bool,
) -> None:
    """Create the first ADMINISTRATOR exactly once, using a hidden prompt."""
    expected_token = os.getenv("BOOTSTRAP_TOKEN", "").strip()
    if len(expected_token) < 24:
        raise click.ClickException(
            "Set a BOOTSTRAP_TOKEN of at least 24 random characters before bootstrapping."
        )

    supplied_token = click.prompt("Bootstrap token", hide_input=True)
    if not hmac.compare_digest(supplied_token.strip(), expected_token):
        raise click.ClickException("Bootstrap authorisation failed.")

    try:
        seed_reference_data(commit=False)
        db.session.flush()
        administrator_count = db.session.scalar(
            db.select(db.func.count())
            .select_from(User)
            .join(Role)
            .where(Role.name == "ADMINISTRATOR")
        )
    except OperationalError as exc:
        db.session.rollback()
        raise click.ClickException(
            "Database schema is unavailable. Run 'flask db upgrade' first."
        ) from exc

    if administrator_count:
        db.session.rollback()
        raise click.ClickException(
            "An administrator already exists. Use the administrative UI for "
            "additional account provisioning."
        )

    supplied_username = username or click.prompt("Administrator username")
    canonical_username = _normalise_username(supplied_username)
    if not USERNAME_RE.fullmatch(canonical_username):
        raise click.ClickException(
            "Username must be 3-32 characters using letters, numbers, '.', '_' or '-'."
        )

    supplied_email = email or click.prompt("Administrator email")
    canonical_email = _normalise_email(supplied_email)

    if db.session.scalar(
        db.select(User).where(
            (User.username == canonical_username) | (User.email == canonical_email)
        )
    ):
        raise click.ClickException("That username or email is already in use.")

    password = click.prompt(
        "Administrator password",
        hide_input=True,
        confirmation_prompt=True,
    )
    password_errors = _bootstrap_password_errors(
        password,
        username=canonical_username,
        email=canonical_email,
        allow_weak=allow_weak_temporary_password,
    )
    if password_errors:
        raise click.ClickException(" ".join(password_errors))

    if allow_weak_temporary_password:
        click.echo(
            "Warning: temporary password composition override accepted. "
            "The account must change this password at first login.",
            err=True,
        )

    role = db.session.scalar(
        db.select(Role).where(Role.name == "ADMINISTRATOR")
    )
    if role is None:
        db.session.rollback()
        raise click.ClickException(
            "ADMINISTRATOR role is missing. Run 'flask db upgrade' first."
        )

    encoded_hash, pepper_version = hash_password(password)
    user = User(
        username=canonical_username,
        email=canonical_email,
        password_hash=encoded_hash,
        password_pepper_version=pepper_version,
        role=role,
        is_active=True,
        must_change_password=True,
        totp_enabled=False,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(
        AuditLog(
            actor_user_id=None,
            target_user_id=user.id,
            action="admin.bootstrap",
            outcome="success",
            details='{"method": "cli"}',
        )
    )
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise click.ClickException(
            "Administrator creation conflicted with an existing account."
        ) from exc
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Administrator bootstrap failed")
        raise click.ClickException("Administrator creation failed.") from exc

    click.echo(
        "Administrator created. First login requires a password change and "
        "two-factor authentication setup. Remove BOOTSTRAP_TOKEN from the environment."
    )


@click.command("seed-rbac")
@with_appcontext
def seed_rbac_command() -> None:
    """Create or refresh roles and permissions from the permission matrix."""
    try:
        seed_reference_data()
    except OperationalError as exc:
        db.session.rollback()
        raise click.ClickException(
            "Database schema is unavailable. Run 'flask db upgrade' first."
        ) from exc
    click.echo("Roles and permissions are synchronised.")


@click.command("config-check")
@with_appcontext
def config_check_command() -> None:
    """Print a non-sensitive summary of the loaded runtime configuration."""
    config = current_app.config
    database_scheme = urlsplit(str(config.get("SQLALCHEMY_DATABASE_URI", ""))).scheme
    click.echo(f"Environment: {config.get('FLASK_ENV')}")
    click.echo(f"Debug: {bool(config.get('DEBUG'))}")
    click.echo(f"Database scheme: {database_scheme or 'unset'}")
    click.echo(f"Secure session cookie: {bool(config.get('SESSION_COOKIE_SECURE'))}")
    click.echo(f"HTTPS enforcement: {bool(config.get('ENFORCE_HTTPS'))}")
    current_version = config.get("PASSWORD_PEPPER_VERSION")
    pepper_versions = sorted((config.get("PASSWORD_PEPPERS") or {}).keys())
    click.echo(f"Active pepper version: {current_version}")
    click.echo(f"Configured pepper versions: {pepper_versions}")
    click.echo(f"Rate limiting enabled: {bool(config.get('RATELIMIT_ENABLED'))}")
    click.echo(f"Two-factor privileged roles: {', '.join(sorted(PRIVILEGED_ROLES))}")


def register_cli(app) -> None:
    app.cli.add_command(create_admin_command)
    app.cli.add_command(seed_rbac_command)
    app.cli.add_command(config_check_command)
