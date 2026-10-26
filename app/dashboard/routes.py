"""Role-aware dashboards and operational records."""

from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user
from sqlalchemy import func

from app.admin.forms import RecordForm
from app.extensions import db
from app.models.common import utcnow
from app.models.record import UserRecord
from app.models.roles import Role
from app.models.security import LoginAttempt
from app.models.user import User
from app.security.audit import log_event
from app.security.decorators import permission_required

bp = Blueprint("dashboard", __name__)


@bp.get("/dashboard")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))
    role = current_user.role_name
    if role == "INPUTER":
        return redirect(url_for("dashboard.records"))
    if role == "MANAGER":
        return redirect(url_for("dashboard.reports"))
    if role in {"ADMIN", "ADMINISTRATOR"}:
        return redirect(url_for("admin.dashboard"))
    abort(403)


@bp.get("/records")
@permission_required("records.view_own")
def records():
    record_rows = list(
        db.session.scalars(
            db.select(UserRecord)
            .where(UserRecord.owner_id == current_user.id)
            .order_by(UserRecord.updated_at.desc())
        )
    )
    return render_template("dashboard/records.html", records=record_rows)


@bp.route("/records/new", methods=["GET", "POST"])
@permission_required("records.manage_own")
def new_record():
    form = RecordForm()
    if form.validate_on_submit():
        record = UserRecord(
            owner_id=current_user.id,
            title=form.title.data.strip(),
            content=form.content.data.strip(),
        )
        db.session.add(record)
        db.session.flush()
        log_event(
            "record.created",
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            details={"record_id": record.id},
        )
        db.session.commit()
        flash("Record created.", "success")
        return redirect(url_for("dashboard.records"))
    return render_template("dashboard/record_form.html", form=form, record=None)


@bp.route("/records/<int:record_id>/edit", methods=["GET", "POST"])
@permission_required("records.manage_own")
def edit_record(record_id: int):
    record = db.session.get(UserRecord, record_id)
    if record is None:
        abort(404)
    if record.owner_id != current_user.id:
        abort(403)

    form = RecordForm(obj=record)
    if form.validate_on_submit():
        record.title = form.title.data.strip()
        record.content = form.content.data.strip()
        log_event(
            "record.updated",
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            details={"record_id": record.id},
        )
        db.session.commit()
        flash("Record updated.", "success")
        return redirect(url_for("dashboard.records"))
    return render_template("dashboard/record_form.html", form=form, record=record)


@bp.get("/reports")
@permission_required("reports.view")
def reports():
    since = utcnow() - timedelta(days=30)
    total_records = int(
        db.session.scalar(db.select(db.func.count()).select_from(UserRecord)) or 0
    )
    records_last_30_days = int(
        db.session.scalar(
            db.select(db.func.count())
            .select_from(UserRecord)
            .where(UserRecord.created_at >= since)
        )
        or 0
    )
    active_users = int(
        db.session.scalar(
            db.select(db.func.count()).select_from(User).where(User.is_active.is_(True))
        )
        or 0
    )
    recent_logins = int(
        db.session.scalar(
            db.select(db.func.count())
            .select_from(LoginAttempt)
            .where(
                LoginAttempt.successful.is_(True),
                LoginAttempt.created_at >= since,
            )
        )
        or 0
    )
    role_counts = list(
        db.session.execute(
            db.select(Role.name, func.count(User.id))
            .join(User, User.role_id == Role.id)
            .group_by(Role.name)
            .order_by(Role.name)
        )
    )
    recent_records = list(
        db.session.scalars(
            db.select(UserRecord).order_by(UserRecord.created_at.desc()).limit(10)
        )
    )
    return render_template(
        "dashboard/reports.html",
        total_records=total_records,
        records_last_30_days=records_last_30_days,
        active_users=active_users,
        recent_logins=recent_logins,
        role_counts=role_counts,
        recent_records=recent_records,
    )
