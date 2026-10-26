"""Operational records used by the INPUTER and ADMIN dashboards."""

from __future__ import annotations

from app.extensions import db
from app.models.common import utcnow


class UserRecord(db.Model):
    __tablename__ = "user_records"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    owner = db.relationship("User", lazy="joined")

    def __repr__(self) -> str:
        return f"<UserRecord {self.id} owner={self.owner_id}>"
