"""Administrative forms."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp


class CreateUserForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=32),
            Regexp(
                r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
                message="Use letters, numbers, '.', '_' or '-'.",
            ),
        ],
    )
    email = StringField(
        "Email address",
        validators=[DataRequired(), Email(check_deliverability=False), Length(max=255)],
    )
    role_id = SelectField("Role", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Create user")


class ChangeRoleForm(FlaskForm):
    role_id = SelectField("Role", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Update role")


class ToggleActiveForm(FlaskForm):
    submit = SubmitField("Update status")


class AdminPasswordResetForm(FlaskForm):
    current_password = PasswordField(
        "Your current password",
        validators=[DataRequired(), Length(max=128)],
    )
    reason = TextAreaField(
        "Reason for reset",
        validators=[DataRequired(), Length(min=5, max=255)],
    )
    submit = SubmitField("Reset password")


class AdminTwoFactorResetForm(FlaskForm):
    current_password = PasswordField(
        "Your current password",
        validators=[DataRequired(), Length(max=128)],
    )
    reason = TextAreaField(
        "Reason for 2FA reset",
        validators=[DataRequired(), Length(min=5, max=255)],
    )
    submit = SubmitField("Reset two-factor authentication")


class RecordForm(FlaskForm):
    title = StringField(
        "Title",
        validators=[DataRequired(), Length(min=2, max=120)],
    )
    content = TextAreaField(
        "Details",
        validators=[DataRequired(), Length(max=5000)],
    )
    submit = SubmitField("Save record")
