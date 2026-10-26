"""Authentication and account-security forms."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp


class RegistrationForm(FlaskForm):
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
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=12, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords do not match."),
        ],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    identifier = StringField(
        "Username or email",
        validators=[DataRequired(), Length(min=3, max=255)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=1, max=128)],
    )
    submit = SubmitField("Sign in")


class TwoFactorForm(FlaskForm):
    code = StringField(
        "Authentication code or recovery code",
        validators=[DataRequired(), Length(min=6, max=64)],
    )
    submit = SubmitField("Verify and continue")


class SetupTwoFactorForm(FlaskForm):
    code = StringField(
        "Six-digit code",
        validators=[
            DataRequired(),
            Regexp(r"^\d{6}$", message="Enter the six-digit code."),
        ],
    )
    submit = SubmitField("Enable two-factor authentication")


class DisableTwoFactorForm(FlaskForm):
    password = PasswordField(
        "Current password",
        validators=[DataRequired(), Length(max=128)],
    )
    code = StringField(
        "Current two-factor code",
        validators=[
            DataRequired(),
            Regexp(r"^\d{6}$", message="Enter the six-digit code."),
        ],
    )
    submit = SubmitField("Disable two-factor authentication")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current password",
        validators=[DataRequired(), Length(max=128)],
    )
    new_password = PasswordField(
        "New password",
        validators=[DataRequired(), Length(min=12, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords do not match."),
        ],
    )
    submit = SubmitField("Update password")
