from flask_wtf import FlaskForm, RecaptchaField
from wtforms.validators import Email, Length, EqualTo, DataRequired
from wtforms import PasswordField, BooleanField, SubmitField, TextField
from wtforms.fields.html5 import EmailField

from app.users.models import Users 

class LoginForm(FlaskForm):
    email = EmailField("Email", [DataRequired(), Email()])
    password = PasswordField("Password", [DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    username = TextField("Username",  [DataRequired()])
    email = EmailField("Email", [DataRequired(), Email()])
    password = PasswordField("Password", [DataRequired(), Length(min=6, message="The min password length is 6 chars long.")])
    password_confirm = PasswordField("Confirm", [DataRequired(), EqualTo("password", message="Your passwords don't match.")])
    recaptcha = RecaptchaField()
    submit = SubmitField("Register")

    def validate(self):
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = Users.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append("Email already registered")
            return False
        return True

class RecoverPasswordForm(FlaskForm):
    email = EmailField('Email', [DataRequired(), Email(message=None), Length(min=6, max=255)])
    submit = SubmitField("Reset Password")

    def validate(self):
        initial_validation = super(RecoverPasswordForm, self).validate()
        if not initial_validation:
            return False
        user = Users.query.filter_by(email=self.email.data).first()
        if not user:
            self.email.errors.append("This email is not registered")
            return False
        return True

class SendEmailConfirmForm(FlaskForm):
    email = EmailField("Email", [DataRequired(), Email()])
    submit = SubmitField("Resend confirmation")

class ChangePasswordTokenForm(FlaskForm):
    password = PasswordField("Password", [DataRequired(), Length(min=8, message="The min password length is 12 chars long.")])
    password_confirm = PasswordField("Confirm", [DataRequired(), EqualTo("password", message="Your passwords don't match.")])
    submit = SubmitField("Change Password")

