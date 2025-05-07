from flask_wtf import FlaskForm
from wtforms import validators
from wtforms.fields import *
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

class LoginForm(FlaskForm):
    email = EmailField(
        label="Email Address",
        validators=[DataRequired(), Email()],
        description="Enter your registered email"
    )
    password = PasswordField(
        label="Password",
        validators=[DataRequired()],
        description="Enter your password"
    )
    submit = SubmitField(label="Login")

class RegisterForm(FlaskForm):
    email = EmailField(
        label="Email Address",
        validators=[DataRequired(), Email()],
        description="You need to sign up with an email"
    )
    password = PasswordField(
        label="Create your password",
        validators=[
            DataRequired(),
            EqualTo('confirm', message="Passwords must match")
        ]
    )
    confirm = PasswordField(
        label="Confirm password",
        validators=[DataRequired()],
        description = "Make sure this entry matches your password"
    )
    submit = SubmitField(label="Register")
