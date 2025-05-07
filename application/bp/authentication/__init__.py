from flask import Blueprint, render_template, redirect, url_for, flash, request
from application.bp.authentication.forms import RegisterForm, LoginForm
from flask import *
from application.database import User, db
from application.bp.authentication.forms import *
from application.bp.authentication.forms import RegisterForm
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

authentication = Blueprint('authentication', __name__, template_folder='templates')

@authentication.route("/registration", methods = ['POST', 'GET'])
def registration():
    form = RegisterForm()
    if form.validate_on_submit():
        user_check = User.find_user_by_email(form.email.data)
        if user_check is None:
            user = User.create(form.email.data, form.password.data)
            user.save()
        else:
            flash("Already Registered!")

    return render_template('registration.html', form=form)

@authentication.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('User Not Found', 'error')
            return redirect(url_for('authentication.login'))

        if not check_password_hash(user.password, form.password.data):
            flash('Password Incorrect', 'error')
            return redirect(url_for('authentication.login'))

        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('authentication.dashboard'))

    return render_template('login.html', form=form)

@authentication.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@authentication.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('homepage.homepage'))