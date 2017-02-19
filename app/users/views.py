import datetime
from app import app, db, bcrypt, recaptcha, mail
from flask import Blueprint, render_template, url_for, flash, redirect, request, session
from .models import Users
from .forms import LoginForm, RegisterForm, RecoverPasswordForm, ChangePasswordTokenForm
from .utils import get_ip, is_safe_url, generate_confirmation_token, confirm_token,\
 send_email,password_reset_email, email_reset_notice
from flask_login import login_user, logout_user, current_user, login_required


users_blueprint = Blueprint("users", __name__, template_folder="templates")

@users_blueprint.route("/login/", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first() 
        if user is not None and bcrypt.check_password_hash(user.password, form.password.data):
            remember = form.remember.data
            user.login_count += 1
            user.last_login_ip = user.current_login_ip
            user.last_login_at = user.current_login_at
            user.current_login_ip = get_ip()
            user.current_login_at = datetime.datetime.now()
            db.session.add(user)
            db.session.commit()
            # cache.clear()
            login_user(user,remember)
            next = request.args.get("next")
            if not is_safe_url(next):
                return flask.abort(400)
            return redirect(next or url_for("home.index"))
        else:
            flash("<strong>Invalid Credentials.</strong> Please try again.", "danger")
            return redirect(url_for("users.login"))
    return render_template(
        "login.html",
        form=form
        )

@users_blueprint.route("/register/", methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if recaptcha.verify():
            user = Users(
                username = form.username.data,
                email = form.email.data,
                password = form.password.data,
                login_count = 1,
                current_login_ip = get_ip(),
                current_login_at = datetime.datetime.now()
                )
            print user
            
            db.session.add(user)
            db.session.commit()
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('users.confirm_email_register', token=token, _external=True)
            html = render_template("email/welcome.html", confirm_url=confirm_url, user=user)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)
            login_user(user,True)
            flash("Welcome <strong>%s</strong> to Menu App. Please go to your inbox and confirm your email." % (user.username), "success")
            next = request.args.get("next") 
            if not is_safe_url(next):
                return flask.abort(400)
            return redirect(next or url_for("home.index"))
        else:
            flash("Please try again", "danger")
            return redirect(url_for("users.register"))
    return render_template(
        "register.html",
        form=form
        )

@users_blueprint.route("/logout/")
@login_required
def logout():
    # referer = request.META.get('HTTP_REFERER', '')
    # print referer
    # session.pop("logged_in", None)
    # session.pop("session", None)
    # cache.clear()
    flash("You were logged out.", "danger")
    logout_user()
    return redirect(url_for('home.index')) 

@users_blueprint.route('/confirm/<token>/')
@login_required
def confirm_email_register(token):
    email = confirm_token(token)
    try:
        user = Users.query.filter_by(email=email).one_or_none()
        if user.confirmed:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.confirmed = True
            user.confirmed_at = datetime.datetime.now()
            db.session.add(user)
            db.session.commit()
            flash('You have confirmed your account. Thanks!', 'success')
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('home.index'))
    
    return redirect(url_for('home.index'))

@users_blueprint.route("/forgot-password/", methods=["GET","POST"])
def forgot_password():
    form = RecoverPasswordForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data, confirmed=True).one_or_none()
        if user is not None:
            password_reset_email(user.email)
            flash("password recovery email to %s" % user.email, "warning")
            return redirect(url_for("users.login"))
        else:
            flash("this account is not confirmed", "danger")
            return redirect(url_for("users.login"))
    return render_template(
        "forgot_password.html", 
        form=form
        )

@users_blueprint.route("/password-reset/<token>/", methods=["GET","POST"])
def forgot_password_reset_token(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = Users.query.filter_by(email=email).one_or_none()
    form = ChangePasswordTokenForm()
    if request.method == "POST": 
        user.password = form.password.data
        db.session.add(user)
        db.session.commit()
        email_reset_notice(user.email)
        flash("Successful password updated!", "success")
        # cache.clear()
        login_user(user,True)
        return redirect(url_for("home.index"))
    return render_template("forgot_password_change.html", form=form, token=token)