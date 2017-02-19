from itsdangerous import URLSafeTimedSerializer
from urlparse import urlparse, urljoin
from app import app, mail
from app.users.models import Users 
from flask import request, url_for, current_app, render_template
from flask_mail import Message
from flask_login import current_user 

def get_ip():
    headers_list = request.headers.getlist("X-Forwarded-For")
    user_ip = headers_list[0] if headers_list else request.remote_addr
    return user_ip

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def generate_confirmation_token(email):
    t_salt = "thdfsfwewewrwrwjsljfalii3333"
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=t_salt)

def confirm_token(token, expriation=3600):
    t_salt = "thdfsfwewewrwrwjsljfalii3333"
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(token, salt=t_salt, max_age=expriation)
    except:
        return False
    return email 

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

#login forgot password link
def password_reset_email(email):
    user = Users.query.filter_by(email=email).one()
    token = generate_confirmation_token(user.email)
    reset_link = url_for('users.forgot_password_reset_token', token=token, _external=True)
    html = render_template("email/reset_instructions.html", reset_link=reset_link, user=user)
    subject = "reset instructions"
    send_email(user.email, subject, html)

def email_reset_notice(email):
    """ can handle all email reset emails """
    html = render_template("email/reset_notice.html")
    subject = "Password reset"
    send_email(email, subject, html)