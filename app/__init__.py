import os 
from flask import Flask 
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt 
from flask_login import LoginManager, current_user
from flask_recaptcha import ReCaptcha

app = Flask(__name__)
app.config.from_object(os.environ['APP_SETTINGS'])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app) 
recaptcha = ReCaptcha(app)
mail = Mail(app)



from app.home.views import home_blueprint 
app.register_blueprint(home_blueprint)
from app.users.views import users_blueprint 
app.register_blueprint(users_blueprint)
from app.profile.views import profile_blueprint 
app.register_blueprint(profile_blueprint)

from app.users.models import Users 

login_manager.login_view = "users.login"
login_manager.login_message = "You need to login first before you can continue." 
login_manager.login_message_category = "info"



@login_manager.user_loader 
def load_user(user_id):
    return Users.query.filter_by(id=int(user_id)).one_or_none()