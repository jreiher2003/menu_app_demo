from app import app, db
from flask import Blueprint, render_template, current_app
from flask_login import login_user, logout_user, current_user, login_required

home_blueprint = Blueprint("home", __name__, template_folder="templates")



@home_blueprint.route("/")
# @login_required
def index():
    return render_template("index.html")