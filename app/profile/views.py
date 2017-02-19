from app import app, db
from flask import Blueprint, render_template
from flask_login import login_required

profile_blueprint = Blueprint("profile", __name__, template_folder="templates")



@profile_blueprint.route("/profile/")
@login_required
def profile():
    return render_template("profile.html")