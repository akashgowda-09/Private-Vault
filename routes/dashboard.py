from flask import Blueprint, render_template, session, redirect
from models.db import users, files

dashboard = Blueprint("dashboard", __name__)

@dashboard.route("/dashboard")
def home():
    if "user" not in session:
        return redirect("/login")

    user = users.find_one({"email": session["user"]})
    user_files = list(files.find({"user_email": session["user"]}))

    return render_template("dashboard.html", user=user, files=user_files)