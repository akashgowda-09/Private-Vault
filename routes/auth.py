from flask import Blueprint, render_template, request, redirect, session, flash, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import re

from models.db import users, otp_collection
from utils.otp import generate_otp
from utils.mail import send_otp_email

auth = Blueprint("auth", __name__)


# -------- PASSWORD CHECK --------
def is_strong_password(p):
    return len(p) >= 6 and re.search(r"[A-Za-z]", p) and re.search(r"[0-9]", p)


# -------- CLEAN EXPIRED OTPs --------
def cleanup_otps(email):
    otp_collection.delete_many({
        "email": email,
        "expires": {"$lt": datetime.datetime.utcnow()}
    })


# -------- SIGNUP --------
@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        contact = request.form["contact"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        # 🔥 NEW (GET PLAN FROM FORM)
        plan = request.form.get("plan", "free")

        if not re.fullmatch(r"\d{10}", contact):
            flash("Invalid phone number", "signup")
            return redirect("/signup")

        if users.find_one({"email": email}):
            flash("User already exists", "signup")
            return redirect("/signup")

        if password != confirm:
            flash("Passwords do not match", "signup")
            return redirect("/signup")

        if not is_strong_password(password):
            flash("Weak password", "signup")
            return redirect("/signup")

        otp = generate_otp()

        otp_collection.delete_many({"email": email})

        otp_collection.insert_one({
            "email": email,
            "otp": otp,
            "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            "type": "signup",

            # 🔥 IMPORTANT (PLAN STORED HERE)
            "data": {
                "name": name,
                "contact": contact,
                "password": generate_password_hash(password),
                "plan": request.form.get("plan", "free")
            }
        })

        send_otp_email(current_app, email, otp)

        session["email"] = email
        return redirect("/verify")

    return render_template("signup.html")


# -------- LOGIN --------
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = users.find_one({"email": email})

        if not user:
            flash("User not found")
            return render_template("login.html")   # 🔥 FIX

        # 🔒 block check
        if user.get("block_until") and user["block_until"] > datetime.datetime.utcnow():
            flash("Account blocked. Try later.")
            return render_template("login.html")   # 🔥 FIX

        # ❌ wrong password
        if not check_password_hash(user["password"], password):
            users.update_one({"email": email}, {"$inc": {"failed_attempts": 1}})
            updated = users.find_one({"email": email})

            if updated["failed_attempts"] >= 3:
                users.update_one(
                    {"email": email},
                    {"$set": {
                        "block_until": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
                        "failed_attempts": 0
                    }}
                )
                flash("Account blocked for 5 minutes")
            else:
                flash("Wrong password")

            return render_template("login.html")   # 🔥 FIX

        # ✅ correct password → reset attempts
        users.update_one({"email": email}, {"$set": {"failed_attempts": 0}})

        otp = generate_otp()

        otp_collection.delete_many({"email": email})

        otp_collection.insert_one({
            "email": email,
            "otp": otp,
            "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            "type": "login"
        })

        send_otp_email(current_app, email, otp)

        session["email"] = email
        return redirect("/verify")

    return render_template("login.html")

def mask_email(email):
    if not email:
        return ""
    name, domain = email.split("@")
    return name[:2] + "***@" + domain

# -------- VERIFY --------
@auth.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        otp_entered = request.form["otp"]
        email = session.get("email")

        cleanup_otps(email)

        record = otp_collection.find_one({"email": email}, sort=[("_id", -1)])

        if not record:
            flash("OTP not found")
            return redirect("/")

        if record["expires"] < datetime.datetime.utcnow():
            flash("OTP expired")
            return redirect("/")

        if record["otp"] != otp_entered:
            flash("Invalid OTP")
            return redirect("/verify")

        # -------- SIGNUP --------
        if record["type"] == "signup":
            data = record["data"]

            if users.find_one({"email": email}):
                flash("User already exists")
                return redirect("/")

            users.insert_one({
                "name": data["name"],
                "email": email,
                "contact": data["contact"],
                "password": data["password"],
                "failed_attempts": 0,
                "block_until": None,
                "created_at": datetime.datetime.utcnow(),

                # 🔥 PLAN SYSTEM
                "plan": "free",
                "plan_expiry": None
            })

        otp_collection.delete_many({"email": email})

        session["user"] = email

        # 🔥 FORCE PLAN SELECTION FIRST TIME
        user = users.find_one({"email": email})
        if not user.get("plan_expiry"):
            return redirect("/dashboard")

        return redirect("/dashboard")

    return render_template("otp.html", email=session.get("email"))


# -------- RESEND OTP --------
@auth.route("/resend-otp")
def resend_otp():
    email = session.get("email")

    if not email:
        return redirect("/login")

    otp = generate_otp()

    otp_collection.delete_many({"email": email})

    otp_collection.insert_one({
        "email": email,
        "otp": otp,
        "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        "type": "resend"
    })

    # ✅ SEND EMAIL
    send_otp_email(current_app, email, otp)

    return redirect("/verify")


# -------- LOGOUT --------
@auth.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -------- PROFILE --------
@auth.route("/get-profile")
def get_profile():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    user = users.find_one({"email": session["user"]})

    return jsonify({
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "phone": user.get("contact", ""),

        # 🔥 ADD THIS
        "plan": user.get("plan", "free"),
        "plan_expiry": user.get("plan_expiry").isoformat() if user.get("plan_expiry") else None
    })


@auth.route("/update-profile", methods=["POST"])
def update_profile():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json
    name = data.get("name", "")
    phone = data.get("phone", "")

    if not re.fullmatch(r"\d{10}", phone):
        return jsonify({"error": "Invalid phone number"}), 400

    users.update_one(
        {"email": session["user"]},
        {"$set": {
            "name": name,
            "contact": phone
        }}
    )

    return jsonify({"success": True})

@auth.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.json
    email = data.get("email")

    user = users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = generate_otp()

    otp_collection.delete_many({"email": email})

    otp_collection.insert_one({
        "email": email,
        "otp": otp,
        "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        "type": "forgot"
    })

    send_otp_email(current_app, email, otp)

    return jsonify({"success": True})

@auth.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json
    email = data.get("email")
    otp_entered = data.get("otp")

    cleanup_otps(email)

    record = otp_collection.find_one({"email": email}, sort=[("_id", -1)])

    if not record:
        return jsonify({"error": "OTP not found"}), 400

    if record["expires"] < datetime.datetime.utcnow():
        return jsonify({"error": "OTP expired"}), 400

    if record["otp"] != otp_entered:
        return jsonify({"error": "Invalid OTP"}), 400

    return jsonify({"success": True})

@auth.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    new_password = data.get("password")

    user = users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    hashed = generate_password_hash(new_password)

    users.update_one(
        {"email": email},
        {"$set": {"password": hashed}}
    )

    otp_collection.delete_many({"email": email})

    return jsonify({"success": True})

@auth.route("/activate-plan", methods=["POST"])
def activate_plan():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json
    plan = data.get("plan")
    duration = data.get("duration")

    user = users.find_one({"email": session["user"]})
    current_plan = user.get("plan", "free")

    levels = {
        "free": 0,
        "2gb": 1,
        "5gb": 2
    }

    # ❌ block downgrade only
    if levels.get(plan, 0) < levels.get(current_plan, 0):
        return jsonify({"error": "Cannot downgrade plan"}), 400

    expiry = None

    if plan != "free":
        now = datetime.datetime.now()

        if duration == "6m":
            expiry = now + datetime.timedelta(days=180)
        elif duration == "12m":
            expiry = now + datetime.timedelta(days=365)
        else:
            return jsonify({"error": "Invalid duration"}), 400

    users.update_one(
        {"email": session["user"]},
        {
            "$set": {
                "plan": plan,
                "plan_expiry": expiry
            }
        }
    )

    return jsonify({"success": True})

@auth.route("/plans")
def plans():
    if "user" not in session:
        return redirect("/login")

    return render_template("plans.html")