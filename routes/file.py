from flask import Blueprint, request, redirect, session, flash, Response, jsonify, render_template
from datetime import datetime, timedelta
import cloudinary.uploader
import uuid
import requests
import mimetypes
import random
from utils.crypto import encrypt_file, decrypt_file
from models.db import files, shares, users   # 🔥 ADDED users
from werkzeug.security import generate_password_hash, check_password_hash
file_bp = Blueprint("file", __name__)   

# 🔒 ALLOWED FILE TYPES
ALLOWED_EXTENSIONS = (".pdf", ".jpg", ".jpeg", ".png", ".docx", ".pptx")


# -------- STORAGE LIMIT FUNCTION (NEW) --------
def get_storage_limit(user):
    plan = user.get("plan", "free")

    limits = {
        "free": 500 * 1024 * 1024,
        "2gb": 2 * 1024 * 1024 * 1024,
        "5gb": 5 * 1024 * 1024 * 1024
    }

    return limits.get(plan, limits["free"])


# -------- UPLOAD --------
@file_bp.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return redirect("/login")

    file = request.files.get("file")

    if not file:
        flash("No file selected")
        return redirect("/dashboard")

    # size
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)

    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        flash("File type not allowed")
        return redirect("/dashboard")

    # 🔥 STORAGE CHECK (ADDED)
    user = users.find_one({"email": session["user"]})
    user_files = list(files.find({"user_email": session["user"]}))
    used = sum(f.get("size", 0) for f in user_files)

    limit = get_storage_limit(user)

    if used + size > limit:
        flash("Storage limit exceeded")
        return redirect("/dashboard")

    mode = request.form.get("mode", "insecure")
    file_bytes = file.read()

    if mode == "secure":
        enc = encrypt_file(file_bytes)
        upload_data = enc["data"]
        encryption_key = enc["key"]
        is_encrypted = True
        upload_type = "private"
    else:
        upload_data = file_bytes
        encryption_key = None
        is_encrypted = False
        upload_type = "upload"

    result = cloudinary.uploader.upload(
        upload_data,
        resource_type="auto",
        type=upload_type
    )

    file_id = str(uuid.uuid4())

    files.insert_one({
        "file_id": file_id,
        "user_email": session["user"],
        "filename": file.filename,
        "cloud_url": result["secure_url"],
        "size": size,
        "uploaded_at": datetime.now(),
        "is_encrypted": is_encrypted,
        "encryption_key": encryption_key
    })

    flash("File uploaded successfully", "upload")
    return redirect("/dashboard")


# -------- VIEW FILE --------
@file_bp.route("/file/<file_id>")
def get_file(file_id):
    if "user" not in session:
        return redirect("/login")

    file = files.find_one({"file_id": file_id})

    if not file or file["user_email"] != session["user"]:
        return "Unauthorized"

    # 🔓 INSECURE
    if not file.get("is_encrypted"):
        return redirect(file["cloud_url"])

    # 🔐 SECURE
    file_data = requests.get(file["cloud_url"]).content
    file_data = decrypt_file(file_data, file["encryption_key"])

    mime_type, _ = mimetypes.guess_type(file["filename"])
    mime_type = mime_type or "application/octet-stream"

    return Response(file_data, content_type=mime_type)


# -------- CREATE SHARE --------
@file_bp.route("/create-share/<file_id>", methods=["POST"])
def create_share(file_id):
    if "user" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    file = files.find_one({
        "file_id": file_id,
        "user_email": session["user"]
    })

    if not file:
        return jsonify({"success": False, "error": "File not found"}), 404

    share_id = str(uuid.uuid4())

    value = request.form.get("value")
    unit = (request.form.get("unit") or "").lower()
    start_mode = request.form.get("start_mode", "creation")

    expires_at = None

    try:
        if unit == "permanent":
            expires_at = None
        else:
            value = int(value)

            if value <= 0:
                return jsonify({"error": "Invalid expiry value"}), 400

            now = datetime.now()

            if start_mode == "creation":
                if unit == "minutes":
                    expires_at = now + timedelta(minutes=value)
                elif unit == "hours":
                    expires_at = now + timedelta(hours=value)
                elif unit == "days":
                    expires_at = now + timedelta(days=value)
                else:
                    return jsonify({"error": "Invalid unit"}), 400
            else:
                expires_at = None

    except Exception:
        return jsonify({"error": "Invalid input"}), 400

    max_downloads = request.form.get("max_downloads")
    max_downloads = int(max_downloads) if max_downloads else 0

    shares.insert_one({
        "share_id": share_id,
        "file_id": file_id,
        "user_email": session["user"],
        "file_name": file.get("filename"),
        "created_at": datetime.now(),
        "expires_at": expires_at,
        "start_mode": start_mode,
        "activated": False,
        "access_type": request.form.get("access", "view"),
        "password": request.form.get("password") or None,
        "views": 0,
        "last_accessed": None,
        "active": True,
        "duration": value if unit != "permanent" else None,
        "duration_unit": unit if unit != "permanent" else None,
        "max_downloads": max_downloads,
        "downloads": 0,
        "remaining":None,
        "last_started":0
    })

    link = request.host_url.rstrip("/") + "/share/" + share_id

    return jsonify({
        "success": True,
        "link": link,
        "expires_at": expires_at.isoformat() if expires_at else None
    })


# -------- ACCESS SHARE --------
@file_bp.route("/share/<share_id>", methods=["GET", "POST"])
def access_share(share_id):
    share = shares.find_one({"share_id": share_id})

    if not share:
        return "Invalid link"

    # 🔥 DISABLE CHECK
    if not share.get("active", True):
        return "Link disabled"

    # 🔐 PASSWORD
    if share.get("password"):
        if request.method == "POST":
            if request.form.get("password") != share["password"]:
                return "Wrong password"
        else:
            return '''
            <form method="POST">
                <input type="password" name="password" required>
                <button>Unlock</button>
            </form>
            '''

    # 🔥 FIRST OPEN ACTIVATION (FIXED)
    if share.get("start_mode") == "first_open" and not share.get("activated"):
        value = share.get("duration")
        unit = share.get("duration_unit")

        if value and unit:
            seconds = 0
            if unit == "minutes":
                seconds = value * 60
            elif unit == "hours":
                seconds = value * 3600
            elif unit == "days":
                seconds = value * 86400

            shares.update_one(
                {"share_id": share_id},
                {"$set": {
                    "remaining": seconds,
                    "last_started": datetime.now(),
                    "activated": True
                }}
            )

            share = shares.find_one({"share_id": share_id})

    # 🔥 NEW COUNTDOWN LOGIC (REPLACES expires_at)
    if share.get("remaining") is not None:
        if share.get("active"):
            elapsed = (datetime.now() - share.get("last_started")).total_seconds()
            remaining = share["remaining"] - elapsed
        else:
            remaining = share["remaining"]

        if remaining <= 0:
            return "Link expired"

    # 🔥 DOWNLOAD LIMIT
    max_dl = int(share.get("max_downloads") or 0)

    if max_dl > 0:
        result = shares.update_one(
            {
                "share_id": share_id,
                "downloads": {"$lt": max_dl}
            },
            {
                "$inc": {"downloads": 1}
            }
        )

        if result.modified_count == 0:
            return "Download limit reached"
    else:
        shares.update_one(
            {"share_id": share_id},
            {"$inc": {"downloads": 1}}
        )

    # 🔥 VIEW TRACKING
    shares.update_one(
        {"share_id": share_id},
        {
            "$inc": {"views": 1},
            "$set": {"last_accessed": datetime.now()}
        }
    )

    file = files.find_one({"file_id": share["file_id"]})
    if not file:
        return "File not found"

    mime_type, _ = mimetypes.guess_type(file["filename"])
    mime_type = mime_type or "application/octet-stream"

    # 🔓 INSECURE
    if not file.get("is_encrypted"):
        file_data = requests.get(file["cloud_url"]).content

        if share.get("access_type") == "view":
            headers = {"Content-Disposition": f'inline; filename="{file["filename"]}"'}
        else:
            headers = {"Content-Disposition": f'attachment; filename="{file["filename"]}"'}

        return Response(file_data, content_type=mime_type, headers=headers)

    # 🔐 SECURE
    file_data = requests.get(file["cloud_url"]).content
    file_data = decrypt_file(file_data, file["encryption_key"])

    if share.get("access_type") == "view":
        headers = {"Content-Disposition": f'inline; filename="{file["filename"]}"'}
    else:
        headers = {"Content-Disposition": f'attachment; filename="{file["filename"]}"'}

    return Response(file_data, content_type=mime_type, headers=headers)

# -------- GET SHARES --------
from datetime import datetime

@file_bp.route("/api/shares")
def get_shares():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    user_files = list(files.find({"user_email": session["user"]}))
    file_ids = [f["file_id"] for f in user_files]

    user_shares = list(shares.find({"file_id": {"$in": file_ids}}))

    result = []
    now = datetime.now()   # 🔥 SINGLE TIME (important)

    for s in user_shares:
        file = files.find_one({"file_id": s["file_id"]})

        start_mode = s.get("start_mode", "creation")
        active = s.get("active", True)

        remaining = None

        # ======================================================
        # 🔥 PRIORITY 1: NEW TIMER SYSTEM (remaining + pause)
        # ======================================================
        if s.get("remaining") is not None:

            if active and s.get("last_started"):
                elapsed = (now - s["last_started"]).total_seconds()
                remaining = max(0, s["remaining"] - elapsed)
            else:
                # paused OR not started yet
                remaining = s.get("remaining")

        # ======================================================
        # 🔥 PRIORITY 2: FALLBACK OLD expiry_at SYSTEM
        # ======================================================
        elif s.get("expires_at"):
            remaining = max(0, (s["expires_at"] - now).total_seconds())

        # ======================================================
        # 🔥 STATUS LOGIC (FINAL)
        # ======================================================
        if start_mode == "first_open" and not s.get("activated"):
            status = "waiting"

        elif remaining is not None:
            if remaining <= 0:
                status = "expired"
            elif not active:
                status = "paused"
            else:
                status = "active"

        else:
            status = "permanent"

        # ======================================================
        # 🔥 RESPONSE
        # ======================================================
        result.append({
            "share_id": s["share_id"],
            "file_name": file["filename"] if file else "Unknown",
            "link": request.host_url.rstrip("/") + "/share/" + s["share_id"],

            # 🔥 THIS FIXES YOUR "PERMANENT" BUG
            "remaining": int(remaining) if remaining is not None else None,

            "status": status,
            "start_mode": start_mode,

            "views": s.get("views", 0),
            "last_accessed": s.get("last_accessed").isoformat() if s.get("last_accessed") else None,
            "active": active
        })

    return jsonify({"shares": result})

# -------- DELETE FILE --------
@file_bp.route("/delete/<file_id>")
def delete_file(file_id):
    if "user" not in session:
        return redirect("/login")

    file = files.find_one({"file_id": file_id})

    if not file or file["user_email"] != session["user"]:
        return "Unauthorized"

    # 🔥 DELETE FROM CLOUDINARY
    try:
        public_id = file["cloud_url"].split("/")[-1].split(".")[0]
        cloudinary.uploader.destroy(public_id, resource_type="auto")
    except Exception:
        pass

    files.delete_one({"file_id": file_id})

    flash("File deleted", "upload")
    return redirect("/dashboard")

# -------- DELETE SHARE --------
@file_bp.route("/delete-share/<share_id>")
def delete_share(share_id):
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    share = shares.find_one({"share_id": share_id})
    if not share:
        return jsonify({"error": "not found"}), 404

    file = files.find_one({"file_id": share["file_id"]})
    if not file or file["user_email"] != session["user"]:
        return jsonify({"error": "unauthorized"}), 403

    shares.delete_one({"share_id": share_id})
    return jsonify({"success": True})

def format_size(bytes):
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024**2:
        return f"{bytes/1024:.1f} KB"
    elif bytes < 1024**3:
        return f"{bytes/1024**2:.1f} MB"
    else:
        return f"{bytes/1024**3:.2f} GB"
    
# -------- GET FILES --------
@file_bp.route("/api/files")
def get_files():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    query = request.args.get("q", "").lower()

    if query:
        user_files = list(files.find({
            "user_email": session["user"],
            "filename": {"$regex": query, "$options": "i"}
        }))
    else:
        user_files = list(files.find({"user_email": session["user"]}))

    result = []

    for f in user_files:
        result.append({
            "file_id": f["file_id"],
            "filename": f["filename"],
            "size": f.get("size", 0),
            "uploaded_at": f.get("uploaded_at").isoformat() if f.get("uploaded_at") else None,
            "is_encrypted": f.get("is_encrypted", False)
        })

    user = users.find_one({"email": session["user"]}) or {}

    plan = user.get("plan", "free")
    expiry = user.get("plan_expiry")

    # 🔥 FIXED SAFE DOWNGRADE
    if expiry and expiry < datetime.now() and plan != "free":
        users.update_one(
            {"email": session["user"]},
            {
                "$set": {
                    "plan": "free",
                    "plan_expiry": None
                }
            }
        )
        plan = "free"
        expiry = None

    limits = {
        "free": 500 * 1024 * 1024,
        "2gb": 2 * 1024 * 1024 * 1024,
        "5gb": 5 * 1024 * 1024 * 1024
    }

    limit = limits.get(plan, limits["free"])
    used = sum(f.get("size", 0) for f in user_files)

    percent = (used / limit * 100) if limit > 0 else 0

    return jsonify({
        "files": result,
        "storage": {
            "used": used,
            "limit": limit,
            "percent": round(percent, 1),
            "used_label": format_size(used),
            "total_label": format_size(limit)
        },

        # 🔥 FIXED
        "user_plan": plan,
        "plan_expiry": expiry.isoformat() if expiry else None
    })

# -------- TOGGLE SHARE --------
@file_bp.route("/toggle-share/<share_id>", methods=["POST"])
def toggle_share(share_id):
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    share = shares.find_one({"share_id": share_id})
    if not share:
        return jsonify({"error": "not found"}), 404

    now = datetime.now()
    active = share.get("active", True)

    if active:
        # 🔴 PAUSE
        if share.get("last_started") and share.get("remaining") is not None:
            elapsed = (now - share["last_started"]).total_seconds()
            remaining = max(0, share["remaining"] - elapsed)
        else:
            remaining = share.get("remaining")

        shares.update_one(
            {"share_id": share_id},
            {"$set": {
                "active": False,
                "remaining": remaining
            }}
        )

        return jsonify({"status": "paused", "remaining": int(remaining or 0)})

    else:
        # 🟢 RESUME
        shares.update_one(
            {"share_id": share_id},
            {"$set": {
                "active": True,
                "last_started": now
            }}
        )

        return jsonify({"status": "resumed"})

# -------- OTP SEND --------
@file_bp.route("/send-otp", methods=["POST"])
def send_otp():
    from flask import current_app
    from utils.mail import send_otp_email   # 🔥 USE EXISTING FUNCTION

    email = request.json.get("email")

    user = users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = str(random.randint(100000, 999999))

    users.update_one(
        {"email": email},
        {"$set": {
            "reset_otp": otp,
            "otp_expiry": datetime.now() + timedelta(minutes=5)
        }}
    )

    # 🔥 THIS IS THE REAL FIX
    send_otp_email(current_app, email, otp)

    return jsonify({"message": "OTP sent"})

# -------- VERIFY OTP --------
@file_bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email")
    otp = request.json.get("otp")

    user = users.find_one({"email": email})

    if not user or user.get("reset_otp") != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    if user.get("otp_expiry") < datetime.now():
        return jsonify({"error": "OTP expired"}), 400

    return jsonify({"message": "OTP verified"})


# -------- RESET PASSWORD --------
@file_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json

    email = data.get("email")
    new_password = data.get("password")

    user = users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # 🔐 HASH PASSWORD (IMPORTANT)
    hashed = generate_password_hash(new_password)

    users.update_one(
        {"email": email},
        {
            "$set": {
                "password": hashed
            },
            "$unset": {
                "reset_otp": "",
                "otp_expiry": ""
            }
        }
    )

    return jsonify({"message": "Password updated"})


# -------- SUBSCRIBE --------
@file_bp.route("/activate-plan", methods=["POST"])
def subscribe():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json
    plan = data.get("plan")
    duration = data.get("duration")

    levels = {
        "free": 0,
        "2gb": 1,
        "5gb": 2
    }

    user = users.find_one({"email": session["user"]})
    current_plan = user.get("plan", "free")

    # ❌ BLOCK DOWNGRADE
    if levels.get(plan, 0) < levels.get(current_plan, 0):
        return jsonify({"error": "Cannot downgrade plan"}), 400

    now = datetime.now()

    expiry = None

    # 🔥 ONLY PRO PLANS HAVE EXPIRY
    if plan != "free":
        if duration == "12m":
            expiry = now + timedelta(days=365)
        else:
            expiry = now + timedelta(days=180)

    users.update_one(
        {"email": session["user"]},
        {
            "$set": {
                "plan": plan,
                "plan_duration": duration,
                "plan_expiry": expiry
            }
        }
    )

    return jsonify({"success": True})

@file_bp.route("/forgot")
def forgot():
    return render_template("forgot.html")