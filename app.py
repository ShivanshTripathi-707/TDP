"""RoadWatch - citizen traffic-violation reporting portal (Flask + MongoDB)."""
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from bson import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_from_directory, session, url_for)
from flask_wtf.csrf import CSRFProtect
from pymongo import DESCENDING, GEOSPHERE, MongoClient
from pymongo.errors import PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash

from ai_hooks import analyze_report

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")  # NOT inside /static: files are served only to authorised users
os.makedirs(UPLOAD_DIR, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-secret-change-me")
OTP_VALID_MINUTES = 10
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
MAX_FILES = 5

CATEGORIES = [
    "Excessive smoke / pollution",
    "Rash or reckless driving",
    "Road rage",
    "Wrong-side driving",
    "Signal jumping",
    "Overspeeding",
    "Suspected drunk driving",
    "Other",
]
STATUSES = {
    "pending": "Pending",
    "under_review": "Under review",
    "verified": "Verified - genuine",
    "rejected": "Rejected - not genuine",
    "action_taken": "Action taken",
}
STATUS_COLORS = {
    "pending": "#ffbf00", "under_review": "#1f5fa8", "verified": "#1b7a4b",
    "rejected": "#b3261e", "action_taken": "#6b3fa0",
}
ALLOWED_EXT = {"jpg", "jpeg", "png", "webp", "mp4", "mov", "webm"}
VIDEO_EXT = {"mp4", "mov", "webm"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=60 * 1024 * 1024,  # 60 MB per request
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
CSRFProtect(app)

# --------------------------------------------------------------------------- database
client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=4000)
db = client[os.getenv("DB_NAME", "roadwatch")]
users = db.users
reports = db.reports
posts = db.posts
otps = db.otps


def init_db():
    client.admin.command("ping")
    users.create_index("email", unique=True)
    users.create_index("phone", unique=True, partialFilterExpression={"phone": {"$type": "string"}})
    users.create_index("aadhaar_hash", unique=True, partialFilterExpression={"aadhaar_hash": {"$type": "string"}})
    reports.create_index([("location", GEOSPHERE)])
    reports.create_index([("created_at", DESCENDING)])
    reports.create_index("user_id")
    reports.create_index("media.filename")
    otps.create_index("expires_at", expireAfterSeconds=0)  # Mongo auto-deletes expired OTPs


try:
    init_db()
except PyMongoError as exc:
    raise SystemExit(
        "\n[ERROR] Cannot connect to MongoDB. Is MongoDB running on "
        f"{os.getenv('MONGO_URI', 'mongodb://localhost:27017')} ?\n{exc}\n")


# --------------------------------------------------------------------------- helpers
def now():
    """Current UTC time as a naive datetime (what MongoDB stores/returns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def keyed_hash(value: str) -> str:
    return hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def oid(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        abort(404)


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else None


# Verhoeff checksum (the algorithm behind the last digit of an Aadhaar number)
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def send_email(to, subject, body) -> bool:
    host, user = os.getenv("SMTP_HOST"), os.getenv("SMTP_USER")
    if not host or not user:  # DEV MODE
        print(f"\n===== DEV MODE EMAIL to {to} =====\n{subject}\n{body}\n==================================\n")
        return True
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, to
    msg["From"] = os.getenv("MAIL_FROM", user)
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as smtp:
            smtp.starttls()
            smtp.login(user, os.getenv("SMTP_PASS", ""))
            smtp.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001
        app.logger.error("Email failed: %s", exc)
        return False


def issue_and_send_otp(email) -> bool:
    code = f"{secrets.randbelow(10 ** 6):06d}"
    t = now()
    otps.update_one(
        {"email": email},
        {"$set": {"code_hash": keyed_hash(code), "attempts": 0, "sent_at": t,
                  "expires_at": t + timedelta(minutes=OTP_VALID_MINUTES)}},
        upsert=True)
    return send_email(email, "Your RoadWatch verification code",
                      f"Your RoadWatch OTP is {code}.\nIt is valid for {OTP_VALID_MINUTES} minutes. "
                      "Do not share it with anyone.")


def sniff_ok(head: bytes, ext: str) -> bool:
    """Check the file's first bytes really match its extension."""
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8")
    if ext == "png":
        return head.startswith(b"\x89PNG")
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if ext in ("mp4", "mov"):
        return head[4:8] == b"ftyp"
    if ext == "webm":
        return head.startswith(b"\x1a\x45\xdf\xa3")
    return False


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "uid" not in session:
            flash("Please log in to continue.", "warn")
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def role_required(role):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if session.get("role") != role:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


@app.template_filter("dt")
def fmt_dt(value):
    if not value:
        return ""
    return (value + timedelta(hours=5, minutes=30)).strftime("%d %b %Y, %I:%M %p")  # shown in IST


@app.context_processor
def inject_globals():
    return {"STATUSES": STATUSES, "CATEGORIES": CATEGORIES}


# --------------------------------------------------------------------------- public pages
@app.route("/")
def index():
    notices = list(posts.find().sort("created_at", DESCENDING).limit(5))
    stats = {"total": reports.count_documents({}),
             "acted": reports.count_documents({"status": "action_taken"})}
    return render_template("index.html", notices=notices, stats=stats)


# --------------------------------------------------------------------------- auth
@app.route("/register", methods=["GET", "POST"])
def register():
    v = {}
    if request.method == "POST":
        v = {k: request.form.get(k, "").strip() for k in ("name", "email", "phone", "aadhaar", "address", "pincode")}
        v["email"] = v["email"].lower()
        v["aadhaar"] = re.sub(r"[\s-]", "", v["aadhaar"])
        v["phone"] = re.sub(r"[\s-]", "", v["phone"]).removeprefix("+91")
        password, confirm = request.form.get("password", ""), request.form.get("confirm", "")

        errors = []
        if len(v["name"]) < 3:
            errors.append("Enter your full name.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v["email"]):
            errors.append("Enter a valid email address.")
        if not re.match(r"^[6-9]\d{9}$", v["phone"]):
            errors.append("Enter a valid 10-digit Indian mobile number.")
        if not re.match(r"^[2-9]\d{11}$", v["aadhaar"]):
            errors.append("Aadhaar must be 12 digits.")
        elif os.getenv("VALIDATE_AADHAAR_CHECKSUM", "false").lower() == "true" and not verhoeff_ok(v["aadhaar"]):
            errors.append("This Aadhaar number is not valid. Check the digits.")
        if len(v["address"]) < 10:
            errors.append("Enter your full address.")
        if not re.match(r"^[1-9]\d{5}$", v["pincode"]):
            errors.append("Enter a valid 6-digit PIN code.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            aadhaar_hash = keyed_hash(v["aadhaar"])
            match = {"$or": [{"email": v["email"]}, {"phone": v["phone"]}, {"aadhaar_hash": aadhaar_hash}]}
            users.delete_many({"is_verified": False, **match})  # drop abandoned sign-ups
            if users.find_one(match):
                errors.append("An account with this email, phone or Aadhaar already exists.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", v=v)

        users.insert_one({
            "name": v["name"], "email": v["email"], "phone": v["phone"],
            "aadhaar_last4": v["aadhaar"][-4:], "aadhaar_hash": aadhaar_hash,
            "address": v["address"], "pincode": v["pincode"],
            "password_hash": generate_password_hash(password),
            "role": "citizen", "is_verified": False, "created_at": now(),
        })
        session["pending_email"] = v["email"]
        if not issue_and_send_otp(v["email"]):
            flash("We could not send the email. Use 'Resend code' to try again.", "error")
        else:
            flash(f"We sent a 6-digit code to {v['email']}.", "ok")
        return redirect(url_for("verify_otp"))
    return render_template("register.html", v=v)


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("register"))
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        rec = otps.find_one({"email": email})
        if not rec or rec["expires_at"] < now():
            flash("This code has expired. Request a new one.", "error")
        elif rec["attempts"] >= OTP_MAX_ATTEMPTS:
            flash("Too many wrong attempts. Request a new code.", "error")
        elif not hmac.compare_digest(rec["code_hash"], keyed_hash(code)):
            otps.update_one({"_id": rec["_id"]}, {"$inc": {"attempts": 1}})
            flash("Wrong code. Check the email and try again.", "error")
        else:
            users.update_one({"email": email}, {"$set": {"is_verified": True}})
            otps.delete_one({"_id": rec["_id"]})
            session.pop("pending_email", None)
            flash("Email verified. You can log in now.", "ok")
            return redirect(url_for("login"))
    return render_template("verify_otp.html", email=email)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("register"))
    rec = otps.find_one({"email": email})
    if rec and (now() - rec["sent_at"]).total_seconds() < OTP_RESEND_SECONDS:
        flash(f"Wait {OTP_RESEND_SECONDS} seconds before asking for a new code.", "warn")
    elif issue_and_send_otp(email):
        flash("A new code has been sent.", "ok")
    else:
        flash("We could not send the email. Try again shortly.", "error")
    return redirect(url_for("verify_otp"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = users.find_one({"email": email})
        if not user or not check_password_hash(user["password_hash"], request.form.get("password", "")):
            flash("Email or password is incorrect.", "error")
            return render_template("login.html", email=email)
        if not user.get("is_verified"):
            session.clear()
            session["pending_email"] = email
            issue_and_send_otp(email)
            flash("Verify your email first. We sent you a new code.", "warn")
            return redirect(url_for("verify_otp"))
        session.clear()
        session.update(uid=str(user["_id"]), role=user["role"], name=user["name"])
        if user["role"] == "police":
            return redirect(url_for("police_dashboard"))
        return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))
    return render_template("login.html", email="")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- citizen
@app.route("/dashboard")
@role_required("citizen")
def dashboard():
    mine = list(reports.find({"user_id": ObjectId(session["uid"])}).sort("created_at", DESCENDING))
    return render_template("dashboard.html", reports=mine)


@app.route("/report/new", methods=["GET", "POST"])
@role_required("citizen")
def report_new():
    v = {}
    if request.method == "POST":
        v = {k: request.form.get(k, "").strip() for k in ("category", "vehicle_number", "description", "landmark")}
        v["vehicle_number"] = re.sub(r"[\s-]", "", v["vehicle_number"]).upper()
        errors = []

        if v["category"] not in CATEGORIES:
            errors.append("Choose what kind of problem this is.")
        if v["vehicle_number"] and not re.match(r"^[A-Z0-9]{4,12}$", v["vehicle_number"]):
            errors.append("Vehicle number should be letters and digits only, e.g. AP39TX1234.")
        if not 15 <= len(v["description"]) <= 1500:
            errors.append("Describe what happened in 15 to 1500 characters.")
        try:
            lat, lng = float(request.form["lat"]), float(request.form["lng"])
            accuracy = float(request.form.get("accuracy") or 0)
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                raise ValueError
        except (KeyError, ValueError):
            errors.append("Your location is missing. Allow location access in the browser and try again.")

        files = [f for f in request.files.getlist("media") if f and f.filename]
        checked = []
        if not files:
            errors.append("Add at least one photo or video as proof.")
        elif len(files) > MAX_FILES:
            errors.append(f"You can upload up to {MAX_FILES} files.")
        else:
            for f in files:
                ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
                head = f.read(16)
                f.seek(0)
                if ext not in ALLOWED_EXT or not sniff_ok(head, ext):
                    errors.append(f"'{f.filename}' is not a supported photo or video (JPG, PNG, WEBP, MP4, MOV, WEBM).")
                else:
                    checked.append((f, ext))

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("report_new.html", v=v)

        media, paths = [], []
        for f, ext in checked:
            name = f"{uuid.uuid4().hex}.{ext}"
            path = os.path.join(UPLOAD_DIR, name)
            f.save(path)
            paths.append(path)
            media.append({"filename": name, "type": "video" if ext in VIDEO_EXT else "image"})

        t = now()
        doc = {
            "user_id": ObjectId(session["uid"]),
            "category": v["category"], "vehicle_number": v["vehicle_number"],
            "description": v["description"], "landmark": v["landmark"][:200],
            "media": media,
            "location": {"type": "Point", "coordinates": [lng, lat]},  # GeoJSON order = [lng, lat]
            "accuracy_m": round(accuracy, 1),
            "status": "pending", "history": [],
            "ai_analysis": None,
            "ip": request.remote_addr, "user_agent": request.headers.get("User-Agent", "")[:300],
            "created_at": t, "updated_at": t,
        }
        res = reports.insert_one(doc)
        try:
            result = analyze_report(doc, paths)
            if result:
                reports.update_one({"_id": res.inserted_id}, {"$set": {"ai_analysis": result}})
        except Exception as exc:  # noqa: BLE001 - AI must never break a submission
            app.logger.error("AI analysis failed: %s", exc)
        flash("Report submitted. Police will review it.", "ok")
        return redirect(url_for("report_view", rid=res.inserted_id))
    return render_template("report_new.html", v=v)


@app.route("/report/<rid>")
@login_required
def report_view(rid):
    r = reports.find_one({"_id": oid(rid)})
    if not r:
        abort(404)
    is_police = session["role"] == "police"
    if not is_police and str(r["user_id"]) != session["uid"]:
        abort(403)
    reporter = users.find_one({"_id": r["user_id"]}) if is_police else None
    return render_template("report_detail.html", r=r, reporter=reporter, is_police=is_police)


@app.route("/media/<name>")
@login_required
def media(name):
    """Uploads are private: only the uploader and police can open them."""
    if not re.match(r"^[0-9a-f]{32}\.[a-z0-9]{3,4}$", name):
        abort(404)
    r = reports.find_one({"media.filename": name}, {"user_id": 1})
    if not r:
        abort(404)
    if session["role"] != "police" and str(r["user_id"]) != session["uid"]:
        abort(403)
    return send_from_directory(UPLOAD_DIR, name)


# --------------------------------------------------------------------------- police
@app.route("/police")
@role_required("police")
def police_dashboard():
    status = request.args.get("status", "")
    category = request.args.get("category", "")
    q = request.args.get("q", "").strip()[:60]
    flt = {}
    if status in STATUSES:
        flt["status"] = status
    if category in CATEGORIES:
        flt["category"] = category
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        flt["$or"] = [{"vehicle_number": rx}, {"description": rx}, {"landmark": rx}]

    rows = list(reports.aggregate([
        {"$match": flt}, {"$sort": {"created_at": -1}}, {"$limit": 200},
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "user"}},
        {"$unwind": "$user"},
    ]))
    counts = {s: 0 for s in STATUSES}
    for row in reports.aggregate([{"$group": {"_id": "$status", "n": {"$sum": 1}}}]):
        counts[row["_id"]] = row["n"]
    points = [{"lat": r["location"]["coordinates"][1], "lng": r["location"]["coordinates"][0],
               "cat": r["category"], "vehicle": r.get("vehicle_number", ""),
               "color": STATUS_COLORS.get(r["status"], "#777"),
               "url": url_for("report_view", rid=str(r["_id"]))} for r in rows]
    return render_template("police_dashboard.html", rows=rows, counts=counts, points=points,
                           f={"status": status, "category": category, "q": q})


@app.route("/report/<rid>/update", methods=["POST"])
@role_required("police")
def report_update(rid):
    status = request.form.get("status", "")
    note = request.form.get("note", "").strip()[:1000]
    if status not in STATUSES:
        abort(400)
    t = now()
    reports.update_one(
        {"_id": oid(rid)},
        {"$set": {"status": status, "updated_at": t},
         "$push": {"history": {"status": status, "note": note, "by": session["name"], "at": t}}})
    flash("Report updated.", "ok")
    return redirect(url_for("report_view", rid=rid))


@app.route("/police/posts", methods=["GET", "POST"])
@role_required("police")
def police_posts():
    if request.method == "POST":
        title, body = request.form.get("title", "").strip(), request.form.get("body", "").strip()
        if not (3 <= len(title) <= 120 and 10 <= len(body) <= 2000):
            flash("Add a title (3-120 characters) and a message (10-2000 characters).", "error")
        else:
            posts.insert_one({"title": title, "body": body, "author": session["name"],
                              "author_id": ObjectId(session["uid"]), "created_at": now()})
            flash("Notice published on the home page.", "ok")
        return redirect(url_for("police_posts"))
    return render_template("police_posts.html", posts=list(posts.find().sort("created_at", DESCENDING)))


@app.route("/police/posts/<pid>/delete", methods=["POST"])
@role_required("police")
def police_post_delete(pid):
    posts.delete_one({"_id": oid(pid)})
    flash("Notice removed.", "ok")
    return redirect(url_for("police_posts"))


# --------------------------------------------------------------------------- errors
@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, msg="You do not have access to this page."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, msg="We could not find that page."), 404


@app.errorhandler(413)
def too_large(_):
    flash("Upload is too large. Keep the total under 60 MB.", "error")
    return redirect(url_for("report_new"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
