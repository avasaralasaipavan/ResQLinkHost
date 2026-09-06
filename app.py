"""ResQLink - single-file Flask application.

Every Flask concern (app setup, business logic and all routes) lives in this one
module so it is easy to deploy on PythonAnywhere:

    # WSGI configuration (Web tab -> WSGI configuration file)
    import sys
    sys.path.insert(0, "/home/<your-username>/ResQLinkHost")
    from app import app as application

There are NO blueprints - every route is registered directly on the app object.
Supporting modules (kept separate because they are clean, single-purpose files):
  config.py      - reads settings from .env (or real environment variables)
  extensions.py  - db / csrf / mail extension instances
  models.py      - SQLAlchemy models
"""

import base64
import hashlib
import io
import random
import re
import secrets
from datetime import timedelta
from functools import wraps

import qrcode
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_mail import Message
from werkzeug.security import generate_password_hash

from config import Config
from extensions import csrf, db, mail
from models import AccessConfig, AccessLog, EmergencyContact, OtpRecord, User, utcnow

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = Flask(__name__, instance_relative_config=False)
app.config.from_object(Config)

db.init_app(app)
csrf.init_app(app)
mail.init_app(app)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MOBILE_RE = re.compile(r"^[+]?[0-9]{8,15}$")


def is_valid_email(value):
    return bool(value) and bool(EMAIL_RE.match(value.strip()))


def is_valid_mobile(value):
    return bool(value) and bool(MOBILE_RE.match(value.strip()))


# ---------------------------------------------------------------------------
# Session helpers / decorators
# ---------------------------------------------------------------------------


def get_current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    return db.session.get(User, uid)


def get_current_admin():
    uid = session.get("admin_id")
    if uid is None:
        return None
    return db.session.get(User, uid)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth_login"))
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        admin = get_current_admin()
        if admin is None or not admin.is_admin or not admin.is_active:
            flash("Admin access required.", "danger")
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# OTP delivery (Flask-Mail for email, stub for SMS)
# ---------------------------------------------------------------------------


def _purpose_label(purpose):
    return {
        "register": "account registration",
        "login": "login",
        "helper": "accessing an emergency contact record",
    }.get(purpose, "verification")


def send_otp_email(recipient, code, purpose, context=None):
    cfg = current_app.config
    label = _purpose_label(purpose)
    subject = f"ResQLink: your {label} code is {code}"
    text = (
        f"Hello,\n\n"
        f"Use this code to complete your {label}:\n\n"
        f"    {code}\n\n"
        f"The code expires in {cfg['OTP_EXPIRY_MINUTES']} minutes. Never share it with anyone.\n\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"ResQLink"
    )

    # Not configured (or suppress-send enabled) -> dev mode fallback.
    if not (cfg.get("MAIL_USERNAME") and cfg.get("MAIL_PASSWORD")):
        current_app.logger.warning("[DEV-MODE] OTP for %s: %s", recipient, code)
        return False
    if cfg.get("MAIL_SUPPRESS_SEND"):
        current_app.logger.warning("[MAIL_SUPPRESS_SEND] OTP skipped for %s: %s", recipient, code)
        return False

    msg = Message(
        subject=subject,
        recipients=[recipient],
        body=text,
        sender=cfg.get("MAIL_DEFAULT_SENDER"),
    )
    try:
        mail.send(msg)
    except Exception as exc:  # SMTP auth / network errors
        current_app.logger.error("Failed to send OTP email to %s: %s", recipient, exc)
        return False
    return True


def send_otp_sms(mobile, code, purpose):
    """Mobile OTP delivery. Replace this stub with Twilio / MSG91 / SMS provider.

    Returns True when the SMS was actually sent, False otherwise (which enables the
    dev-mode on-screen OTP display).
    """
    current_app.logger.warning("[DEV-MODE] SMS OTP for %s: %s", mobile, code)
    return False


# ---------------------------------------------------------------------------
# OTP issuance and verification
# ---------------------------------------------------------------------------

VALID_PURPOSES = {"register", "login", "helper"}


class OtpError(Exception):
    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after


def _hash_code(code):
    return hashlib.sha256(str(code).encode()).hexdigest()


def issue_otp(identifier, channel, purpose, ip=None):
    """Create, save and send a fresh OTP for the identifier.

    Returns (record, code) where `code` is only populated in MAIL_DEBUG mode
    (development) so the UI can surface it on screen.
    """
    cfg = current_app.config
    identifier = identifier.strip().lower()

    if purpose not in VALID_PURPOSES:
        raise OtpError("Invalid OTP purpose.")

    # Rate limit: max sends per identifier in the window.
    since = utcnow() - timedelta(minutes=cfg["OTP_RATE_LIMIT_WINDOW_MINUTES"])
    sent = OtpRecord.query.filter(
        OtpRecord.identifier == identifier,
        OtpRecord.purpose == purpose,
        OtpRecord.created_at >= since,
    ).count()
    if sent >= cfg["OTP_RATE_LIMIT_COUNT"]:
        raise OtpError(
            "Too many code requests. Please wait a while and try again."
        )

    latest = (
        OtpRecord.query.filter_by(identifier=identifier, purpose=purpose)
        .order_by(OtpRecord.id.desc())
        .first()
    )
    if latest:
        elapsed = (utcnow() - latest.created_at).total_seconds()
        wait = cfg["OTP_COOLDOWN_SECONDS"] - elapsed
        if wait > 0:
            raise OtpError(
                "Please wait a moment before requesting another code.",
                retry_after=int(wait) + 1,
            )

    code = f"{random.SystemRandom().randint(0, 999999):06d}"[: cfg["OTP_LENGTH"]]
    record = OtpRecord(
        identifier=identifier,
        channel=channel,
        purpose=purpose,
        code_hash=_hash_code(code),
        expires_at=utcnow() + timedelta(minutes=cfg["OTP_EXPIRY_MINUTES"]),
        ip_address=ip,
    )
    db.session.add(record)
    db.session.commit()

    if channel == "email":
        sent = send_otp_email(identifier, code, purpose)
    else:
        sent = send_otp_sms(identifier, code, purpose)

    return_code = code if (cfg.get("MAIL_DEBUG") and not sent) else None
    return record, return_code


def verify_otp(identifier, channel, purpose, code, ip=None):
    """Validate and consume the latest unverified OTP for the identifier."""
    cfg = current_app.config
    identifier = identifier.strip().lower()

    record = (
        OtpRecord.query.filter_by(
            identifier=identifier, channel=channel, purpose=purpose, verified=False
        )
        .order_by(OtpRecord.id.desc())
        .first()
    )
    if record is None:
        raise OtpError("No active code found. Please request a new one.")

    if record.expires_at < utcnow():
        raise OtpError("This code has expired. Please request a new one.")

    if record.attempts >= cfg["OTP_MAX_ATTEMPTS"]:
        raise OtpError("Too many failed attempts. Please request a new code.")

    record.attempts += 1
    if not secrets.compare_digest(record.code_hash, _hash_code(code.strip())):
        db.session.commit()
        remaining = cfg["OTP_MAX_ATTEMPTS"] - record.attempts
        raise OtpError(f"Incorrect code. {remaining} attempt(s) remaining.")

    record.verified = True
    record.ip_address = ip or record.ip_address
    db.session.commit()
    return record


# ---------------------------------------------------------------------------
# QR token management and image generation
# ---------------------------------------------------------------------------


def ensure_token(user):
    """Make sure the user owns a non-guessable QR token."""
    if user.qr_token:
        return user.qr_token
    token = secrets.token_urlsafe(16)
    while User.query.filter_by(qr_token=token).first():
        token = secrets.token_urlsafe(16)
    user.qr_token = token
    user.qr_enabled = True
    user.qr_created_at = utcnow()
    db.session.commit()
    return token


def regenerate_token(user):
    user.qr_token = secrets.token_urlsafe(16)
    user.qr_created_at = utcnow()
    db.session.commit()


def set_active(user, enabled):
    user.qr_enabled = bool(enabled)
    db.session.commit()


def qr_png_bytes(url):
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0b3b73", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def qr_data_uri(url):
    return "data:image/png;base64," + base64.b64encode(qr_png_bytes(url)).decode()


# ---------------------------------------------------------------------------
# Helper-facing logic: QR lookups, access limits and audit logging
# ---------------------------------------------------------------------------


class QrLookupError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def get_user_by_token(token):
    user = User.query.filter_by(qr_token=token).first()
    if user is None:
        raise QrLookupError("This QR code is not registered with ResQLink.")
    if not user.is_active:
        raise QrLookupError("This ResQLink account is no longer active.")
    if not user.qr_enabled:
        raise QrLookupError("This QR code has been deactivated by its owner.")
    return user


def get_config(user, create=True):
    cfg = user.access_config
    if cfg is None and create:
        cfg = AccessConfig(
            user_id=user.id,
            limit_enabled=True,
            max_count=current_app.config["DEFAULT_ACCESS_LIMIT_COUNT"],
            window_minutes=current_app.config["DEFAULT_ACCESS_LIMIT_WINDOW_MINUTES"],
        )
        db.session.add(cfg)
        db.session.commit()
    return cfg


def update_config(user, limit_enabled, max_count, window_minutes):
    cfg = get_config(user)
    cfg.limit_enabled = bool(limit_enabled)
    cfg.max_count = max(1, min(99, int(max_count)))
    cfg.window_minutes = max(1, min(1440, int(window_minutes)))
    db.session.commit()
    return cfg


def displayed_in_window(user, window_minutes):
    since = utcnow() - timedelta(minutes=window_minutes)
    return AccessLog.query.filter(
        AccessLog.user_id == user.id,
        AccessLog.contacts_displayed.is_(True),
        AccessLog.accessed_at >= since,
    ).count()


def access_check(user):
    """Return (allowed, denied_reason) based on the owner's access limit."""
    cfg = get_config(user)
    if not cfg.limit_enabled:
        return True, None
    if displayed_in_window(user, cfg.window_minutes) >= cfg.max_count:
        return (
            False,
            "The maximum number of accesses for this QR code has been reached "
            "within the configured period. The emergency contacts may already "
            "have been notified.",
        )
    return True, None


def log_access(user, identifier, channel, ip, user_agent, displayed, denied_reason=None):
    log = AccessLog(
        user_id=user.id,
        helper_identifier=identifier,
        channel=channel,
        ip_address=ip,
        user_agent=(user_agent or "")[:300],
        contacts_displayed=bool(displayed),
        denied_reason=denied_reason,
    )
    db.session.add(log)
    db.session.commit()
    return log


def recent_access(user, limit=5):
    return (
        AccessLog.query.filter_by(user_id=user.id)
        .order_by(AccessLog.accessed_at.desc())
        .limit(limit)
        .all()
    )


def access_stats(user):
    total = AccessLog.query.filter_by(user_id=user.id).count()
    week_ago = utcnow() - timedelta(days=7)
    week = AccessLog.query.filter(
        AccessLog.user_id == user.id, AccessLog.accessed_at >= week_ago
    ).count()
    shown = AccessLog.query.filter_by(
        user_id=user.id, contacts_displayed=True
    ).count()
    return {"total": total, "week": week, "shown": shown}


# ---------------------------------------------------------------------------
# Emergency contacts CRUD
# ---------------------------------------------------------------------------


def list_contacts(user):
    return (
        EmergencyContact.query.filter_by(user_id=user.id)
        .order_by(EmergencyContact.created_at.desc())
        .all()
    )


def get_contact(contact_id):
    return db.session.get(EmergencyContact, contact_id)


def create_contact(user, name, relationship, phone, email=None):
    contact = EmergencyContact(
        user_id=user.id,
        name=name.strip(),
        relationship=relationship.strip(),
        phone=phone.strip(),
        email=(email or "").strip(),
    )
    db.session.add(contact)
    db.session.commit()
    return contact


def update_contact(contact, name, relationship, phone, email=None):
    contact.name = name.strip()
    contact.relationship = relationship.strip()
    contact.phone = phone.strip()
    contact.email = (email or "").strip()
    db.session.commit()
    return contact


def delete_contact(contact):
    db.session.delete(contact)
    db.session.commit()


# ---------------------------------------------------------------------------
# Admin queries and moderation actions
# ---------------------------------------------------------------------------


def admin_stats():
    qr_enabled_count = User.query.filter_by(qr_enabled=True).count()
    non_admin_users = User.query.filter_by(is_admin=False).count()
    flagged_count = AccessLog.query.filter_by(flagged=True).count()
    return {
        "users": User.query.count(),
        "non_admin_users": non_admin_users,
        "qr_active": qr_enabled_count,
        "access_logs": AccessLog.query.count(),
        "flagged": flagged_count,
    }


def list_users(search=None):
    q = User.query.filter_by(is_admin=False)
    if search:
        term = f"%{search}%"
        q = q.filter(
            db.or_(
                User.email.ilike(term),
                User.full_name.ilike(term),
                User.phone.ilike(term),
            )
        )
    return q.order_by(User.created_at.desc()).all()


def user_access_count(user_id):
    return AccessLog.query.filter_by(user_id=user_id).count()


def toggle_suspend(user):
    user.is_active = not user.is_active
    db.session.commit()
    return user.is_active


def list_logs(search=None, flagged_only=False):
    q = AccessLog.query
    if flagged_only:
        q = q.filter(AccessLog.flagged.is_(True))
    if search:
        term = f"%{search}%"
        q = q.filter(AccessLog.helper_identifier.ilike(term))
    return q.order_by(AccessLog.accessed_at.desc()).all()


def toggle_flag(log, reason=None):
    if log.flagged:
        log.flagged = False
        log.flag_reason = None
    else:
        log.flagged = True
        log.flag_reason = (reason or "Flagged")[:255]
    db.session.commit()
    return log.flagged


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


def _require_not_logged_in():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return None


@app.route("/auth/register", methods=["GET", "POST"])
def auth_register():
    guarded = _require_not_logged_in()
    if guarded:
        return guarded

    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = None
        if len(name) < 2:
            flash("Please enter your full name.", "danger")
        elif not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("An account already exists with this email. Please log in instead.", "warning")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            try:
                _record, code = issue_otp(
                    email, "email", "register", ip=request.remote_addr
                )
            except OtpError as exc:
                flash(exc.message, "danger")
            except Exception:
                flash("Could not send the verification code. Please try again.", "danger")
            else:
                session["pending_reg"] = {
                    "name": name,
                    "email": email,
                    "password_hash": generate_password_hash(password),
                }
                if code:
                    flash(f"DEV MODE: your verification code is {code}", "info")
                flash("A verification code was sent to your email.", "success")
                return redirect(url_for("auth_register_verify"))

    return render_template("auth/register.html", form=request.form)


@app.route("/auth/register/verify", methods=["GET", "POST"])
def auth_register_verify():
    pending = session.get("pending_reg")
    if not pending:
        return redirect(url_for("auth_register"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        try:
            verify_otp(pending["email"], "email", "register", code, ip=request.remote_addr)
        except OtpError as exc:
            flash(exc.message, "danger")
        else:
            user = User(email=pending["email"], full_name=pending["name"])
            user.password_hash = pending["password_hash"]
            db.session.add(user)
            db.session.commit()
            session.pop("pending_reg", None)
            session["user_id"] = user.id
            flash(f"Welcome to ResQLink, {user.full_name}! Your account is ready.", "success")
            return redirect(url_for("dashboard"))

    return render_template("auth/register_verify.html", email=pending["email"])


@app.route("/auth/register/resend", methods=["POST"])
def auth_register_resend():
    pending = session.get("pending_reg")
    if not pending:
        return redirect(url_for("auth_register"))
    try:
        _record, code = issue_otp(
            pending["email"], "email", "register", ip=request.remote_addr
        )
    except OtpError as exc:
        flash(exc.message, "danger")
    else:
        if code:
            flash(f"DEV MODE: your verification code is {code}", "info")
        flash("A new verification code was sent.", "success")
    return redirect(url_for("auth_register_verify"))


@app.route("/auth/login", methods=["GET", "POST"])
def auth_login():
    guarded = _require_not_logged_in()
    if guarded:
        return guarded

    mode = request.form.get("mode", request.args.get("mode", "password"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()

        if user is None:
            flash("No account found with this email.", "danger")
        elif not user.is_active:
            flash("This account has been suspended. Please contact support.", "danger")
        elif mode == "otp":
            try:
                _record, code = issue_otp(email, "email", "login", ip=request.remote_addr)
            except OtpError as exc:
                flash(exc.message, "danger")
            else:
                session["login_otp_email"] = email
                if code:
                    flash(f"DEV MODE: your verification code is {code}", "info")
                flash("A login code was sent to your email.", "success")
                return redirect(url_for("auth_login_otp_verify"))
        else:
            password = request.form.get("password", "")
            if user.check_password(password):
                session["user_id"] = user.id
                flash(f"Welcome back, {user.full_name or user.email}!", "success")
                return redirect(url_for("dashboard"))
            flash("Incorrect password. Please try again.", "danger")

    return render_template("auth/login.html", form=request.form, mode=mode)


@app.route("/auth/login-otp/verify", methods=["GET", "POST"])
def auth_login_otp_verify():
    email = session.get("login_otp_email")
    if not email:
        return redirect(url_for("auth_login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        try:
            verify_otp(email, "email", "login", code, ip=request.remote_addr)
        except OtpError as exc:
            flash(exc.message, "danger")
        else:
            user = User.query.filter_by(email=email).first()
            if user is None or not user.is_active:
                flash("This account is unavailable.", "danger")
            else:
                session.pop("login_otp_email", None)
                session["user_id"] = user.id
                flash(f"Welcome back, {user.full_name or user.email}!", "success")
                return redirect(url_for("dashboard"))

    return render_template("auth/login_otp_verify.html", email=email)


@app.route("/auth/login-otp/resend", methods=["POST"])
def auth_login_otp_resend():
    email = session.get("login_otp_email")
    if not email:
        return redirect(url_for("auth_login"))
    try:
        _record, code = issue_otp(email, "email", "login", ip=request.remote_addr)
    except OtpError as exc:
        flash(exc.message, "danger")
    else:
        if code:
            flash(f"DEV MODE: your code is {code}", "info")
        flash("A new login code was sent.", "success")
    return redirect(url_for("auth_login_otp_verify"))


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.pop("user_id", None)
    session.pop("pending_reg", None)
    session.pop("login_otp_email", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# User routes
# ---------------------------------------------------------------------------


def _load_or_abort(model, obj_id):
    row = db.session.get(model, obj_id)
    if row is None:
        abort(404)
    return row


@app.route("/user/")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    stats = access_stats(user)
    recent = recent_access(user, limit=5)
    return render_template(
        "user/dashboard.html",
        nav="dashboard",
        user=user,
        stats=stats,
        recent=recent,
        contacts_count=len(user.contacts),
        qr_url=user.qr_url,
    )


@app.route("/user/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        action = request.form.get("action")

        if action == "save_profile":
            name = request.form.get("full_name", "").strip()
            phone = request.form.get("phone", "").strip()
            if len(name) < 2:
                flash("Please enter your full name.", "danger")
            elif phone and not phone.replace("+", "", 1).isdigit():
                flash("Phone number can only contain digits.", "danger")
            else:
                user.full_name = name
                user.phone = phone
                db.session.commit()
                flash("Profile updated.", "success")
        elif action == "change_password":
            current_pwd = request.form.get("current_password", "")
            new_pwd = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not user.check_password(current_pwd):
                flash("Current password is incorrect.", "danger")
            elif len(new_pwd) < 6:
                flash("New password must be at least 6 characters.", "danger")
            elif new_pwd != confirm:
                flash("New passwords do not match.", "danger")
            else:
                user.set_password(new_pwd)
                db.session.commit()
                flash("Password updated.", "success")
        return redirect(url_for("profile"))

    return render_template("user/profile.html", nav="profile", user=user)


@app.route("/user/contacts")
@login_required
def contacts():
    user = User.query.get(session["user_id"])
    return render_template(
        "user/contacts.html", nav="contacts", user=user, contacts=user.contacts
    )


def _validate_contact_form():
    name = request.form.get("name", "").strip()
    relationship = request.form.get("relationship", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    if len(name) < 2:
        return None, "Please enter the contact's name."
    if not relationship:
        return None, "Please enter the relationship (e.g. Mother, Spouse)."
    if not phone or not phone.replace("+", "", 1).isdigit():
        return None, "Please enter a valid phone number."
    if email and not is_valid_email(email):
        return None, "Please enter a valid email address or leave it blank."
    return {"name": name, "relationship": relationship, "phone": phone, "email": email}, None


@app.route("/user/contacts/new", methods=["GET", "POST"])
@login_required
def contact_new():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        data, err = _validate_contact_form()
        if err:
            flash(err, "danger")
        else:
            create_contact(user=user, **data)
            flash(f"Emergency contact '{data['name']}' added.", "success")
            return redirect(url_for("contacts"))
    return render_template("user/contact_form.html", nav="contacts", contact=None, form=request.form)


@app.route("/user/contacts/<int:contact_id>/edit", methods=["GET", "POST"])
@login_required
def contact_edit(contact_id):
    user = User.query.get(session["user_id"])
    contact = _load_or_abort(EmergencyContact, contact_id)
    if contact.user_id != user.id:
        abort(403)
    if request.method == "POST":
        data, err = _validate_contact_form()
        if err:
            flash(err, "danger")
        else:
            update_contact(contact, **data)
            flash(f"Emergency contact '{data['name']}' updated.", "success")
            return redirect(url_for("contacts"))
    return render_template("user/contact_form.html", nav="contacts", contact=contact, form=request.form)


@app.route("/user/contacts/<int:contact_id>/delete", methods=["POST"])
@login_required
def contact_delete(contact_id):
    user = User.query.get(session["user_id"])
    contact = _load_or_abort(EmergencyContact, contact_id)
    if contact.user_id != user.id:
        abort(403)
    delete_contact(contact)
    flash("Emergency contact removed.", "info")
    return redirect(url_for("contacts"))


@app.route("/user/qr", methods=["GET"])
@login_required
def qr():
    user = User.query.get(session["user_id"])
    ensure_token(user)
    url = user.qr_url
    return render_template(
        "user/qr.html",
        nav="qr",
        user=user,
        qr_url=url,
        qr_data_uri=qr_data_uri(url),
    )


@app.route("/user/qr/download")
@login_required
def qr_download():
    user = User.query.get(session["user_id"])
    ensure_token(user)
    data = qr_png_bytes(user.qr_url)
    return Response(
        data,
        mimetype="image/png",
        headers={
            "Content-Disposition": (
                f'attachment; filename="resqlink-qr-{user.qr_token}.png"'
            )
        },
    )


@app.route("/user/qr/toggle", methods=["POST"])
@login_required
def qr_toggle():
    user = User.query.get(session["user_id"])
    ensure_token(user)
    if user.contacts is None or len(user.contacts) == 0:
        flash("Add at least one emergency contact before enabling your QR code.", "warning")
    else:
        set_active(user, not user.qr_enabled)
        state = "activated" if user.qr_enabled else "deactivated"
        flash(f"Your QR code is now {state}.", "success")
    return redirect(url_for("qr"))


@app.route("/user/qr/regenerate", methods=["POST"])
@login_required
def qr_regenerate():
    user = User.query.get(session["user_id"])
    regenerate_token(user)
    flash("A new QR code was generated. Old scans no longer work.", "success")
    return redirect(url_for("qr"))


@app.route("/user/access")
@login_required
def access_log():
    user = User.query.get(session["user_id"])
    logs = (
        AccessLog.query.filter_by(user_id=user.id)
        .order_by(AccessLog.accessed_at.desc())
        .all()
    )
    return render_template("user/access.html", nav="access", user=user, logs=logs)


@app.route("/user/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = User.query.get(session["user_id"])
    cfg = get_config(user)
    if request.method == "POST":
        limit_enabled = request.form.get("limit_enabled") == "on"
        max_count = request.form.get("max_count", 3)
        window_minutes = request.form.get("window_minutes", 60)
        try:
            update_config(user, limit_enabled, int(max_count), int(window_minutes))
        except (TypeError, ValueError):
            flash("Please enter valid numbers for the access limit.", "danger")
        else:
            flash("Access limitation settings saved.", "success")
        return redirect(url_for("settings"))
    return render_template(
        "user/settings.html",
        nav="settings",
        user=user,
        cfg=cfg,
        used=displayed_in_window(user, cfg.window_minutes),
    )


# ---------------------------------------------------------------------------
# Helper (QR) routes
# ---------------------------------------------------------------------------


def _pending():
    return session.get("helper_pending")


def _verified():
    return session.get("helper_access")


def _load_or_error(token):
    try:
        return get_user_by_token(token)
    except QrLookupError:
        return None


@app.route("/q/<token>")
def q_landing(token):
    user = _load_or_error(token)
    if user is None:
        return render_template("helper/invalid.html"), 404
    return render_template("helper/landing.html", token=token, owner=user)


@app.route("/q/<token>/send-otp", methods=["POST"])
def q_send_otp(token):
    user = _load_or_error(token)
    if user is None:
        return render_template("helper/invalid.html"), 404

    channel = request.form.get("channel", "email")
    identifier = request.form.get("identifier", "").strip()

    if channel == "email":
        if not is_valid_email(identifier):
            flash("Please enter a valid email address.", "danger")
        else:
            ok = True
    elif channel == "mobile":
        if not is_valid_mobile(identifier):
            flash("Please enter a valid mobile number (8-15 digits).", "danger")
        else:
            ok = True
    else:
        ok = False
        flash("Please choose a verification method.", "danger")

    if not ok:
        return redirect(url_for("q_landing", token=token))

    try:
        _record, code = issue_otp(
            identifier, channel, "helper", ip=request.remote_addr
        )
    except OtpError as exc:
        flash(exc.message, "danger")
        return redirect(url_for("q_landing", token=token))

    session["helper_pending"] = {
        "token": token,
        "channel": channel,
        "identifier": identifier,
    }
    if code:
        flash(f"DEV MODE: your code is {code}", "info")
    flash("A verification code was sent. Enter it below to view the emergency contacts.", "success")
    return redirect(url_for("q_verify", token=token))


@app.route("/q/<token>/verify", methods=["GET", "POST"])
def q_verify(token):
    user = _load_or_error(token)
    if user is None:
        return render_template("helper/invalid.html"), 404

    pending = _pending()
    if not pending or pending.get("token") != token:
        return redirect(url_for("q_landing", token=token))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        try:
            verify_otp(
                pending["identifier"], pending["channel"], "helper", code, ip=request.remote_addr
            )
        except OtpError as exc:
            flash(exc.message, "danger")
        else:
            allowed, reason = access_check(user)
            identifier = pending["identifier"]
            session.pop("helper_pending", None)
            log_access(
                user,
                identifier,
                pending["channel"],
                request.remote_addr,
                request.user_agent.string if request.user_agent else None,
                displayed=allowed,
                denied_reason=reason,
            )
            session["helper_access"] = {
                "token": token,
                "identifier": identifier,
                "channel": pending["channel"],
            }
            flash("Identity verified. Emergency contact information below.", "success")
            if not allowed:
                return redirect(url_for("q_limited", token=token))
            return redirect(url_for("q_contacts", token=token))

    return render_template("helper/verify.html", token=token, pending=pending)


@app.route("/q/<token>/resend", methods=["POST"])
def q_resend(token):
    user = _load_or_error(token)
    if user is None:
        return render_template("helper/invalid.html"), 404
    pending = _pending()
    if not pending or pending.get("token") != token:
        return redirect(url_for("q_landing", token=token))
    try:
        _record, code = issue_otp(
            pending["identifier"], pending["channel"], "helper", ip=request.remote_addr
        )
    except OtpError as exc:
        flash(exc.message, "danger")
    else:
        if code:
            flash(f"DEV MODE: your code is {code}", "info")
        flash("A new verification code was sent.", "success")
    return redirect(url_for("q_verify", token=token))


@app.route("/q/<token>/contacts", methods=["GET"])
def q_contacts(token):
    user = _load_or_error(token)
    if user is None:
        return render_template("helper/invalid.html"), 404

    verified = _verified()
    if not verified or verified.get("token") != token:
        return redirect(url_for("q_landing", token=token))

    allowed, reason = access_check(user)
    if not allowed:
        return render_template("helper/limited.html", token=token, reason=reason)

    return render_template("helper/contacts.html", token=token, owner=user, contacts=user.contacts)


@app.route("/q/<token>/limited", methods=["GET"])
def q_limited(token):
    return render_template("helper/limited.html", token=token)


@app.route("/q/<token>/done", methods=["POST"])
def q_done(token):
    session.pop("helper_access", None)
    flash("Thank you for helping. Your verified access has been recorded.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if get_current_admin():
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        admin = User.query.filter_by(email=email, is_admin=True).first()
        if admin is None or not admin.is_active or not admin.check_password(password):
            flash("Invalid admin credentials.", "danger")
        else:
            session["admin_id"] = admin.id
            session.pop("user_id", None)
            flash("Welcome back, Admin.", "success")
            return redirect(url_for("admin_dashboard"))
    return render_template("admin/login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_id", None)
    flash("Logged out of admin console.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/")
@admin_required
def admin_dashboard():
    return render_template("admin/dashboard.html", nav="dashboard", stats=admin_stats())


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        user = User.query.get(user_id)
        if user and not user.is_admin:
            active = toggle_suspend(user)
            flash(
                f"User {user.email} is now {'active' if active else 'suspended'}.",
                "success" if active else "warning",
            )
        return redirect(url_for("admin_users"))
    search = request.args.get("q", "").strip()
    rows = list_users(search)
    counts = {u.id: user_access_count(u.id) for u in rows}
    return render_template("admin/users.html", nav="users", users=rows, counts=counts, search=search)


@app.route("/admin/logs", methods=["GET", "POST"])
@admin_required
def admin_logs():
    if request.method == "POST":
        log_id = request.form.get("log_id")
        log = db.session.get(AccessLog, log_id)
        if log:
            flagged = toggle_flag(log, request.form.get("flag_reason"))
            flash(
                "Access log flagged for review." if flagged else "Flag removed from access log.",
                "success" if flagged else "info",
            )
        return redirect(url_for("admin_logs", flagged_only=request.form.get("from_flagged")))
    search = request.args.get("q", "").strip()
    flagged_only = request.args.get("flagged_only") == "1"
    rows = list_logs(search=search, flagged_only=flagged_only)
    return render_template(
        "admin/logs.html",
        nav="logs",
        logs=rows,
        search=search,
        flagged_only=flagged_only,
    )


# ---------------------------------------------------------------------------
# Admin bootstrap / template helpers / error handlers
# ---------------------------------------------------------------------------


def _ensure_admin():
    admin = User.query.filter_by(is_admin=True).first()
    if admin is None:
        cfg = current_app.config
        admin = User(
            email=cfg["ADMIN_EMAIL"].lower(),
            full_name="ResQLink Admin",
            is_admin=True,
            is_active=True,
        )
        admin.set_password(cfg["ADMIN_PASSWORD"])
        db.session.add(admin)
        db.session.commit()


def _register_template_helpers(app):
    @app.context_processor
    def inject_defaults():
        return {"current_user": get_current_user(), "app_name": "ResQLink"}

    @app.template_filter("utc")
    def _utc(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def _register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("errors.html", title="403", code=403, message="You do not have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("errors.html", title="404", code=404, message="The page you are looking for does not exist."), 404

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        return render_template("errors.html", title="500", code=500, message="Something went wrong on our side. Please try again."), 500


with app.app_context():
    db.create_all()
    _ensure_admin()

_register_template_helpers(app)
_register_error_handlers(app)

if __name__ == "__main__":
    app.run(debug=True)