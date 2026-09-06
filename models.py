from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utcnow():
    """Timezone-aware-free UTC timestamp for SQLite storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False, default="")
    phone = db.Column(db.String(20), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # QR identity (unique, non-guessable token)
    qr_token = db.Column(db.String(32), unique=True, nullable=True)
    qr_enabled = db.Column(db.Boolean, default=True, nullable=False)
    qr_created_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    contacts = db.relationship(
        "EmergencyContact", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    access_config = db.relationship(
        "AccessConfig", backref="user", uselist=False, cascade="all, delete-orphan"
    )
    access_logs = db.relationship(
        "AccessLog", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return bool(self.password_hash) and check_password_hash(self.password_hash, password)

    @property
    def qr_url(self):
        from flask import current_app

        if not self.qr_token:
            return None
        base = current_app.config["BASE_URL"].rstrip("/")
        return f"{base}/q/{self.qr_token}"


class EmergencyContact(db.Model):
    __tablename__ = "emergency_contacts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    relationship = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class AccessConfig(db.Model):
    """Per-owner rule limiting how many helpers may view the contacts in a window."""

    __tablename__ = "access_configs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    limit_enabled = db.Column(db.Boolean, default=True, nullable=False)
    max_count = db.Column(db.Integer, default=3, nullable=False)
    window_minutes = db.Column(db.Integer, default=60, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class AccessLog(db.Model):
    """Audit trail for every verified QR access attempt."""

    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    helper_identifier = db.Column(db.String(255), nullable=False)
    channel = db.Column(db.String(10), nullable=False)  # 'email' | 'mobile'
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    contacts_displayed = db.Column(db.Boolean, default=False, nullable=False)
    denied_reason = db.Column(db.String(255), nullable=True)
    flagged = db.Column(db.Boolean, default=False, nullable=False)
    flag_reason = db.Column(db.String(255), nullable=True)
    accessed_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)


class OtpRecord(db.Model):
    __tablename__ = "otp_records"

    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), nullable=False, index=True)  # email or mobile
    channel = db.Column(db.String(10), nullable=False)  # 'email' | 'mobile'
    purpose = db.Column(db.String(20), nullable=False)  # register | login | helper
    code_hash = db.Column(db.String(255), nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    verified = db.Column(db.Boolean, default=False, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)