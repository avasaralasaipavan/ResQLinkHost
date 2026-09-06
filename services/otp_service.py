"""OTP issuance, delivery, verification and abuse protection."""

import hashlib
import random
import secrets
from datetime import timedelta

from flask import current_app

from extensions import db
from models import OtpRecord, utcnow
from .email_service import send_otp_email, send_otp_sms

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