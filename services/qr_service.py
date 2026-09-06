"""QR token management and image generation."""

import base64
import io
import secrets

import qrcode

from extensions import db
from models import User, utcnow


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