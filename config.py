import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load .env from the project root so every setting below can be overridden
# from a single file without touching code.
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _int(name, default):
    return int(os.environ.get(name, default))


def _bool(name, default):
    val = os.environ.get(name, str(default))
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # Core
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me-in-production")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "resqlink.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True

    # Public base URL used to build the QR payload.
    # In production set this to the real domain, e.g. https://resqlink.pythonanywhere.com
    BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

    # ---- OTP settings ----
    OTP_LENGTH = _int("OTP_LENGTH", 6)
    OTP_EXPIRY_MINUTES = _int("OTP_EXPIRY_MINUTES", 10)
    OTP_MAX_ATTEMPTS = _int("OTP_MAX_ATTEMPTS", 5)  # max wrong guesses per code
    OTP_RATE_LIMIT_COUNT = _int("OTP_RATE_LIMIT_COUNT", 5)  # max codes per identifier
    OTP_RATE_LIMIT_WINDOW_MINUTES = _int("OTP_RATE_LIMIT_WINDOW_MINUTES", 15)
    OTP_COOLDOWN_SECONDS = _int("OTP_COOLDOWN_SECONDS", 30)  # min gap between sends

    # ---- Email (Flask-Mail via SMTP). Defaults target Gmail SMTP. ----
    # For Gmail you MUST use an App Password (google account -> Security -> 2-Step
    # Verification -> App passwords), NOT your normal password.
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = _int("MAIL_PORT", 587)
    MAIL_USE_TLS = _bool("MAIL_USE_TLS", True)
    MAIL_USE_SSL = _bool("MAIL_USE_SSL", False)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_FROM", "ResQLink <no-reply@resqlink.app>")
    MAIL_SUPPRESS_SEND = _bool("MAIL_SUPPRESS_SEND", False)
    # When True, the OTP is also shown in the UI for development/testing.
    MAIL_DEBUG = _bool("MAIL_DEBUG", True)

    # ---- Default QR access limitation (owner configurable) ----
    DEFAULT_ACCESS_LIMIT_COUNT = _int("DEFAULT_ACCESS_LIMIT_COUNT", 3)
    DEFAULT_ACCESS_LIMIT_WINDOW_MINUTES = _int("DEFAULT_ACCESS_LIMIT_WINDOW_MINUTES", 60)

    # ---- Bootstrap admin account ----
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@resqlink.app")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    MAIL_DEBUG = True