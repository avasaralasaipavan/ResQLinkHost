"""E-mail / SMS delivery for OTP codes (via Flask-Mail for email).

If Gmail SMTP credentials are not configured the code is logged to the console and
the on-screen dev-mode OTP display is activated (return False).
"""

from flask import current_app
from flask_mail import Message

from extensions import mail


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