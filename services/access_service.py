"""Helper-facing logic: QR lookups, access limits and audit logging."""

from datetime import timedelta

from extensions import db
from models import AccessConfig, AccessLog, User, utcnow


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
            max_count=_default_count(),
            window_minutes=_default_window(),
        )
        db.session.add(cfg)
        db.session.commit()
    return cfg


def _default_count():
    from flask import current_app

    return current_app.config["DEFAULT_ACCESS_LIMIT_COUNT"]


def _default_window():
    from flask import current_app

    return current_app.config["DEFAULT_ACCESS_LIMIT_WINDOW_MINUTES"]


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