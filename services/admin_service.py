"""Admin queries and moderation actions."""

from flask import abort

from extensions import db
from models import AccessLog, User


def stats():
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