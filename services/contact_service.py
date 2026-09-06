"""CRUD for a QR owner's emergency contacts."""

from flask import abort

from extensions import db
from models import EmergencyContact


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