from flask_login import UserMixin
from datetime import datetime, timezone
from uuid import uuid4

from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id():
    return str(uuid4())


class User(UserMixin, db.Model):
    __tablename__ = "tv_users"

    id = db.Column(db.String(36), primary_key=True, default=new_id)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="owner")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    documents = db.relationship("Document", back_populates="owner")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)


class Document(db.Model):
    __tablename__ = "tv_documents"

    id = db.Column(db.String(36), primary_key=True, default=new_id)
    owner_id = db.Column(
        db.String(36),
        db.ForeignKey("tv_users.id"),
        nullable=False,
        index=True,
    )
    title = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    category = db.Column(
        db.String(50),
        nullable=False,
        default="General",
        server_default="General",
    )
    storage_key = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    is_deleted = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("0"),
    )

    owner = db.relationship("User", back_populates="documents")
    permissions = db.relationship(
        "Permission",
        back_populates="document",
        cascade="all, delete-orphan",
    )


class Permission(db.Model):
    __tablename__ = "tv_doc_permissions"
    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_tv_doc_user",
        ),
    )

    id = db.Column(db.String(36), primary_key=True, default=new_id)
    document_id = db.Column(
        db.String(36),
        db.ForeignKey("tv_documents.id"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("tv_users.id"),
        nullable=False,
        index=True,
    )
    permission = db.Column(db.String(20), nullable=False, default="read")
    is_revoked = db.Column(db.Boolean, nullable=False, default=False)
    granted_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    revoked_at = db.Column(db.DateTime, nullable=True)

    document = db.relationship("Document", back_populates="permissions")
    user = db.relationship("User", foreign_keys=[user_id])


class AuditLog(db.Model):
    __tablename__ = "tv_audit_logs"

    id = db.Column(db.String(36), primary_key=True, default=new_id)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("tv_users.id"),
        nullable=True,
        index=True,
    )
    document_id = db.Column(
        db.String(36),
        db.ForeignKey("tv_documents.id"),
        nullable=True,
        index=True,
    )
    action = db.Column(db.String(80), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.String(1000), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    previous_hash = db.Column(db.String(64), nullable=True)
    event_hash = db.Column(db.String(64), nullable=False, unique=True)
    chain_index = db.Column(db.Integer, nullable=False, unique=True)

    user = db.relationship("User", foreign_keys=[user_id])
