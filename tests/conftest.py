import pytest

from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture()
def document_env(tmp_path, monkeypatch):
    import app.auth as auth_module
    import app.documents as documents_module

    audit_events = []

    def fake_audit_event(**kwargs):
        audit_events.append(kwargs)
        return {
            "id": f"test-{len(audit_events)}",
            "chain_index": len(audit_events),
            "event_hash": "test-hash",
        }

    monkeypatch.setattr(auth_module, "append_audit_event", fake_audit_event)
    monkeypatch.setattr(
        documents_module, "append_audit_event", fake_audit_event
    )

    upload_dir = tmp_path / "private_uploads"
    upload_dir.mkdir()

    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": False,
        "SESSION_COOKIE_SECURE": False,
        "PRIVATE_UPLOAD_DIR": str(upload_dir),
    })

    with application.app_context():
        db.create_all()

        alice = User(
            username="alice",
            email="alice@example.test",
            role="owner",
            is_active=True,
        )
        alice.set_password("TestPassword123!")

        bob = User(
            username="bob",
            email="bob@example.test",
            role="owner",
            is_active=True,
        )
        bob.set_password("TestPassword456!")

        admin = User(
            username="admin_user",
            email="admin@example.test",
            role="admin",
            is_active=True,
        )
        admin.set_password("AdminPass123!@#")

        viewer = User(
            username="charlie_viewer",
            email="viewer@example.test",
            role="viewer",
            is_active=True,
        )
        viewer.set_password("ViewerPass123!@#")

        db.session.add_all([alice, bob, admin, viewer])
        db.session.commit()

        ids = {
            "alice": alice.id,
            "bob": bob.id,
            "admin": admin.id,
            "viewer": viewer.id,
        }

    # Important: yield OUTSIDE the application context.
    yield {
        "app": application,
        "ids": ids,
        "audit_events": audit_events,
        "upload_dir": upload_dir,
    }

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(document_env):
    return document_env["app"].test_client()
