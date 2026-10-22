import pytest

from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture()
def app(monkeypatch):
    # Prevent test login/logout requests from writing to the real
    # Oracle audit chain.
    import app.auth as auth_module

    audit_events = []

    def fake_audit_event(**kwargs):
        audit_events.append(kwargs)
        return {
            "id": f"test-{len(audit_events)}",
            "chain_index": len(audit_events),
            "event_hash": "test-hash",
        }

    monkeypatch.setattr(
        auth_module, "append_audit_event", fake_audit_event
    )

    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "WTF_CSRF_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
        }
    )

    with application.app_context():
        db.create_all()

        user = User(
            username="alice",
            email="alice@example.test",
            role="owner",
            is_active=True,
        )
        user.set_password("TestPassword123!")
        db.session.add(user)
        db.session.commit()

    # Important: yield OUTSIDE the application context so each test request
    # manages its own clean request/application context and calls load_user() fresh!
    yield application, audit_events

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    application, _ = app
    return application.test_client()


def test_login_page_loads(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert b"username" in response.data
    assert b"password" in response.data


def test_valid_login_records_success_and_authenticates(client, app):
    response = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 302
    assert "/documents/" in response.headers["Location"]

    _, audit_events = app
    assert audit_events[-1]["action"] == "login"
    assert audit_events[-1]["outcome"] == "success"

    # The same client should now have an authenticated session.
    response = client.get("/login")
    assert response.status_code == 302


def test_invalid_password_is_rejected_and_audited(client, app):
    response = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "WrongPassword!",
        },
    )

    assert response.status_code == 401

    _, audit_events = app
    assert audit_events[-1]["action"] == "login"
    assert audit_events[-1]["outcome"] == "failure"


def test_unknown_username_is_rejected_and_audited(client, app):
    response = client.post(
        "/login",
        data={
            "username": "unknown-user",
            "password": "Anything123!",
        },
    )

    assert response.status_code == 401

    _, audit_events = app
    assert audit_events[-1]["action"] == "login"
    assert audit_events[-1]["outcome"] == "failure"
    assert audit_events[-1]["user_id"] is None


def test_logout_ends_session_and_is_audited(client, app):
    client.post(
        "/login",
        data={
            "username": "alice",
            "password": "TestPassword123!",
        },
    )

    response = client.post("/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    _, audit_events = app
    assert audit_events[-1]["action"] == "logout"
    assert audit_events[-1]["outcome"] == "success"

    # Logging in again should require credentials.
    response = client.get("/login")
    assert response.status_code == 200


def test_user_can_update_profile_username_and_email(client, app):
    client.post(
        "/login",
        data={
            "username": "alice",
            "password": "TestPassword123!",
        },
    )

    response = client.post(
        "/profile",
        data={
            "username": "alice_updated",
            "email": "alice_new@example.test",
        },
    )

    assert response.status_code == 302

    application, audit_events = app
    with application.app_context():
        user = User.query.filter_by(username="alice_updated").one()
        assert user.email == "alice_new@example.test"

    assert any(
        e["action"] == "profile_update" and e["outcome"] == "success"
        for e in audit_events
    )


def test_deactivated_user_session_is_immediately_rejected(client, app):
    client.post(
        "/login",
        data={
            "username": "alice",
            "password": "TestPassword123!",
        },
    )

    application, _ = app
    with application.app_context():
        user = User.query.filter_by(username="alice").one()
        user.is_active = False
        db.session.commit()

    # Very next request must reject the deactivated account's session
    response = client.get("/documents/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
