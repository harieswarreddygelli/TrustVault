
from io import BytesIO

from app import create_app
from app.extensions import db
from app.models import User


def test_upload_without_csrf_token_is_rejected(tmp_path, monkeypatch):
    # Prevent Oracle audit writes: this test checks CSRF, not audit storage.
    import app.auth as auth_module
    import app.documents as documents_module

    def fake_audit_event(**kwargs):
        return {
            "id": "csrf-test-event",
            "chain_index": 1,
            "event_hash": "csrf-test-hash",
        }

    monkeypatch.setattr(auth_module, "append_audit_event", fake_audit_event)
    monkeypatch.setattr(
        documents_module, "append_audit_event", fake_audit_event
    )

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "csrf-test-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "WTF_CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": False,
        "PRIVATE_UPLOAD_DIR": str(tmp_path),
    })

    with app.app_context():
        db.create_all()
        user = User(
            username="csrf-user",
            email="csrf-user@example.test",
            is_active=True,
        )
        user.set_password("TestPassword123!")
        db.session.add(user)
        db.session.commit()

    client = app.test_client()

    # Obtain a session through the login form, including its CSRF token.
    login_page = client.get("/login")
    assert login_page.status_code == 200

    # Extract the token from the HTML form.
    import re

    match = re.search(
        rb'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"'
        rb'|name="csrf_token"\s+value="([^"]+)"',
        login_page.data,
    )
    assert match is not None, "Login form did not contain a CSRF token"
    token = next(group for group in match.groups() if group is not None)

    login_response = client.post(
        "/login",
        data={
            "username": "csrf-user",
            "password": "TestPassword123!",
            "csrf_token": token.decode(),
        },
    )
    assert login_response.status_code == 302

    # This state-changing request deliberately omits its CSRF token.
    response = client.post(
        "/documents/upload",
        data={
            "title": "Forged upload",
            "file": (BytesIO(b"should not be stored"), "forged.txt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400

    with app.app_context():
        assert User.query.filter_by(username="csrf-user").one()
        from app.models import Document
        assert Document.query.filter_by(title="Forged upload").first() is None
        db.session.remove()
        db.drop_all()
