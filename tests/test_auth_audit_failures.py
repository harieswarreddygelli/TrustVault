
import app.auth as auth_module


def test_successful_login_audit_failure_does_not_create_session(
    document_env, monkeypatch
):
    client = document_env["app"].test_client()

    def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit outage")

    monkeypatch.setattr(auth_module, "append_audit_event", fail_audit)

    response = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 503

    # A later request must still be unauthenticated.
    response = client.get("/documents/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_failed_login_audit_failure_still_rejects_login(
    document_env, monkeypatch
):
    client = document_env["app"].test_client()

    def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit outage")

    monkeypatch.setattr(auth_module, "append_audit_event", fail_audit)

    response = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "incorrect-password",
        },
    )

    assert response.status_code == 401


def test_logout_clears_session_when_audit_fails(
    document_env, monkeypatch
):
    client = document_env["app"].test_client()

    # Log in while the fixture's normal audit mock is active.
    response = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 302

    def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit outage")

    monkeypatch.setattr(auth_module, "append_audit_event", fail_audit)

    response = client.post("/logout")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    # The session must be cleared even though logout auditing failed.
    response = client.get("/documents/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
