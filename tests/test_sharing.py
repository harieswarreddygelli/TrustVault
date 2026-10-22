from uuid import uuid4

from app.extensions import db
from app.models import Document, Permission, User


def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
    )


def make_private_document(document_env):
    with document_env["app"].app_context():
        storage_key = uuid4().hex
        (document_env["upload_dir"] / storage_key).write_bytes(b"shared test")

        document = Document(
            owner_id=document_env["ids"]["alice"],
            title="Shared test document",
            original_filename="shared.txt",
            storage_key=storage_key,
        )
        db.session.add(document)
        db.session.commit()
        return document.id


def test_owner_can_share_document_with_active_reader(client, document_env):
    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "read"},
    )

    assert response.status_code == 302

    with document_env["app"].app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
        ).one()
        assert permission.permission == "read"
        assert permission.is_revoked is False


def test_shared_reader_can_download_then_is_denied_after_revocation(
    client, document_env
):
    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "read"},
    )
    assert response.status_code == 302

    client.post("/logout")
    login(client, "bob", "TestPassword456!")

    response = client.get(f"/documents/{document_id}/download")
    assert response.status_code == 200
    assert response.data == b"shared test"

    client.post("/logout")
    login(client, "alice", "TestPassword123!")

    response = client.post(
        f"/documents/{document_id}/revoke/{document_env['ids']['bob']}"
    )
    assert response.status_code == 302

    client.post("/logout")
    login(client, "bob", "TestPassword456!")

    response = client.get(f"/documents/{document_id}/download")
    assert response.status_code == 404


def test_non_owner_cannot_share_or_revoke_another_users_document(
    client, document_env
):
    document_id = make_private_document(document_env)
    login(client, "bob", "TestPassword456!")

    response = client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "read"},
    )
    assert response.status_code == 404

    response = client.post(
        f"/documents/{document_id}/revoke/{document_env['ids']['bob']}"
    )
    assert response.status_code == 404


def test_owner_can_revoke_permission(client, document_env):
    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "write"},
    )

    response = client.post(
        f"/documents/{document_id}/revoke/{document_env['ids']['bob']}"
    )
    assert response.status_code == 302

    with document_env["app"].app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
        ).one()
        assert permission.is_revoked is True
        assert permission.revoked_at is not None

def test_invalid_permission_is_rejected(client, document_env):
    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "admin"},
    )

    assert response.status_code == 302
    with document_env["app"].app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
        ).first()
        assert permission is None


def test_unknown_user_cannot_receive_document_access(client, document_env):
    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(
        f"/documents/{document_id}/share",
        data={"username": "unknown_user", "permission": "read"},
    )

    assert response.status_code == 302
    with document_env["app"].app_context():
        assert Permission.query.filter_by(
            document_id=document_id,
        ).count() == 0


def test_failed_audit_does_not_leave_new_share_permission(
    client, document_env, monkeypatch
):
    import app.documents as documents_module

    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit failure")

    monkeypatch.setattr(documents_module, "append_audit_event", fail_audit)

    response = client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "read"},
    )

    assert response.status_code == 302
    with document_env["app"].app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
        ).first()
        assert permission is None


def test_failed_audit_restores_permission_after_revoke(
    client, document_env, monkeypatch
):
    import app.documents as documents_module

    document_id = make_private_document(document_env)
    login(client, "alice", "TestPassword123!")

    # First grant access with the normal test audit writer.
    client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "write"},
    )

    def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit failure")

    monkeypatch.setattr(documents_module, "append_audit_event", fail_audit)

    response = client.post(
        f"/documents/{document_id}/revoke/{document_env['ids']['bob']}"
    )

    assert response.status_code == 302
    with document_env["app"].app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
        ).one()
        assert permission.permission == "write"
        assert permission.is_revoked is False
        assert permission.revoked_at is None
