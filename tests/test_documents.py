from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest

from app.extensions import db
from app.models import Document, Permission


@pytest.fixture()
def client(document_env):
    return document_env["app"].test_client()


def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
    )


def make_document(document_env, owner_name="alice", content=b"private test"):
    application = document_env["app"]

    with application.app_context():
        storage_key = uuid4().hex
        path = document_env["upload_dir"] / storage_key
        path.write_bytes(content)

        document = Document(
            owner_id=document_env["ids"][owner_name],
            title="Test document",
            original_filename="test.txt",
            storage_key=storage_key,
        )
        db.session.add(document)
        db.session.commit()
        return document.id


def test_documents_requires_login(client):
    response = client.get("/documents/")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_owner_can_upload_and_download(client, document_env):
    login(client, "alice", "TestPassword123!")

    response = client.post(
        "/documents/upload",
        data={
            "title": "My test file",
            "file": (BytesIO(b"hello TrustVault"), "hello.txt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302

    with document_env["app"].app_context():
        document = Document.query.filter_by(
            title="My test file"
        ).one()
        saved_path = document_env["upload_dir"] / document.storage_key

        assert saved_path.is_file()
        assert saved_path.read_bytes() == b"hello TrustVault"
        document_id = document.id

    response = client.get(f"/documents/{document_id}/download")

    assert response.status_code == 200
    assert response.data == b"hello TrustVault"

    events = document_env["audit_events"]
    assert any(
        e["action"] == "document_upload" and e["outcome"] == "success"
        for e in events
    )
    assert any(
        e["action"] == "document_download" and e["outcome"] == "success"
        for e in events
    )


def test_another_user_cannot_download_private_document(
    client, document_env
):
    document_id = make_document(document_env)

    login(client, "bob", "TestPassword456!")
    response = client.get(f"/documents/{document_id}/download")

    assert response.status_code == 404
    assert any(
        e["action"] == "document_download" and e["outcome"] == "denied"
        for e in document_env["audit_events"]
    )


def test_owner_sees_document_in_list(client, document_env):
    make_document(document_env)

    login(client, "alice", "TestPassword123!")
    response = client.get("/documents/")

    assert response.status_code == 200
    assert b"Test document" in response.data
    assert b"test.txt" in response.data


def test_upload_without_file_is_rejected(client):
    login(client, "alice", "TestPassword123!")

    response = client.post(
        "/documents/upload",
        data={"title": "Missing file"},
    )

    assert response.status_code == 302


def test_owner_can_edit_document(client, document_env):
    document_id = make_document(document_env, content=b"initial content")
    login(client, "alice", "TestPassword123!")

    get_resp = client.get(f"/documents/{document_id}/edit")
    assert get_resp.status_code == 200
    assert b"initial content" in get_resp.data

    post_resp = client.post(
        f"/documents/{document_id}/edit",
        data={"content": "updated secure content"},
    )
    assert post_resp.status_code == 302

    download_resp = client.get(f"/documents/{document_id}/download")
    assert download_resp.data == b"updated secure content"

    assert any(
        e["action"] == "document_edit" and e["outcome"] == "success"
        for e in document_env["audit_events"]
    )


def test_shared_write_user_can_edit_but_read_user_cannot(client, document_env):
    document_id = make_document(document_env, content=b"shared text")
    login(client, "alice", "TestPassword123!")

    # Grant read-only permission to Bob first
    client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "read"},
    )

    bob_client = document_env["app"].test_client()
    login(bob_client, "bob", "TestPassword456!")

    denied_edit = bob_client.post(
        f"/documents/{document_id}/edit",
        data={"content": "unauthorized edit"},
    )
    assert denied_edit.status_code == 404

    # Upgrade Bob to write permission
    client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "write"},
    )

    allowed_edit = bob_client.post(
        f"/documents/{document_id}/edit",
        data={"content": "authorized collaborator edit"},
    )
    assert allowed_edit.status_code == 302

    download_resp = bob_client.get(f"/documents/{document_id}/download")
    assert download_resp.data == b"authorized collaborator edit"


def test_owner_can_soft_delete_document(client, document_env):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(f"/documents/{document_id}/delete")

    assert response.status_code == 302

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        assert document is not None
        assert document.is_deleted is True

    events = document_env["audit_events"]
    assert any(
        event["action"] == "document_delete"
        and event["outcome"] == "requested"
        for event in events
    )
    assert any(
        event["action"] == "document_delete"
        and event["outcome"] == "success"
        for event in events
    )


def test_non_owner_cannot_delete_document(client, document_env):
    document_id = make_document(document_env)
    login(client, "bob", "TestPassword456!")

    response = client.post(f"/documents/{document_id}/delete")

    assert response.status_code == 404

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        assert document is not None
        assert document.is_deleted is False


def test_deleted_document_cannot_be_downloaded(client, document_env):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(f"/documents/{document_id}/delete")
    assert response.status_code == 302

    response = client.get(f"/documents/{document_id}/download")
    assert response.status_code == 404


def test_deleted_document_is_hidden_from_document_list(
    client, document_env
):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(f"/documents/{document_id}/delete")
    assert response.status_code == 302

    response = client.get("/documents/")

    assert response.status_code == 200
    assert b"Test document" not in response.data


def test_delete_removes_private_file_but_preserves_document_row(
    client, document_env
):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        file_path = document_env["upload_dir"] / document.storage_key
        assert file_path.is_file()

    response = client.post(f"/documents/{document_id}/delete")
    assert response.status_code == 302

    assert not file_path.exists()

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        assert document is not None
        assert document.is_deleted is True


def test_delete_keeps_document_inaccessible_when_file_cleanup_fails(
    client, document_env, monkeypatch
):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        file_path = document_env["upload_dir"] / document.storage_key
        assert file_path.is_file()

    original_unlink = Path.unlink

    def fail_target_file_unlink(self, *args, **kwargs):
        if self == file_path:
            raise OSError("Simulated file cleanup failure")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_target_file_unlink)

    response = client.post(f"/documents/{document_id}/delete")

    assert response.status_code == 302

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        assert document is not None
        assert document.is_deleted is True

    # Physical cleanup failed, but application access must stay revoked.
    assert file_path.is_file()
    assert client.get(f"/documents/{document_id}/download").status_code == 404

    assert any(
        event["action"] == "document_delete"
        and event["outcome"] == "failure"
        for event in document_env["audit_events"]
    )


def test_delete_remains_effective_when_final_audit_write_fails(
    client, document_env, monkeypatch
):
    import app.documents as documents_module

    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        file_path = document_env["upload_dir"] / document.storage_key

    original_append = documents_module.append_audit_event

    def fail_final_audit(*args, **kwargs):
        if (
            kwargs.get("action") == "document_delete"
            and kwargs.get("outcome") in {"success", "failure"}
        ):
            raise RuntimeError("Simulated final audit write failure")

        return original_append(*args, **kwargs)

    monkeypatch.setattr(
        documents_module, "append_audit_event", fail_final_audit
    )

    response = client.post(f"/documents/{document_id}/delete")

    assert response.status_code == 302

    # A final audit failure must not restore access to the document.
    with document_env["app"].app_context():
        document = db.session.get(Document, document_id)
        assert document is not None
        assert document.is_deleted is True

    assert not file_path.exists()
    assert client.get(f"/documents/{document_id}/download").status_code == 404


def test_deleted_document_cannot_be_shared_again(client, document_env):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    delete_response = client.post(
        f"/documents/{document_id}/delete"
    )
    assert delete_response.status_code == 302

    share_response = client.post(
        f"/documents/{document_id}/share",
        data={},
    )

    assert share_response.status_code == 404


def test_deleted_document_preserves_permission_but_blocks_recipient(
    client, document_env
):
    document_id = make_document(document_env)

    # Give Bob read access before deletion.
    with document_env["app"].app_context():
        permission = Permission(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
            permission="read",
            is_revoked=False,
        )
        db.session.add(permission)
        db.session.commit()
        permission_id = permission.id

    # Alice owns the document and deletes it.
    login(client, "alice", "TestPassword123!")
    response = client.post(f"/documents/{document_id}/delete")
    assert response.status_code == 302

    # The permission remains for historical traceability.
    with document_env["app"].app_context():
        permission = db.session.get(Permission, permission_id)
        document = db.session.get(Document, document_id)

        assert permission is not None
        assert permission.is_revoked is False
        assert document is not None
        assert document.is_deleted is True

    # Bob's existing permission must not bypass the deletion check.
    bob_client = document_env["app"].test_client()
    login(bob_client, "bob", "TestPassword456!")

    response = bob_client.get(
        f"/documents/{document_id}/download"
    )
    assert response.status_code == 404


def test_oversized_upload_is_rejected(client, document_env):
    # Authenticate before lowering the limit for this test.
    login(client, "alice", "TestPassword123!")

    application = document_env["app"]
    application.config["MAX_CONTENT_LENGTH"] = 1024

    response = client.post(
        "/documents/upload",
        data={
            "title": "Oversized test file",
            "file": (BytesIO(b"A" * 4096), "large.txt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413

    with application.app_context():
        assert Document.query.filter_by(
            title="Oversized test file"
        ).first() is None

    assert list(document_env["upload_dir"].iterdir()) == []


def test_revoked_user_cannot_download_document(
    client, document_env
):
    document_id = make_document(document_env)

    login(client, "alice", "TestPassword123!")

    share_response = client.post(
        f"/documents/{document_id}/share",
        data={
            "username": "bob",
            "permission": "read",
        },
    )
    assert share_response.status_code == 302

    bob_client = document_env["app"].test_client()
    login(bob_client, "bob", "TestPassword456!")

    download_response = bob_client.get(
        f"/documents/{document_id}/download"
    )
    assert download_response.status_code == 200
    assert download_response.data == b"private test"

    bob_id = document_env["ids"]["bob"]
    revoke_response = client.post(
        f"/documents/{document_id}/revoke/{bob_id}"
    )
    assert revoke_response.status_code == 302

    with document_env["app"].app_context():
        db.session.expire_all()
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=bob_id,
        ).one()
        assert permission.is_revoked is True
        assert permission.revoked_at is not None

    denied_response = bob_client.get(
        f"/documents/{document_id}/download"
    )
    assert denied_response.status_code == 404


def test_non_owner_cannot_view_document_history(client, document_env):
    document_id = make_document(document_env)
    login(client, "bob", "TestPassword456!")

    response = client.get(f"/documents/{document_id}/history")
    assert response.status_code == 404
    assert any(
        e["action"] == "document_history" and e["outcome"] == "denied"
        for e in document_env["audit_events"]
    )


def test_viewer_role_cannot_upload_documents(client, document_env):
    login(client, "charlie_viewer", "ViewerPass123!@#")

    get_resp = client.get("/documents/upload")
    assert get_resp.status_code == 403

    post_resp = client.post(
        "/documents/upload",
        data={
            "title": "Unauthorized Viewer Upload",
            "file": (BytesIO(b"blocked"), "blocked.txt"),
        },
        content_type="multipart/form-data",
    )
    assert post_resp.status_code == 403


def test_search_by_name_owner_category_and_date(client, document_env):
    from datetime import datetime

    with document_env["app"].app_context():
        doc1 = Document(
            owner_id=document_env["ids"]["alice"],
            title="Q4 Salary Letter",
            original_filename="salary.txt",
            category="HR",
            storage_key=uuid4().hex,
            created_at=datetime(2026, 10, 15, 12, 0, 0),
        )
        doc2 = Document(
            owner_id=document_env["ids"]["bob"],
            title="Vendor Contract",
            original_filename="contract.txt",
            category="Legal",
            storage_key=uuid4().hex,
            created_at=datetime(2026, 10, 20, 12, 0, 0),
        )
        db.session.add_all([doc1, doc2])
        db.session.commit()

        perm = Permission(
            document_id=doc2.id,
            user_id=document_env["ids"]["alice"],
            permission="read",
            is_revoked=False,
        )
        db.session.add(perm)
        db.session.commit()

    login(client, "alice", "TestPassword123!")

    # Filter by name
    r_name = client.get("/documents/?q=Salary")
    assert b"Q4 Salary Letter" in r_name.data
    assert b"Vendor Contract" not in r_name.data

    # Filter by owner
    r_owner = client.get("/documents/?owner=bob")
    assert b"Vendor Contract" in r_owner.data
    assert b"Q4 Salary Letter" not in r_owner.data

    # Filter by category
    r_cat = client.get("/documents/?category=HR")
    assert b"Q4 Salary Letter" in r_cat.data
    assert b"Vendor Contract" not in r_cat.data

    # Filter by date
    r_date = client.get("/documents/?date=2026-10-20")
    assert b"Vendor Contract" in r_date.data
    assert b"Q4 Salary Letter" not in r_date.data


def test_admin_can_view_permission_changes_in_activity(client, document_env):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")
    client.post(
        f"/documents/{document_id}/share",
        data={"username": "bob", "permission": "write"},
    )
    client.post("/logout")

    login(client, "admin_user", "AdminPass123!@#")
    resp = client.get("/documents/activity")
    assert resp.status_code == 200
    assert b"Global Permission Grants" in resp.data
    assert b"Test document" in resp.data


def test_share_single_document_with_multiple_users(client, document_env):
    document_id = make_document(document_env)
    login(client, "alice", "TestPassword123!")

    response = client.post(
        f"/documents/{document_id}/share",
        data={
            "username": "bob, charlie_viewer",
            "permission": "edit",
        },
    )
    assert response.status_code == 302

    with document_env["app"].app_context():
        bob_perm = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["bob"],
            is_revoked=False,
        ).one()
        viewer_perm = Permission.query.filter_by(
            document_id=document_id,
            user_id=document_env["ids"]["viewer"],
            is_revoked=False,
        ).one()
        assert bob_perm.permission == "write"
        assert viewer_perm.permission == "write"


def test_bulk_share_multiple_documents_with_user(client, document_env):
    doc1 = make_document(document_env, content=b"doc 1")
    doc2 = make_document(document_env, content=b"doc 2")
    login(client, "alice", "TestPassword123!")

    response = client.post(
        "/documents/bulk-share",
        data={
            "document_ids": [doc1, doc2],
            "usernames": ["bob", "charlie_viewer"],
            "permission": "write",
        },
    )
    assert response.status_code == 302

    bob_client = document_env["app"].test_client()
    login(bob_client, "bob", "TestPassword456!")
    assert bob_client.get(f"/documents/{doc1}/download").status_code == 200
    assert bob_client.get(f"/documents/{doc2}/download").status_code == 200


def test_non_owner_cannot_bulk_share_others_documents(client, document_env):
    doc1 = make_document(document_env, content=b"alice private")
    login(client, "bob", "TestPassword456!")

    response = client.post(
        "/documents/bulk-share",
        data={
            "document_ids": [doc1],
            "username": "charlie_viewer",
            "permission": "read",
        },
    )
    assert response.status_code == 404


def test_bulk_delete_multiple_owned_documents(client, document_env):
    doc1 = make_document(document_env, content=b"del 1")
    doc2 = make_document(document_env, content=b"del 2")
    login(client, "alice", "TestPassword123!")

    response = client.post(
        "/documents/bulk-delete",
        data={"document_ids": [doc1, doc2]},
    )
    assert response.status_code == 302

    with document_env["app"].app_context():
        assert db.session.get(Document, doc1).is_deleted is True
        assert db.session.get(Document, doc2).is_deleted is True


def test_non_owner_cannot_bulk_delete_others_documents(client, document_env):
    doc1 = make_document(document_env, content=b"alice doc")
    login(client, "bob", "TestPassword456!")

    response = client.post(
        "/documents/bulk-delete",
        data={"document_ids": [doc1]},
    )
    assert response.status_code == 404
    with document_env["app"].app_context():
        assert db.session.get(Document, doc1).is_deleted is False


def test_write_recipient_can_edit_binary_document_via_replacement_file_and_metadata(client, document_env):
    # Simulate a binary PDF/image file with non-UTF8 bytes
    doc_id = make_document(document_env, content=b"\x89PNG\r\n\x1a\n\x00\xff\xfe")
    login(client, "alice", "TestPassword123!")
    client.post(
        f"/documents/{doc_id}/share",
        data={"username": "bob", "permission": "write"},
    )

    bob_client = document_env["app"].test_client()
    login(bob_client, "bob", "TestPassword456!")

    # GET edit page must NOT redirect away even for non-UTF8 binary files!
    get_resp = bob_client.get(f"/documents/{doc_id}/edit")
    assert get_resp.status_code == 200

    # POST replacement file + updated title/category as recipient with write access
    post_resp = bob_client.post(
        f"/documents/{doc_id}/edit",
        data={
            "title": "Updated Binary Spec",
            "category": "Engineering",
            "replacement_file": (BytesIO(b"new version bytes"), "updated_spec.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert post_resp.status_code == 302

    dl_resp = bob_client.get(f"/documents/{doc_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.data == b"new version bytes"

    with document_env["app"].app_context():
        doc = db.session.get(Document, doc_id)
        assert doc.title == "Updated Binary Spec"
        assert doc.category == "Engineering"
        assert doc.original_filename == "updated_spec.pdf"


def test_executable_file_upload_is_rejected_by_validation(client, document_env):
    login(client, "alice", "TestPassword123!")

    # Disallowed extension (.exe) or PE magic bytes (MZ)
    resp = client.post(
        "/documents/upload",
        data={
            "title": "Malicious binary",
            "file": (BytesIO(b"MZ\x90\x00executable"), "payload.txt"),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    with document_env["app"].app_context():
        assert Document.query.filter_by(title="Malicious binary").first() is None
