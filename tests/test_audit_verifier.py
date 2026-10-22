
from datetime import datetime

from scripts.verify_audit_chain import calculate_hash, verify_chain


from contextlib import contextmanager

from app.audit_service import (
    AuditChainIntegrityError,
    append_audit_event,
)
from app.extensions import db
import pytest

class FakeResult:
    def __init__(self, rows):
        self.rows = rows

    def mappings(self):
        return self

    def all(self):
        return self.rows


class FakeConnection:
    """Return isolated test events without connecting to Oracle."""

    def __init__(self, rows):
        self.rows = rows

    def execute(self, statement):
        return FakeResult(self.rows)


def make_valid_chain(count=2):
    rows = []
    previous_hash = None

    for index in range(1, count + 1):
        row = {
            "chain_index": index,
            "id": f"test-event-{index}",
            "user_id": "test-user",
            "document_id": "test-document",
            "action": "document_download",
            "outcome": "success",
            "details": f"Test event {index}",
            "created_at": datetime(2026, 10, 20, 10, index, 0),
            "previous_hash": previous_hash,
            "event_hash": None,
        }

        row["event_hash"] = calculate_hash(row, previous_hash)
        previous_hash = row["event_hash"]
        rows.append(row)

    return rows


def test_valid_audit_chain_passes():
    rows = make_valid_chain()

    total, errors = verify_chain(FakeConnection(rows))

    assert total == 2
    assert errors == []


def test_modified_event_details_are_detected():
    rows = make_valid_chain()
    rows[0]["details"] = "Tampered event details"

    total, errors = verify_chain(FakeConnection(rows))

    assert total == 2
    assert any("Event hash mismatch" in error for error in errors)


def test_modified_previous_hash_is_detected():
    rows = make_valid_chain()
    rows[1]["previous_hash"] = "tampered-previous-hash"

    total, errors = verify_chain(FakeConnection(rows))

    assert total == 2
    assert any("Previous-hash mismatch" in error for error in errors)


def test_sequence_gap_is_detected():
    rows = make_valid_chain()
    rows[1]["chain_index"] = 3

    total, errors = verify_chain(FakeConnection(rows))

    assert total == 2
    assert any("Sequence gap" in error for error in errors)






class FakeAuditWriteConnection:
    def __init__(self, rows):
        self.rows = rows
        self.insert_attempted = False

    def execute(self, statement, parameters=None):
        sql = str(statement).upper()

        if "LOCK TABLE TV_AUDIT_LOGS" in sql:
            return None

        if "FROM TV_AUDIT_LOGS" in sql:
            return FakeResult(self.rows)

        if "INSERT INTO TV_AUDIT_LOGS" in sql:
            self.insert_attempted = True
            return None

        raise AssertionError(f"Unexpected SQL in test: {sql}")


class FakeAuditTransaction:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_append_refuses_to_extend_corrupted_audit_chain(
    document_env, monkeypatch
):
    rows = make_valid_chain(count=2)

    # Simulate tampering after the event hash was calculated.
    rows[0]["details"] = "Modified after hashing"

    connection = FakeAuditWriteConnection(rows)

    # Keep the engine and its patch inside the application context.
    with document_env["app"].app_context():
        engine = db.engine
        original_begin = engine.begin

        try:
            monkeypatch.setattr(
                engine,
                "begin",
                lambda: FakeAuditTransaction(connection),
            )

            with pytest.raises(AuditChainIntegrityError):
                append_audit_event(
                    action="test_event",
                    outcome="success",
                    details="This event must not be appended",
                )

            assert connection.insert_attempted is False

        finally:
            monkeypatch.setattr(engine, "begin", original_begin)
