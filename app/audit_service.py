"""Centralized, tamper-evident audit logging for TrustVault."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.extensions import db


class AuditChainIntegrityError(RuntimeError):
    """Raised when the existing audit chain is inconsistent."""


def _now():
    # Oracle DATE has second precision, so hash exactly what it stores.
    return datetime.now(timezone.utc).replace(
        microsecond=0,
        tzinfo=None,
    )


def _canonical_hash(row, previous_hash):
    """Keep this payload identical to the original migration format."""
    created_at = row["created_at"]
    if isinstance(created_at, str):
        created_at_iso = created_at.replace(" ", "T")
    elif created_at is not None:
        created_at_iso = created_at.isoformat()
    else:
        created_at_iso = None

    payload = {
        "id": row["id"],
        "user_id": row["user_id"],
        "document_id": row["document_id"],
        "action": row["action"],
        "outcome": row["outcome"],
        "details": row["details"],
        "created_at": created_at_iso,
        "previous_hash": previous_hash,
    }

    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return sha256(canonical_json.encode("utf-8")).hexdigest()


def _load_and_validate_chain(connection):
    """Validate every existing event before allowing another append."""
    rows = connection.execute(text("""
        SELECT CHAIN_INDEX AS chain_index,
               ID AS id,
               USER_ID AS user_id,
               DOCUMENT_ID AS document_id,
               ACTION AS action,
               OUTCOME AS outcome,
               DETAILS AS details,
               CREATED_AT AS created_at,
               PREVIOUS_HASH AS previous_hash,
               EVENT_HASH AS event_hash
        FROM TV_AUDIT_LOGS
        ORDER BY CHAIN_INDEX
    """)).mappings().all()

    previous_hash = None

    for expected_index, row in enumerate(rows, start=1):
        if row["chain_index"] != expected_index:
            raise AuditChainIntegrityError(
                f"Expected chain index {expected_index}; "
                f"found {row['chain_index']}."
            )

        if row["previous_hash"] != previous_hash:
            raise AuditChainIntegrityError(
                f"Previous-hash mismatch at chain index {expected_index}."
            )

        calculated_hash = _canonical_hash(row, previous_hash)

        if row["event_hash"] != calculated_hash:
            raise AuditChainIntegrityError(
                f"Event-hash mismatch at chain index {expected_index}."
            )

        previous_hash = row["event_hash"]

    return len(rows), previous_hash


def append_audit_event(
    *,
    action,
    outcome,
    user_id=None,
    document_id=None,
    details=None,
):
    """
    Append one event atomically.

    Call inside a Flask application context. The exclusive table lock
    serializes writers using this service, preventing duplicate indexes.
    """
    if not isinstance(action, str) or not action.strip():
        raise ValueError("action must be a non-empty string.")

    if len(action) > 80:
        raise ValueError("action must be at most 80 characters.")

    if not isinstance(outcome, str) or not outcome.strip():
        raise ValueError("outcome must be a non-empty string.")

    if len(outcome) > 20:
        raise ValueError("outcome must be at most 20 characters.")

    if details is not None and len(details) > 1000:
        raise ValueError("details must be at most 1000 characters.")

    event_id = str(uuid4())
    created_at = _now()

    with db.engine.begin() as connection:
        # Oracle holds this lock until the transaction commits or rolls back.
        # On SQLite local fallback, LOCK TABLE is not supported syntax, so we fall back to SQLite's database-level transaction lock.
        try:
            connection.execute(
                text("LOCK TABLE TV_AUDIT_LOGS IN EXCLUSIVE MODE")
            )
        except OperationalError as exc:
            if "LOCK" not in str(exc).upper():
                raise

        count, previous_hash = _load_and_validate_chain(connection)
        chain_index = count + 1

        row = {
            "id": event_id,
            "user_id": str(user_id) if user_id is not None else None,
            "document_id": (
                str(document_id) if document_id is not None else None
            ),
            "action": action.strip(),
            "outcome": outcome.strip(),
            "details": details,
            "created_at": created_at,
        }

        event_hash = _canonical_hash(row, previous_hash)

        connection.execute(
            text("""
                INSERT INTO TV_AUDIT_LOGS (
                    ID, USER_ID, DOCUMENT_ID, ACTION, OUTCOME,
                    DETAILS, CREATED_AT, PREVIOUS_HASH, EVENT_HASH,
                    CHAIN_INDEX
                ) VALUES (
                    :id, :user_id, :document_id, :action, :outcome,
                    :details, :created_at, :previous_hash, :event_hash,
                    :chain_index
                )
            """),
            {
                **row,
                "previous_hash": previous_hash,
                "event_hash": event_hash,
                "chain_index": chain_index,
            },
        )

    return {
        "id": event_id,
        "chain_index": chain_index,
        "event_hash": event_hash,
    }
