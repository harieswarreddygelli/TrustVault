from hashlib import sha256
import json
from pathlib import Path
import sys

from sqlalchemy import text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db


def calculate_hash(row, previous_hash):
    """Match the canonical hashing format used by the audit service."""
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

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(connection):
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

    errors = []
    expected_previous_hash = None

    for expected_index, row in enumerate(rows, start=1):
        if row["chain_index"] != expected_index:
            errors.append(
                f"Sequence gap: expected index {expected_index}, "
                f"found {row['chain_index']} (event {row['id']})"
            )

        if row["previous_hash"] != expected_previous_hash:
            errors.append(
                f"Previous-hash mismatch at index "
                f"{row['chain_index']} (event {row['id']})"
            )

        calculated = calculate_hash(row, expected_previous_hash)

        if row["event_hash"] != calculated:
            errors.append(
                f"Event hash mismatch at index "
                f"{row['chain_index']} (event {row['id']})"
            )

        expected_previous_hash = row["event_hash"]

    return len(rows), errors


def main():
    app = create_app()

    with app.app_context():
        with db.engine.connect() as connection:
            total, errors = verify_chain(connection)

    print(f"Audit events checked: {total}")

    if errors:
        print(f"INTEGRITY CHECK FAILED: {len(errors)} issue(s)")
        for error in errors:
            print(f" - {error}")
        raise SystemExit(1)

    print("INTEGRITY CHECK PASSED")
    print("Hashes, links, and sequence indexes are consistent.")


if __name__ == "__main__":
    main()
