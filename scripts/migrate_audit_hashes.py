
from hashlib import sha256
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import inspect, text
from app import create_app
from app.extensions import db


def canonical_hash(row, previous_hash):
    payload = {
        "id": row["id"],
        "user_id": row["user_id"],
        "document_id": row["document_id"],
        "action": row["action"],
        "outcome": row["outcome"],
        "details": row["details"],
        "created_at": (
            row["created_at"].isoformat()
            if row["created_at"] is not None
            else None
        ),
        "previous_hash": previous_hash,
    }

    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(canonical_json.encode("utf-8")).hexdigest()


app = create_app()

with app.app_context():
    inspector = inspect(db.engine)
    columns = {
        column["name"].upper()
        for column in inspector.get_columns("TV_AUDIT_LOGS")
    }

    # DDL in Oracle commits implicitly. Each addition is checked so
    # the script can be rerun after an interrupted migration.
    with db.engine.begin() as connection:
        if "PREVIOUS_HASH" not in columns:
            connection.execute(text(
                "ALTER TABLE TV_AUDIT_LOGS "
                "ADD (PREVIOUS_HASH VARCHAR2(64))"
            ))

        if "EVENT_HASH" not in columns:
            connection.execute(text(
                "ALTER TABLE TV_AUDIT_LOGS "
                "ADD (EVENT_HASH VARCHAR2(64))"
            ))

    with db.engine.begin() as connection:
        rows = connection.execute(text("""
            SELECT ID, USER_ID, DOCUMENT_ID, ACTION,
                   OUTCOME, DETAILS, CREATED_AT
            FROM TV_AUDIT_LOGS
            ORDER BY CREATED_AT, ID
        """)).mappings().all()

        previous_hash = None

        for row in rows:
            event_hash = canonical_hash(row, previous_hash)

            connection.execute(
                text("""
                    UPDATE TV_AUDIT_LOGS
                    SET PREVIOUS_HASH = :previous_hash,
                        EVENT_HASH = :event_hash
                    WHERE ID = :event_id
                """),
                {
                    "previous_hash": previous_hash,
                    "event_hash": event_hash,
                    "event_id": row["id"],
                },
            )

            previous_hash = event_hash

    # Apply constraints only after every existing record is hashed.
    constraint_names = {
        constraint["name"]
        for constraint in inspect(db.engine).get_unique_constraints(
            "TV_AUDIT_LOGS"
        )
    }

    with db.engine.begin() as connection:
        if "UQ_TV_AUDIT_EVENT_HASH" not in constraint_names:
            connection.execute(text("""
                ALTER TABLE TV_AUDIT_LOGS
                ADD CONSTRAINT UQ_TV_AUDIT_EVENT_HASH
                UNIQUE (EVENT_HASH)
            """))

        connection.execute(text("""
            ALTER TABLE TV_AUDIT_LOGS
            MODIFY (EVENT_HASH NOT NULL)
        """))

    print(f"Audit hash migration completed. Records processed: {len(rows)}")
    print("Ordering: CREATED_AT, ID")
    print("Hash algorithm: SHA-256")
    print("Existing audit records were retained.")
