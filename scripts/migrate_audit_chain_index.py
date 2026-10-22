
from pathlib import Path
import sys

from sqlalchemy import inspect, text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db


app = create_app()

with app.app_context():
    inspector = inspect(db.engine)

    columns = {
        column["name"].upper()
        for column in inspector.get_columns("TV_AUDIT_LOGS")
    }

    if "CHAIN_INDEX" in columns:
        raise RuntimeError(
            "CHAIN_INDEX already exists. "
            "Do not rerun this migration."
        )

    # Oracle DDL commits implicitly; make a backup before proceeding.
    with db.engine.begin() as connection:
        connection.execute(text("""
            ALTER TABLE TV_AUDIT_LOGS
            ADD (CHAIN_INDEX NUMBER(10))
        """))

    try:
        with db.engine.begin() as connection:
            rows = connection.execute(text("""
                SELECT ID
                FROM TV_AUDIT_LOGS
                ORDER BY CREATED_AT, ID
            """)).mappings().all()

            for index, row in enumerate(rows, start=1):
                connection.execute(
                    text("""
                        UPDATE TV_AUDIT_LOGS
                        SET CHAIN_INDEX = :chain_index
                        WHERE ID = :event_id
                    """),
                    {
                        "chain_index": index,
                        "event_id": row["id"],
                    },
                )

        with db.engine.begin() as connection:
            connection.execute(text("""
                ALTER TABLE TV_AUDIT_LOGS
                MODIFY (CHAIN_INDEX NOT NULL)
            """))

            connection.execute(text("""
                ALTER TABLE TV_AUDIT_LOGS
                ADD CONSTRAINT UQ_TV_AUDIT_CHAIN_IDX
                UNIQUE (CHAIN_INDEX)
            """))

    except Exception:
        print(
            "Migration did not finish. Oracle may have retained "
            "the added column because DDL commits implicitly. "
            "Inspect the table before attempting recovery."
        )
        raise

    print(f"CHAIN_INDEX assigned to {len(rows)} audit records.")
    print("Existing event hashes were not modified.")
