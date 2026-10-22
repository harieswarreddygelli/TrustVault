
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.audit_service import append_audit_event


app = create_app()

with app.app_context():
    result = append_audit_event(
        action="AUDIT_WRITER_TEST",
        outcome="SUCCESS",
        details="Manual audit writer verification.",
    )

    print("Audit event appended successfully.")
    print(f"Chain index: {result['chain_index']}")
    print(f"Event ID: {result['id']}")
    print(f"Event hash: {result['event_hash']}")
