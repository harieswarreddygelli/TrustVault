from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db
from app.models import User

app = create_app()


def seed_default_accounts():
    accounts = [
        ("admin_user", "admin@trustvault.local", "AdminPass123!@#", "admin"),
        ("alice", "alice@trustvault.local", "TestPassword123!", "owner"),
        ("bob", "bob@trustvault.local", "TestPassword456!", "viewer"),
    ]

    for username, email, password, role in accounts:
        existing = User.query.filter_by(username=username).first()
        if existing is None:
            user = User(
                username=username,
                email=email,
                role=role,
                is_active=True,
            )
            user.set_password(password)
            db.session.add(user)

    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_default_accounts()
        print("TrustVault database tables and seed accounts (admin_user, alice, bob) initialized.")
        print("Tables:", ", ".join(sorted(db.metadata.tables.keys())))
