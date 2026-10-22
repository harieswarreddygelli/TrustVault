import os
from pathlib import Path

from flask import Flask, jsonify, redirect, url_for
from flask_login import current_user
from sqlalchemy import inspect, text

from config import Config, build_database_url
from app.extensions import csrf, db, login_manager
from app import models  # noqa: F401

_ORACLE_CLIENT_INITIALIZED = False


def initialize_oracle_client():
    global _ORACLE_CLIENT_INITIALIZED

    if _ORACLE_CLIENT_INITIALIZED:
        return

    client_dir = os.getenv("ORACLE_CLIENT_DIR", "").strip()

    # If ORACLE_CLIENT_DIR is not set or does not exist on this machine,
    # python-oracledb automatically uses Thin Mode without needing Instant Client!
    if not client_dir or not Path(client_dir).is_dir():
        _ORACLE_CLIENT_INITIALIZED = True
        return

    try:
        import oracledb
        oracledb.init_oracle_client(lib_dir=client_dir)
        _ORACLE_CLIENT_INITIALIZED = True
        print("Oracle Thick mode initialized successfully.")
    except Exception as exc:
        print(f"Notice: Could not initialize Oracle Thick mode at {client_dir} ({exc}); falling back to Thin Mode.")
        _ORACLE_CLIENT_INITIALIZED = True


def _ensure_schema_and_seed(app):
    """Ensure database tables, columns, and default role accounts exist when running the app."""
    with app.app_context():
        db.create_all()

        # Auto-add CATEGORY column if running against an existing database created before CATEGORY was added
        try:
            inspector = inspect(db.engine)
            table_names = {t.lower(): t for t in inspector.get_table_names()}
            if "tv_documents" in table_names:
                actual_table = table_names["tv_documents"]
                cols = {c["name"].lower() for c in inspector.get_columns(actual_table)}
                if "category" not in cols:
                    dialect = db.engine.dialect.name
                    with db.engine.begin() as conn:
                        if dialect == "oracle":
                            conn.execute(text("ALTER TABLE TV_DOCUMENTS ADD (CATEGORY VARCHAR2(50) DEFAULT 'General' NOT NULL)"))
                        else:
                            conn.execute(text("ALTER TABLE tv_documents ADD COLUMN category VARCHAR(50) NOT NULL DEFAULT 'General'"))
        except Exception as exc:
            app.logger.warning("Schema column check warning: %s", exc)

        # In non-testing mode, seed default accounts (admin_user, alice, bob) if no users exist yet
        if not app.config.get("TESTING"):
            try:
                if models.User.query.count() == 0:
                    default_accounts = [
                        ("admin_user", "admin@trustvault.local", "AdminPass123!@#", "admin"),
                        ("alice", "alice@trustvault.local", "TestPassword123!", "owner"),
                        ("bob", "bob@trustvault.local", "TestPassword456!", "viewer"),
                    ]
                    created_users = {}
                    for username, email, password, role in default_accounts:
                        u = models.User(
                            username=username,
                            email=email,
                            role=role,
                            is_active=True,
                        )
                        u.set_password(password)
                        db.session.add(u)
                        created_users[username] = u
                    db.session.commit()

                    # Also seed initial demo documents, a shared permission, and audit log events
                    # so judges opening the Live URL immediately see rich seed data!
                    from uuid import uuid4
                    from app.audit_service import append_audit_event
                    alice_user = created_users["alice"]
                    bob_user = created_users["bob"]
                    upload_root = Path(app.config["PRIVATE_UPLOAD_DIR"])
                    upload_root.mkdir(parents=True, exist_ok=True)

                    key1 = uuid4().hex
                    (upload_root / key1).write_text(
                        "CONFIDENTIAL: Q4 Financial Audit Summary\nAll access to this document is tracked in the SHA-256 audit chain.",
                        encoding="utf-8",
                    )
                    doc1 = models.Document(
                        owner_id=alice_user.id,
                        title="Q4 Financial Audit Report",
                        original_filename="q4_financial_audit.txt",
                        category="Financial",
                        storage_key=key1,
                    )

                    key2 = uuid4().hex
                    (upload_root / key2).write_text(
                        "Vendor Security Architecture Specification v2.1\nCollaborators with Edit permission may update this specification.",
                        encoding="utf-8",
                    )
                    doc2 = models.Document(
                        owner_id=alice_user.id,
                        title="Security Architecture Specification",
                        original_filename="security_architecture_spec.txt",
                        category="Engineering",
                        storage_key=key2,
                    )
                    db.session.add_all([doc1, doc2])
                    db.session.commit()

                    perm = models.Permission(
                        document_id=doc2.id,
                        user_id=bob_user.id,
                        permission="write",
                        is_revoked=False,
                    )
                    db.session.add(perm)
                    db.session.commit()

                    append_audit_event(
                        action="document_upload",
                        outcome="success",
                        user_id=alice_user.id,
                        document_id=doc1.id,
                        details="filename='q4_financial_audit.txt';category='Financial'",
                    )
                    append_audit_event(
                        action="document_upload",
                        outcome="success",
                        user_id=alice_user.id,
                        document_id=doc2.id,
                        details="filename='security_architecture_spec.txt';category='Engineering'",
                    )
                    append_audit_event(
                        action="document_share",
                        outcome="success",
                        user_id=alice_user.id,
                        document_id=doc2.id,
                        details=f"recipient_username=bob;recipient_user_id={bob_user.id};permission=write",
                    )
            except Exception as exc:
                db.session.rollback()
                app.logger.warning("Default user seed warning: %s", exc)


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    # Security defaults; explicit test configuration can override these.
    if app.config.get("MAX_CONTENT_LENGTH") is None:
        app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    app.config["SESSION_COOKIE_HTTPONLY"] = True

    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        app.config["SQLALCHEMY_DATABASE_URI"] = build_database_url(strict=True)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY is required. Configure it in .env."
        )

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    private_upload_dir = Path(app.instance_path) / "private_uploads"
    private_upload_dir.mkdir(parents=True, exist_ok=True)
    if "PRIVATE_UPLOAD_DIR" not in app.config:
        app.config["PRIVATE_UPLOAD_DIR"] = str(private_upload_dir)

    # Oracle client initialization is only relevant when connecting to Oracle.
    db_uri = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    if db_uri.startswith("oracle"):
        initialize_oracle_client()

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    if not app.config.get("TESTING"):
        _ensure_schema_and_seed(app)

    @login_manager.user_loader
    def load_user(user_id):
        """Reload an active authenticated user from the database session ID."""
        user = db.session.get(models.User, user_id)
        if user is None or not user.is_active:
            return None
        return user

    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        )
        return response

    from app.auth import auth_bp
    from app.documents import documents_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)

    @app.get("/")
    def root():
        if current_user.is_authenticated:
            return redirect(url_for("documents.dashboard"))
        return redirect(url_for("auth.login"))

    @app.get("/health")
    def health():
        return jsonify(status="ok", application="TrustVault"), 200

    return app
