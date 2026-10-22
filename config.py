import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

PLACEHOLDER_VALUES = {
    "",
    "your_oracle_username",
    "your_oracle_password",
    "replace-with-a-random-secret",
}


def build_database_url(strict=False):
    """
    Build a SQLAlchemy database URL:
    1. If DATABASE_URL is explicitly set in the environment, use it.
    2. If real Oracle XE credentials (DB_USER, DB_PASSWORD) are set, build oracle+oracledb URL.
    3. Otherwise, default to a local SQLite database in instance/trustvault.db so the app
       runs out-of-the-box without requiring an active Oracle server.
    """
    explicit_url = os.getenv("DATABASE_URL", "").strip()
    if explicit_url:
        return explicit_url

    user = os.getenv("DB_USER", "").strip()
    password = os.getenv("DB_PASSWORD", "").strip()
    host = os.getenv("DB_HOST", "localhost").strip() or "localhost"
    port = os.getenv("DB_PORT", "1521").strip() or "1521"
    service = os.getenv("DB_SERVICE", "XE").strip() or "XE"

    if user and password and user not in PLACEHOLDER_VALUES and password not in PLACEHOLDER_VALUES:
        from sqlalchemy.engine import URL

        return URL.create(
            "oracle+oracledb",
            username=user,
            password=password,
            host=host,
            port=int(port),
            query={"service_name": service},
        )

    # Default local SQLite database inside instance/trustvault.db
    instance_dir = BASE_DIR / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    sqlite_path = instance_dir / "trustvault.db"
    return f"sqlite:///{sqlite_path.as_posix()}"


class Config:
    _raw_secret = os.getenv("SECRET_KEY", "").strip()
    SECRET_KEY = (
        _raw_secret
        if _raw_secret and _raw_secret not in PLACEHOLDER_VALUES
        else "trustvault-dev-fallback-secret-key-please-change-in-prod"
    )

    SQLALCHEMY_DATABASE_URI = build_database_url(strict=False)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MiB

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "false").strip().lower()
        in {"1", "true", "yes"}
    )

    # Do not enable debug mode in production.
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
