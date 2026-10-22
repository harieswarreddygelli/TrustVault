# TrustVault — Secure Document Sharing with a Cryptographic Audit Trail

**Live Deployed URL:** `https://trustvault-prod.onrender.com`  
**Demo Video:** `https://www.youtube.com/watch?v=trustvault-demo-placeholder`

TrustVault is an enterprise-grade, security-first document management and auditing platform built with **Flask**, **SQLAlchemy**, and **Oracle Database XE** (with zero-config SQLite local development support and isolated in-memory testing). It is engineered around three non-negotiable guarantees:
1. **Server-Side Authorization Enforcement:** A document is reachable only by its owner or someone with an active, unrevoked grant. Unauthorized requests across any route return `404 Not Found` and log a `denied` audit event.
2. **Cryptographic Proof of Access:** Every upload, download, edit, share, revocation, deletion, history view, and authentication event is immutably recorded in an append-only **SHA-256 hash chain** (`TV_AUDIT_LOGS`) with sequential `CHAIN_INDEX` validation and fail-closed transaction semantics.
3. **Immediate Revocation:** Permissions are never cached in client cookies or pre-signed URLs. Revoking a grant or soft-deleting a document blocks access on the very next HTTP request.

---

## 1. Project Directory Structure

```text
TrustVault-main/
├── .env.example                # Template for environment variables
├── .gitignore                  # Excludes .env, .venv, instance/, and caches
├── Procfile                    # Production Gunicorn process configuration
├── render.yaml                 # Render cloud deployment blueprint
├── requirements.txt            # Python dependencies (Flask, SQLAlchemy, oracledb, pytest)
├── run.py                      # Production WSGI / development entry point
├── config.py                   # Environment configuration & SQLite/Oracle fallback
├── README.md                   # Project overview, architecture, project structure & setup
├── THREATS.md                  # Threat model (STRIDE), mitigations & accepted residual risks
├── PROMPTS.md                  # 7 dated AI usage logs, prompts, flaws caught & code fixes
├── app/                        # Main Flask application package
│   ├── __init__.py             # App factory, security headers & seed execution
│   ├── extensions.py           # SQLAlchemy, LoginManager & CSRFProtect instances
│   ├── models.py               # Database models (User, Document, Permission, AuditLog)
│   ├── auth.py                 # Authentication routes (login, register, logout, profile)
│   ├── documents.py            # Document routes (library, upload, download, edit, share, delete, history, bulk)
│   ├── static/                 # Frontend assets
│   │   ├── css/
│   │   │   └── trustvault.css  # Enterprise Frosted Glass UI theme (Light & Dark mode)
│   │   └── js/
│   │       └── theme.js        # Instant theme switcher & client helpers
│   └── templates/              # Server-rendered Jinja2 templates
│       ├── base.html           # Unified site layout & navigation
│       ├── auth/
│       │   ├── login.html
│       │   ├── register.html
│       │   ├── profile.html
│       │   └── change_password.html
│       └── documents/
│           ├── dashboard.html
│           ├── index.html      # Document library with search, filter & bulk actions
│           ├── upload.html     # Multi-file upload with category selector & size validation
│           ├── shared.html     # Shared documents collaboration view
│           ├── edit.html       # In-browser text editor & file version replacement
│           ├── history.html    # Per-document SHA-256 audit trail & hash chain view
│           └── activity.html   # System-wide administrative security audit overview
├── scripts/                    # Database & audit verification utilities
│   ├── init_db.py              # Schema creator & initial role account seeder
│   ├── inspect_schema.py       # DB schema validator
│   ├── migrate_audit_chain_index.py
│   ├── migrate_audit_hashes.py
│   ├── test_audit_writer.py
│   └── verify_audit_chain.py   # CLI cryptographic SHA-256 audit chain integrity checker
└── tests/                      # Automated test suite (52 comprehensive tests)
    ├── conftest.py             # Test fixtures & isolated SQLite DB context
    ├── test_auth.py            # Authentication, profile & active session tests
    ├── test_auth_audit_failures.py # Fail-closed audit outage tests
    ├── test_audit_verifier.py  # Chain tampering detection tests
    ├── test_csrf_protection.py # Global CSRF enforcement tests
    ├── test_sharing.py         # Multi-user grant and revocation tests
    └── test_documents.py       # Negative IDOR, upload, search, and bulk tests
```

---

## 2. Roles, Permission Model & Seed Credentials

### Role Definitions (`TV_USERS.ROLE`)
| Role | Capabilities |
| :--- | :--- |
| **`admin` (Administrator)** | Can view system-wide document activity, refused access attempts, and permission changes across all users and documents (`/documents/activity`), and verify audit chain integrity. Does **not** automatically get read/write access to private document contents unless explicitly granted by the owner. |
| **`owner` (Document Owner)** | Can upload documents, organize by category, search/filter, edit, download, soft-delete owned documents, view per-document audit history (`/documents/<id>/history`), and grant/revoke `read` or `write` access to named users (individually or in bulk). |
| **`viewer` (Viewer / Collaborator)** | Cannot upload new documents (`viewer` role is blocked on uploads). Can view/download documents explicitly shared with them (`read` grant) or edit plain-text documents when explicitly granted `write` permission. |

### Demo / Seed Accounts
TrustVault automatically seeds three default accounts on first startup:

| Role | Username | Email | Password |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin_user` | `admin@trustvault.local` | `AdminPass123!@#` |
| **Document Owner** | `alice` | `alice@trustvault.local` | `TestPassword123!` |
| **Viewer / Collaborator** | `bob` | `bob@trustvault.local` | `TestPassword456!` |

---

## 3. API & Route Authorization Matrix

All state-changing `POST` requests require a valid `Flask-WTF` CSRF token. Unauthorized document access returns `404 Not Found` to prevent IDOR enumeration and records a `denied` audit event.

| Method & Endpoint | Allowed Caller(s) | Audited Action (`TV_AUDIT_LOGS`) | Description |
| :--- | :--- | :--- | :--- |
| `GET /health` | Public | — | Health check endpoint (`{"status": "ok"}`). |
| `GET, POST /register` | Anonymous | `register` (`success`) | Register new account (`owner` or `viewer`). |
| `GET, POST /login` | Anonymous | `login` (`success` / `failure`) | Authenticate user; fails closed (`503`) if audit write fails. |
| `POST /logout` | Authenticated | `logout` (`success`) | Terminate session and clear cookie. |
| `GET, POST /profile` | Authenticated | `profile_update` (`requested` / `success`) | Update username and email address. |
| `GET, POST /change-password` | Authenticated | `password_change` (`requested` / `success`) | Change password with 12+ char requirement. |
| `GET /documents/dashboard` | Authenticated | — | Secure workspace overview dashboard. |
| `GET /documents/` | Authenticated | — | List authorized documents; search by **name (`q`)**, **owner (`owner`)**, **category (`category`)**, and **date (`date`, `uploaded_after`, `uploaded_before`)**. |
| `GET /documents/shared` | Authenticated | — | List documents actively shared with the current user. |
| `GET, POST /documents/upload` | Authenticated (`owner`, `admin`) | `document_upload` (`success` / `denied`) | Upload file(s) (max 16 MiB) with magic-byte security validation. |
| `GET /documents/<id>/download` | Document `owner` OR active `read`/`write` grantee | `document_download` (`success` / `denied` / `failure`) | Stream file attachment from private storage after live DB check. |
| `GET, POST /documents/<id>/edit` | Document `owner` OR active `write` grantee | `document_edit` (`success` / `denied`) | Edit title, category, plain-text content, or upload replacement file. |
| `POST /documents/<id>/share` | Document `owner` **only** | `document_share` (`success`) | Grant or update `read` or `write` access to a user. |
| `POST /documents/bulk-share` | Document `owner` **only** | `document_share` (`success`) | Share multiple selected documents with multiple users at once. |
| `POST /documents/<id>/revoke/<uid>` | Document `owner` **only** | `document_revoke` (`success`) | Immediately revoke a user's access. |
| `POST /documents/<id>/delete` | Document `owner` **only** | `document_delete` (`requested` / `success` / `failure`) | Soft-delete document and remove physical file. |
| `POST /documents/bulk-delete` | Document `owner` **only** | `document_delete` (`requested` / `success` / `failure`) | Soft-delete multiple selected documents at once. |
| `GET /documents/<id>/history` | Document `owner` OR `admin` | `document_history` (`denied` on non-owner) | View full chronological audit trail and SHA-256 hashes. |
| `GET /documents/activity` | Authenticated (`admin` sees global metrics & audit trail; others see own) | — | Security audit activity view. |

---

## 4. Architecture & Design Write-Up

### How Files Are Stored & Protected
Uploaded files are never placed in `app/static/`. They are written to `instance/private_uploads/` under a random 32-character hex UUID (`uuid4().hex`) opened in exclusive binary creation mode (`xb`). Before any file read or write, `_document_path()` resolves the canonical path and verifies `path.resolve().parent == root`, neutralizing path traversal even if database metadata were manipulated.

### How the Audit Trail Is Protected
`TV_AUDIT_LOGS` is managed exclusively through `app/audit_service.py`:
1. **Serialization:** `LOCK TABLE TV_AUDIT_LOGS IN EXCLUSIVE MODE` prevents concurrent race conditions on `CHAIN_INDEX`.
2. **Pre-Write Validation:** `_load_and_validate_chain()` verifies that every existing row has a contiguous `CHAIN_INDEX` ($1 \dots N$), a matching `PREVIOUS_HASH`, and a valid SHA-256 `EVENT_HASH` over its canonical JSON payload before allowing event $N+1$ to be inserted.
3. **Fail-Closed Operations:** If `append_audit_event()` fails during login, registration, upload, edit, share, or revoke, the operation rolls back or compensates automatically so no unaudited state change survives.

### What We Chose NOT to Build (and Why)
- **No Hierarchical Folders or Group Inheritance:** Complex folder inheritance trees introduce subtle permission-leak bugs when files are moved across folders. A flat per-document grant model (`TV_DOC_PERMISSIONS`) with category/owner/date filtering is simpler to reason about and mathematically verifiable.
- **No Public/Anonymous Share Links or Pre-Signed S3 URLs:** Pre-signed URLs remain valid until their expiration timestamp even after an owner clicks "Revoke", and anonymous links can be forwarded to unauthorized people. Requiring authenticated accounts and streaming every download through the Flask server guarantees that revocation is instantaneous.
- **No AI Inside the Permission Loop:** All access grants require explicit human confirmation by the document owner.

---

## 5. Clean Clone Setup & Deployment Instructions

### Prerequisites
- Python 3.10+
- Oracle Database XE (optional — app defaults to local SQLite automatically if Oracle credentials are not supplied).

### Step-by-Step Setup
```bash
# 1. Clone repository and enter directory
git clone https://github.com/harieswarreddygelli/TrustVault.git
cd TrustVault

# 2. Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize schema and seed demo accounts (admin, owner, viewer)
python scripts/init_db.py

# 5. Run the server
python run.py
```

### Running Automated Tests & Audit Chain Verification
```bash
# Run the full automated test suite (52 tests)
python -m pytest -v

# Verify the live SHA-256 audit chain integrity
python scripts/verify_audit_chain.py
```
