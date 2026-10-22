# TrustVault — Secure Document Sharing with a Cryptographic Audit Trail

TrustVault is a security-first document platform built with **Flask**, **SQLAlchemy**, and **Oracle Database XE** (with SQLite in-memory support for isolated automated testing). It is engineered around three non-negotiable guarantees:
1. **The server decides, every time:** A document is reachable only by its owner or someone with an active grant. Unauthorized requests across any route return `404 Not Found` and record a `denied` audit event.
2. **Cryptographic proof of access:** Every upload, download, edit, share, revocation, deletion, history view, and authentication event is recorded in an append-only, tamper-evident **SHA-256 hash chain** (`TV_AUDIT_LOGS`) with sequential `CHAIN_INDEX` verification and fail-closed transaction semantics.
3. **Immediate revocation:** Permissions are never cached in client sessions or pre-signed URLs. Revoking a grant or soft-deleting a document blocks access on the very next request.

---

## 1. Roles, Permission Model & Seed Credentials

### Role Definitions (`TV_USERS.ROLE`)
| Role | Capabilities |
| :--- | :--- |
| **`admin` (Administrator)** | Can view system-wide document activity, refused access attempts, and permission changes across all users and documents (`/documents/activity`, `/admin/audit`), and verify audit chain integrity. Does **not** automatically get read/write access to private document contents unless explicitly granted by the owner. |
| **`owner` (Document Owner)** | Can upload documents, organize by category, search/filter, edit, download, soft-delete owned documents, view per-document audit history (`/documents/<id>/history`), and grant/revoke `read` or `write` access to named users. |
| **`viewer` (Viewer / Collaborator)** | Cannot upload new documents by default (`viewer` role), or can act as a recipient on shared documents. Can only view/download documents explicitly shared with them (`read` grant) or edit plain-text documents when explicitly granted `write` permission. |

### Per-Document Permission Model (`TV_DOC_PERMISSIONS`)
- Permissions (`read` or `write`) are granted per document to named active users (`UNIQUE(document_id, user_id)`).
- **`read` permission:** Allows viewing metadata in `/documents/` and `/documents/shared` and downloading via `GET /documents/<id>/download`.
- **`write` permission:** Includes `read` plus in-browser UTF-8 plain-text editing via `GET/POST /documents/<id>/edit`. It does **not** allow re-sharing, revoking, deleting, or viewing `/history` (strictly owner-only).
- **Revocation & Soft-Deletion:** Revoking access sets `is_revoked = True` and `revoked_at = UTC_NOW`. Deleting a document sets `is_deleted = True` and removes the physical file from `instance/private_uploads/` while preserving the `TV_DOCUMENTS`, `TV_DOC_PERMISSIONS`, and `TV_AUDIT_LOGS` rows so forensic history is never broken.

### Demo / Seed Accounts
Run `python scripts/seed_demo.py` (or `python scripts/init_db.py`) to initialize the schema and seed accounts:

| Role | Username | Email | Password |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin_user` | `admin@trustvault.local` | `AdminPass123!@#` |
| **Document Owner** | `alice` | `alice@trustvault.local` | `TestPassword123!` |
| **Viewer / Collaborator** | `bob` | `bob@trustvault.local` | `TestPassword456!` |

---

## 2. API & Route Authorization Matrix

Every state-changing `POST` endpoint requires a valid `Flask-WTF` CSRF token. Unauthorized document access returns `404 Not Found` and logs a `denied` audit event.

| Method & Endpoint | Allowed Caller(s) | Audited Action (`TV_AUDIT_LOGS`) | Description |
| :--- | :--- | :--- | :--- |
| `GET /health` | Public | — | Health check endpoint (`{"status": "ok"}`). |
| `GET, POST /register` | Anonymous | `register` (`success`) | Register a new account (12+ char password policy). |
| `GET, POST /login` | Anonymous | `login` (`success` / `failure`) | Authenticate user; fails closed (`503`) if audit write fails. |
| `POST /logout` | Authenticated (`admin`, `owner`, `viewer`) | `logout` (`success`) | Terminate session and clear cookie. |
| `GET, POST /profile` | Authenticated (`admin`, `owner`, `viewer`) | `profile_update` (`requested` / `success`) | View profile or update username and email address. |
| `GET, POST /change-password` | Authenticated (`admin`, `owner`, `viewer`) | `password_change` (`requested` / `success`) | Verify current password and set a new 12+ char password. |
| `GET /documents/dashboard` | Authenticated (`admin`, `owner`, `viewer`) | — | Workspace overview dashboard. |
| `GET /documents/` | Authenticated (`admin`, `owner`, `viewer`) | — | List owned + actively shared documents; search by **name (`q`)**, **owner (`owner`)**, **category (`category` / `file_type`)**, and **date (`uploaded_after`, `uploaded_before`)**. |
| `GET /documents/shared` | Authenticated (`admin`, `owner`, `viewer`) | — | List documents actively shared with the current user. |
| `GET, POST /documents/upload` | Authenticated (`owner`, `admin`) | `document_upload` (`success`) | Upload file(s) (max 16 MiB) to `instance/private_uploads/<uuid4>`. |
| `GET /documents/<id>/download` | Document `owner` OR active `read`/`write` grantee | `document_download` (`success` / `denied` / `failure`) | Stream file attachment from private storage after live DB check. |
| `GET, POST /documents/<id>/edit` | Document `owner` OR active `write` grantee | `document_edit` (`success` / `denied`) | Edit document title, category, UTF-8 text (max 1 MiB), or upload a replacement file version (max 16 MiB) for any file format (PDF, DOCX, images, text). |
| `POST /documents/<id>/share` | Document `owner` **only** | `document_share` (`success`) | Grant or update `read` or `write` (`edit`) access for one or multiple active users. |
| `POST /documents/bulk-share` | Document `owner` **only** | `document_share` (`success`) | Share multiple selected owned documents with one or multiple users at once. |
| `POST /documents/bulk-delete` | Document `owner` **only** | `document_delete` (`requested` / `success` / `failure`) | Soft-delete multiple selected owned documents and unlink physical files. |
| `POST /documents/<id>/revoke/<uid>` | Document `owner` **only** | `document_revoke` (`success`) | Immediately revoke a user's access while preserving permission history. |
| `POST /documents/<id>/delete` | Document `owner` **only** | `document_delete` (`requested` / `success` / `failure`) | Soft-delete document (`is_deleted=True`) and unlink physical file. |
| `GET /documents/<id>/history` | Document `owner` OR `admin` | `document_history` (`denied` on non-owner) | View full chronological audit trail and SHA-256 hashes for a document. |
| `GET /documents/activity` | Authenticated (`admin` sees all global activity & permission changes; `owner`/`viewer` sees own activity) | — | Administrative & user security activity log view. |

---

## 3. Architecture & Design Write-Up

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

## 4. Clean Clone Setup & Deployment Instructions

### Prerequisites
- Python 3.10+
- Oracle Database XE (21c/18c) — *Note: `python-oracledb` runs in Thin Mode by default, or Thick Mode if `ORACLE_CLIENT_DIR` is set in `.env`. Automated tests run out-of-the-box on SQLite in-memory without requiring Oracle.*

### Step-by-Step Setup
```bash
# 1. Clone repository and enter directory
git clone https://github.com/harieswarreddygelli/TrustVault.git
cd TrustVault-main

# 2. Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env to set SECRET_KEY and your Oracle XE connection details

# 5. Initialize schema and seed demo accounts (admin, owner, viewer)
python scripts/init_db.py

# 6. Run the server
python run.py
```

### Running Automated Tests & Audit Chain Verification
```bash
# Run the full automated test suite (SQLite in-memory, no Oracle required)
python -m pytest -q 

# Verify the live Oracle SHA-256 audit chain integrity
python scripts/verify_audit_chain.py
```
