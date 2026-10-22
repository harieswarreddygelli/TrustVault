# PROMPTS.md — AI Usage & Verification Log

This file documents how AI tools were directed during the development of **TrustVault**, the reusable context/constraints applied across sessions, specific instances where the AI produced insecure or flawed code, and how those flaws were caught and corrected.

---

## 1. Reusable System Prompt / Context Instructions Used Across the Week

To prevent the AI from generating typical "happy-path" CRUD code with security holes, the following constraints were supplied as persistent context across development sessions:

> **Persistent Context & Security Rules for TrustVault:**
> 1. **Server-Side Authority Only:** Never rely on hidden UI buttons or client-side checks. Every route (`/download`, `/edit`, `/share`, `/revoke`, `/delete`, `/history`, `/admin/*`) must query live database state (`TV_DOCUMENTS`, `TV_DOC_PERMISSIONS`, `TV_USERS`) on every request.
> 2. **Zero ID Enumeration:** When an authenticated user requests a document they do not own or lack active permission for, always return `404 Not Found` (not `403 Forbidden`) and record a `denied` audit event.
> 3. **Immediate Revocation:** Never cache document permissions in Flask `session` cookies or issue long-lived pre-signed URLs.
> 4. **Fail-Closed Auditing:** Every state-changing operation or sensitive access must write to `TV_AUDIT_LOGS` via `append_audit_event()`. If the audit write fails, the database transaction and any filesystem write must roll back or compensate so no unaudited state change survives.
> 5. **Private Storage:** Never store uploaded files inside `app/static/`. Store them in `instance/private_uploads/` under a server-generated `uuid4().hex` key opened with exclusive creation (`xb`), and verify `path.resolve().parent == root`.

---

## 2. Dated Log of AI Prompts, Flawed Outputs, and Corrections

### Entry 1 — 2026-10-15: Authorization & Immediate Revocation (`app/documents.py`)
* **What I asked the tool to do:**
  > *"Implement per-document read and write permission checks for `/documents/<id>/download` and `/documents/<id>/edit`, ensuring that revoking access takes effect immediately."*
* **What it produced:**
  The AI generated a login handler that loaded the user's granted `document_id` list into `session['allowed_documents']` upon login and checked `if document_id in session['allowed_documents']:` inside the `/download` route to "save database queries." It also returned `abort(403)` when a user was not in the list, and omitted the `document.is_deleted` check in `_can_read()`.
* **What was wrong with it, specifically:**
  1. **Broken Immediate Revocation:** Storing permissions in Flask's signed session cookie meant that when Alice revoked Bob's access, Bob's existing cookie still contained `document_id` in `session['allowed_documents']`, allowing Bob to keep downloading the file until he logged out!
  2. **Soft-Delete Bypass:** Because `_can_read()` only checked `Permission.query.filter_by(document_id=document.id, user_id=current_user_id, is_revoked=False)` without checking `if document.is_deleted: return False`, a collaborator whose `Permission` row was preserved for historical traceability could still download a soft-deleted document.
  3. **IDOR Enumeration Leak:** Returning `403 Forbidden` for unauthorized documents and `404 Not Found` for nonexistent documents allowed an attacker to enumerate valid document UUIDs.
* **What I did instead:**
  Removed all session permission caching. Wrote `_can_read(document)` and `_can_write(document)` in `app/documents.py` to query `Permission` live from the database on every request, added `if document.is_deleted: return False` as the very first line of both helpers, standardized all unauthorized responses to `abort(404)`, and wrote `test_revoked_user_cannot_download_document` and `test_deleted_document_preserves_permission_but_blocks_recipient` in `tests/test_documents.py`.
  * **Fix Reference:** `app/documents.py` (`_can_read`, `_can_write`, `download`, `edit`) & `tests/test_documents.py`

---

### Entry 2 — 2026-10-16: Tamper-Evident Audit Chain & Oracle Precision (`app/audit_service.py`)
* **What I asked the tool to do:**
  > *"Build a tamper-evident audit trail in `app/audit_service.py` using a SHA-256 hash chain over `TV_AUDIT_LOGS` in Oracle XE, plus a CLI verification script `scripts/verify_audit_chain.py`."*
* **What it produced:**
  The AI generated an `AuditLog` insert function that computed `created_at = datetime.now(timezone.utc)` (with microseconds), hashed `json.dumps(payload)` without sorting keys, and used `SELECT MAX(CHAIN_INDEX) + 1 FROM TV_AUDIT_LOGS` without locking the table.
* **What was wrong with it, specifically:**
  1. **Broken Hash Verification on Oracle `DATE` Columns:** Python's `datetime.now(timezone.utc)` includes microseconds (e.g., `.482910`), which the AI hashed into `EVENT_HASH`. However, Oracle's `DATE` type (mapped by SQLAlchemy `db.DateTime` on Oracle) truncates microseconds to whole seconds on storage! When `verify_audit_chain.py` read the row back from Oracle, `created_at.isoformat()` had `.000000` (no microseconds), causing **every single event hash in the database to fail verification**.
  2. **Race Condition on `CHAIN_INDEX`:** Without a lock, two concurrent requests executing `SELECT MAX(CHAIN_INDEX) + 1` read the same index, causing either a `UNIQUE` constraint crash or a forked hash chain.
  3. **Non-Deterministic JSON Serialization:** Not passing `sort_keys=True, separators=(",", ":"), ensure_ascii=False` to `json.dumps()` risked key-ordering discrepancies across environments.
* **What I did instead:**
  Created `_now()` in `app/audit_service.py` with `.replace(microsecond=0, tzinfo=None)` so the exact timestamp hashed in memory matches what Oracle persists. Added `LOCK TABLE TV_AUDIT_LOGS IN EXCLUSIVE MODE` inside `with db.engine.begin() as connection:`, validated the existing chain via `_load_and_validate_chain(connection)` before appending, and enforced canonical JSON formatting (`sort_keys=True, separators=(",", ":")`).
  * **Fix Reference:** `app/audit_service.py` (`_now`, `_canonical_hash`, `append_audit_event`) & `tests/test_audit_verifier.py`

---

### Entry 3 — 2026-10-17: Fail-Closed Auditing on Login, Upload, and Revocation (`app/auth.py`, `app/documents.py`)
* **What I asked the tool to do:**
  > *"Add audit logging to login, document upload, sharing, and revocation routes."*
* **What it produced:**
  In `app/auth.py`, the AI called `login_user(user)` *before* `append_audit_event(action="login", outcome="success")` and wrapped the audit call in `try: ... except Exception: logger.error("Audit failed")` while still redirecting the user to `/documents/`. Similarly, in `app/documents.py`, it committed the new `Permission` row and flashed `"Shared successfully"` even if `append_audit_event()` raised an exception.
* **What was wrong with it, specifically:**
  **Fail-Open Repudiation Vulnerability:** If the audit table was locked, corrupted (`AuditChainIntegrityError`), or unreachable, an attacker or insider could log in, upload files, or grant themselves access to confidential documents with **zero record in the audit trail**.
* **What I did instead:**
  Implemented a strict **fail-closed** design across all routes:
  1. In `login()`, `append_audit_event(action="login", outcome="success")` is executed *before* `login_user()`. If the audit write raises an exception, `login_user()` is never called and the server returns `503 Service Unavailable`.
  2. In `upload()`, `share()`, `revoke()`, and `edit()`, if `append_audit_event()` fails, the code rolls back the database session, restores the previous `Permission` values (`old_values`) or deletes the newly created `Document` row, and unlinks/restores the physical file on disk.
  3. Added dedicated fail-closed tests (`tests/test_auth_audit_failures.py`, `test_failed_audit_does_not_leave_new_share_permission`, `test_failed_audit_restores_permission_after_revoke`).
  * **Fix Reference:** `app/auth.py`, `app/documents.py`, `tests/test_auth_audit_failures.py`, & `tests/test_sharing.py`

---

### Entry 4 — 2026-10-18: File Upload Storage & Path Traversal Prevention (`app/documents.py`)
* **What I asked the tool to do:**
  > *"Create the file upload and download endpoints in Flask."*
* **What it produced:**
  The AI saved uploaded files to `app/static/uploads/<secure_filename(file.filename)>` and used `os.path.join(upload_dir, document.original_filename)` to serve them.
* **What was wrong with it, specifically:**
  1. **Direct Unauthenticated URL Access:** Anything inside `app/static/` is served directly by Flask's static file route (`/static/uploads/salary.pdf`), completely bypassing `@login_required`, `_can_read()`, and the audit log!
  2. **Filename Collisions & Overwrites:** Saving files by `original_filename` meant two users uploading `contract.pdf` would overwrite each other's files.
  3. **Weak Path Validation:** `os.path.join()` does not canonicalize symlinks or `..` segments if `storage_key` were ever tampered with.
* **What I did instead:**
  Moved file storage outside the web root to `instance/private_uploads/`. Generated a random `uuid4().hex` `storage_key` for every file while storing `original_filename` only as metadata in `TV_DOCUMENTS`. Opened files with `path.open("xb")` (exclusive binary creation) to make overwrites impossible, and implemented `_document_path()` using `Path.resolve()` and `if path.parent != root: abort(404)`.
  * **Fix Reference:** `app/__init__.py`, `app/documents.py` (`_document_path`, `upload`, `download`)

---

### Entry 5 — 2026-10-19: Pytest Application Context & Session Bleed (`tests/conftest.py`, `app/__init__.py`)
* **What I asked the tool to do:**
  > *"Write pytest fixtures in `tests/conftest.py` to test multi-user document sharing and revocation between Alice and Bob using SQLite in-memory."*
* **What it produced:**
  The AI placed `yield {"app": application, ...}` *inside* the `with application.app_context():` block in `conftest.py`, and in `app/__init__.py` called `initialize_oracle_client()` unconditionally before checking if the test suite was using `sqlite://`.
* **What was wrong with it, specifically:**
  1. **Cross-Client Session Bleed in Flask-Login:** Because `yield` was inside `with application.app_context():`, Flask's `g._login_user` remained bound to the outer application context across requests! When `client` (Alice) logged in, and then a separate `bob_client = app.test_client()` made a request, `current_user` leaked between test clients.
  2. **Test Suite Crash Without Oracle Client:** Calling `initialize_oracle_client()` unconditionally in `create_app()` caused `pytest` to crash on any machine without Oracle Instant Client configured, even when `SQLALCHEMY_DATABASE_URI = "sqlite://"`.
* **What I did instead:**
  Moved `yield` **outside** `with application.app_context():` in `tests/conftest.py` so every test request creates and tears down its own clean request/application context, and guarded `initialize_oracle_client()` in `app/__init__.py` with `if db_uri.startswith("oracle"):` so unit tests run cleanly in isolation.
  * **Fix Reference:** `tests/conftest.py` & `app/__init__.py`
