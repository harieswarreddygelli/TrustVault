# 🔐 TrustVault

### Secure Document Sharing · Permission Control · Cryptographic Audit Trail

> **A security-focused document-sharing project built to demonstrate
> server-side authorization, controlled collaboration and tamper-evident
> audit logging.**

[![Live
Demo](https://img.shields.io/badge/Live%20Demo-Render-4A90E2?logo=render&logoColor=white)](https://trustvault-23ma.onrender.com/login)     
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask-black?logo=flask)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-Oracle%20%7C%20SQLite-F80000?logo=oracle&logoColor=white)](https://www.oracle.com/database/)

**Live application:** [Open
TrustVault](https://trustvault-23ma.onrender.com/login)\
**Project walkthrough:** [Watch the demo
video](https://drive.google.com/file/d/1AGVtcYE_tOlZHWY8wqMAe5jvdrsG4EE0/view)\
**Source code:** [GitHub
repository](https://github.com/harieswarreddygelli/TrustVault)

**At a glance:** `Flask` · `Python` · `SQLAlchemy` · `Oracle / SQLite` ·
`pytest` · `Render`

------------------------------------------------------------------------

## ✨ Overview

TrustVault is a secure document-sharing web application built with
**Python, Flask and SQLAlchemy**. It gives users a place to upload and
manage documents, share them with other registered users, assign read or
write permissions, and review recorded activity.

The project focuses on several common security problems in file-sharing
applications:

-   **Broken access control:** A user must not gain access to another
    user's document simply by changing an identifier or URL.
-   **Stale permissions:** A revoked permission must not remain
    effective because an old permission decision was cached.
-   **Unsafe file handling:** User-provided filenames and extensions
    must not be trusted as storage paths or proof of file type.
-   **Limited accountability:** Important application actions should be
    recorded in an audit trail that can be checked for unexpected
    modification.

TrustVault combines server-side authorization, private file storage,
upload validation and a SHA-256-linked audit log to address these risks.

> **Project status:** TrustVault is a working project and demonstration
> deployment, not a claim of enterprise certification or a guarantee
> that every possible attack is prevented. Security controls have
> defined limits; see [Security Model &
> Limitations](#security-model--limitations).

## 🚀 Key Features

### Document management

-   User registration, login, logout and profile management.
-   Document upload, listing, filtering and search.
-   Document metadata management and soft-delete workflow.
-   Private file storage using generated storage identifiers.
-   Multi-file upload with a configured request-size limit.

### Sharing and access control

-   Document owners can grant and revoke access.
-   Read and write permissions are handled separately.
-   Protected document operations perform server-side authorization
    checks.
-   Revoked permissions are intended to be rejected on the recipient's
    next protected request.
-   Administrative access is separated from document ownership; an
    administrator does not automatically receive access to every private
    document.

### Auditability

-   Important application events are recorded in `TV_AUDIT_LOGS`.
-   Audit records are linked using SHA-256 hashes.
-   A command-line verifier checks the recorded chain.
-   Audit-related operations are designed to fail closed where an audit
    record is required for the business operation.

### Security controls

-   CSRF protection for state-changing forms and requests.
-   Server-side checks for document ownership and sharing permissions.
-   Generated storage names rather than trusting user-supplied
    filenames.
-   Private upload storage outside the public static directory.
-   Path validation before resolving stored files.
-   File-signature checks for selected executable formats.

------------------------------------------------------------------------

## 🧰 Technology Stack

  -----------------------------------------------------------------------
  Layer                               Technologies
  ----------------------------------- -----------------------------------
  Backend                             Python, Flask

  ORM / database access               SQLAlchemy, Flask-SQLAlchemy

  Authentication                      Flask-Login

  Forms and CSRF                      Flask-WTF

  Database                            Oracle Database XE; SQLite for
                                      local development where configured

  Frontend                            HTML, CSS, JavaScript, Jinja2
                                      templates

  Application server                  Gunicorn

  Testing                             pytest

  Deployment                          Render
  -----------------------------------------------------------------------

**Database note:** The local development configuration and the deployed
environment may use different database providers. Check the deployment's
actual environment configuration before describing the live instance as
Oracle-backed.

## 🏗️ Architecture

The application follows a Flask package structure, with route modules,
shared extensions, models, templates, static assets, utility scripts and
tests.

``` text
TrustVault-main/
├── .env.example                # Template for environment variables
├── .gitignore                  # Excludes .env, .venv, instance/, and caches
├── Procfile                    # Production Gunicorn process configuration
├── render.yaml                 # Render cloud deployment blueprint
├── requirements.txt            # Python dependencies (Flask, SQLAlchemy, oracledb, pytest)
├── run.py                      # Production WSGI / development entry point
├── config.py                   # Environment configuration & SQLite/Oracle fallback
├── README.md                   # Project documentation & setup guide
├── THREATS.md                  # Comprehensive STRIDE threat model & accepted risks
├── PROMPTS.md                  # AI collaboration logs, hallucinations caught & corrections
├── app/                        # Main Flask application package
│   ├── __init__.py             # App factory, security headers & automated seeding
│   ├── extensions.py           # SQLAlchemy, LoginManager & CSRFProtect instances
│   ├── models.py               # Database schemas (User, Document, Permission, AuditLog)
│   ├── auth.py                 # Authentication controllers (login, register, logout, profile)
│   ├── documents.py            # Document lifecycle, search, bulk actions & RBAC
│   ├── static/                 # Frontend assets (Frosted Glass UI & theme manager)
│   └── templates/              # Server-rendered responsive Jinja2 templates
├── scripts/                    # Database initialization & SHA-256 chain verification utils
└── tests/                      # Automated test suite (comprehensive test cases)
```

> This is a high-level view. Confirm filenames against the current
> repository before relying on the tree as an exhaustive file listing.

### Request and authorization flow

For a protected document operation, the intended flow is:

1.  The browser sends a request to a Flask route.
2.  The application verifies the user's authenticated session.
3.  The route loads the requested document and its current ownership or
    permission data.
4.  The server checks whether the user is allowed to perform the
    requested action.
5.  If authorized, the application performs the operation using private
    storage and database records.
6.  The relevant event is recorded in the audit log according to the
    operation's audit policy.
7.  The application returns the result without exposing internal storage
    paths.

The browser interface is not the security boundary. Hiding a button or
link does not replace server-side authorization.

------------------------------------------------------------------------

## 👥 Roles and Permissions

TrustVault uses account roles alongside document-level permissions.

  -----------------------------------------------------------------------
  Role                                Intended capabilities
  ----------------------------------- -----------------------------------
  `admin`                             View system-level activity and
                                      security information.
                                      Administrative role does not
                                      automatically bypass private
                                      document authorization.

  `owner`                             Upload and manage owned documents,
                                      update metadata, share documents,
                                      change permissions, revoke access
                                      and review permitted document
                                      history.

  `viewer`                            Access documents shared with the
                                      account, subject to the granted
                                      permission. Upload access is
                                      restricted by role.
                                      
  -----------------------------------------------------------------------

Document-level permissions:

-   **Read:** Allows the recipient to view or download the shared
    document, subject to the implemented route policy.
-   **Write:** Allows the recipient to perform the supported editing
    operations for that document.
-   **Revoked:** Removes the recipient's future access through protected
    TrustVault routes.

A role and a document permission answer different questions. The role
defines broad application capabilities; the document permission defines
what a user can do with a particular document.

### Public demo accounts

These seeded accounts are intentionally listed so reviewers can explore
the Render demonstration without creating accounts. **They are demo-only
credentials, not secure production accounts.** Use them only on the
public TrustVault demo and never reuse these passwords elsewhere.

  -----------------------------------------------------------------------------------
  Account           Username          Email                      Password
  ----------------- ----------------- -------------------------- --------------------
  Administrator     `admin_user`      `admin@trustvault.local`   `AdminPass123!@#`

  Document owner    `alice`           `alice@trustvault.local`   `TestPassword123!`

  Collaborator      `bob`             `bob@trustvault.local`     `TestPassword456!`
  
  -----------------------------------------------------------------------------------

> **Demo environment notice:** The application may recreate seeded demo
> data when its database is empty or reset. Do not enter real personal
> information, upload confidential documents, or treat these accounts as
> private. Public credentials are deliberately exposed for evaluation
> convenience.

Before using TrustVault with real users, disable public demo seeding,
remove or rotate these credentials, configure a strong production secret
key, and apply appropriate account and database controls.

------------------------------------------------------------------------

## 🔎 Route and Authorization Overview

The table below describes the intended route responsibilities. Confirm
endpoint names and methods against the current source before treating
this as a complete API specification.

  -------------------------------------------------------------------------------------
  Endpoint                              Access policy           Purpose
  ------------------------------------- ----------------------- -----------------------
  `GET /health`                         Public                  Basic health response.

  `GET, POST /register`                 Anonymous               Register an account.

  `GET, POST /login`                    Anonymous               Authenticate a user.

  `POST /logout`                        Authenticated           End the current
                                                                session.

  `GET, POST /profile`                  Authenticated           View or update profile
                                                                details.

  `GET, POST /change-password`          Authenticated           Change account
                                                                password.

  `GET /documents/dashboard`            Authenticated           Display the workspace
                                                                dashboard.

  `GET /documents/`                     Authenticated           Browse and filter
                                                                accessible documents.

  `GET /documents/shared`               Authenticated           View documents shared
                                                                with the current user.

  `GET, POST /documents/upload`         Authorized roles        Upload documents,
                                                                subject to role and
                                                                validation rules.

  `GET /documents/<id>/download`        Owner or active grantee Download a document
                                                                after authorization.

  `GET, POST /documents/<id>/edit`      Owner or active writer  Edit supported document
                                                                content.

  `POST /documents/<id>/share`          Document owner          Grant or update a
                                                                recipient's permission.

  `POST /documents/bulk-share`          Document owner          Share multiple
                                                                documents, subject to
                                                                validation.

  `POST /documents/<id>/revoke/<uid>`   Document owner          Revoke a recipient's
                                                                permission.

  `POST /documents/<id>/delete`         Document owner          Delete or soft-delete a
                                                                document according to
                                                                the configured
                                                                workflow.

  `GET /documents/<id>/history`         Authorized owner/admin  View permitted document
                                        policy                  audit history.

  `GET /documents/activity`             Authenticated; scope    View the activity feed.
                                        depends on role         
                                        
  -------------------------------------------------------------------------------------

State-changing requests should use appropriate HTTP methods and CSRF
protection. Unauthorized document access may return `404 Not Found`
rather than `403 Forbidden` to reduce object-existence disclosure.
Verify the actual response policy for each route.

------------------------------------------------------------------------

## ⚙️ Core Engineering Details

### 1. SHA-256-linked audit log

TrustVault records application events in `TV_AUDIT_LOGS` and links
entries using cryptographic hashes.

At a high level, each event contains: - Event identity and sequence
information. - Actor and, where relevant, document references. - Action
and outcome. - Event details. - Timestamp. - Previous event hash. -
Current event hash.

The hash is calculated from a deterministic representation of the event.
The implementation described for this project uses canonical JSON
serialization so that key ordering and whitespace do not change the
bytes being hashed.

Conceptually:

``` text
event_hash = SHA256(canonical_event_data + previous_hash)
```

The actual fields and serialization format must match the implementation
in the audit service and verifier.

**Concurrency:** The Oracle implementation uses a table lock when
appending audit events to serialize writers and protect the sequence of
chain entries. This is database-specific and may affect write
throughput. Confirm the exact transaction scope and locking behaviour in
the current code.

**Verification:** The CLI verifier recomputes hashes and checks the
previous-hash links. A mismatch indicates that the stored chain is
inconsistent with the verifier's calculation.

**Important limitation:** A hash chain is tamper-evident, not absolutely
immutable. An attacker with sufficient database privileges may be able
to rewrite records and recompute the chain. Stronger protection would
require independently protected checkpoints, signatures or external
write-once storage.

### 2. Private file storage

The project is designed to keep uploaded files outside the public static
directory.

The storage approach includes: - Generated internal filenames rather
than using the original filename as a path. - Private storage under the
configured upload directory. - Path resolution and validation before
accessing a stored file. - Exclusive file creation where configured to
avoid accidental overwrites. - Database metadata that links a document
record to its stored file.

The original filename is display metadata; it should not determine the
physical storage path.

**Deployment consideration:** Local instance storage may be ephemeral on
some hosting platforms. Verify whether the deployed storage is durable
across restarts and redeployments. For production use, prefer persistent
storage or object storage with access controls, backups and tested
recovery.

### 3. Upload validation

The application applies configured upload constraints and checks
selected file signatures.

Magic-byte checks can identify some known file formats or executable
signatures, including selected Windows PE, ELF and Mach-O patterns. They
are a useful validation layer, but they are **not antivirus scanning**
and cannot guarantee that an uploaded file is harmless.

For a production service handling untrusted files, consider malware
scanning, sandboxing, content disarm and reconstruction where
appropriate, storage quotas and monitoring.

### 4. Permission revocation

Protected operations should consult current permission records rather
than trusting stale client-side state.

After an owner revokes a grant, the next protected request from that
recipient should be denied if the permission is no longer active.

Revocation cannot recall a file that was already downloaded, copied,
photographed or otherwise captured outside TrustVault. It controls
future access through the application.

------------------------------------------------------------------------

## 🛡️ Security Model & Limitations

TrustVault is built around a practical set of security controls, but it
should not be described as "unhackable," "100% secure," or formally
certified.

  -----------------------------------------------------------------------
  Control                 What it helps with      What it does not
                                                  guarantee
  ----------------------- ----------------------- -----------------------
  Server-side             Blocks requests that    Does not protect
  authorization           fail ownership or       against every
                          permission checks.      application or
                                                  infrastructure
                                                  vulnerability.

  CSRF protection         Helps prevent forged    Does not prevent XSS or
                          state-changing browser  authorization flaws.
                          requests.               

  Generated storage names Reduces filename-based  Does not replace
                          path and collision      authorization checks.
                          risks.                  

  Path validation         Helps keep file access  Does not secure a
                          inside the intended     compromised host or
                          storage directory.      unsafe code elsewhere.

  Magic-byte checks       Detect selected file    Does not provide
                          signatures and some     comprehensive malware
                          executable disguises.   detection.

  SHA-256 hash chain      Makes many unauthorized Does not prevent a
                          changes to the audit    privileged attacker
                          history detectable.     from rewriting and
                                                  recomputing the entire
                                                  chain.

  Permission revocation   Blocks future access    Cannot erase copies
                          through protected       already downloaded by a
                          application routes.     recipient.

  Automated tests         Check the behaviours    Do not prove the
                          covered by the test     absence of all
                          suite.                  vulnerabilities.
                          
  -----------------------------------------------------------------------

### Known areas for future hardening

-   Durable object storage and tested backup/restore procedures.
-   Malware scanning for uploaded files.
-   Rate limiting and abuse monitoring.
-   Independent audit checkpoints or signed exports.
-   Centralized logging and operational alerting.
-   Database migrations and deployment rollback procedures.
-   Additional security testing, including penetration testing.
-   Background workers for notifications and longer-running verification
    tasks.

------------------------------------------------------------------------

## 💻 Local Development Setup

### Prerequisites

-   Python 3.10 or later (use the version supported by the project's
    dependencies).
-   Git.
-   Oracle Database XE for Oracle-specific local development, if
    desired.
-   SQLite for local development where the configuration supports it.

### 1. Clone the repository

``` bash
git clone https://github.com/harieswarreddygelli/TrustVault.git
cd TrustVault
```

### 2. Create and activate a virtual environment

**Windows --- PowerShell or Command Prompt**

``` bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS**

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

``` bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file based on `.env.example` and supply the
required values for your chosen database and session configuration.

Generate a strong development secret key with:

``` bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Do not commit `.env` or place production secrets in source control.
Check `config.py` and `.env.example` for the exact variable names
supported by the current version.

### 5. Initialize the database

If the repository's initialization script is configured for your
selected database:

``` bash
python scripts/init_db.py
```

### 6. Run the application

``` bash
python run.py
```

Open:

``` text
http://127.0.0.1:5000
```

------------------------------------------------------------------------

## 🧪 Tests and Audit Verification

Run the automated test suite:

``` bash
python -m pytest -v
```

Run the audit-chain verifier:

``` bash
python scripts/verify_audit_chain.py
```

Use the verifier against the database configured for the current
environment. If the script requires environment variables or a specific
working directory, follow its implementation and project configuration.

Do not publish a fixed test count unless it has been confirmed against
the current commit. Test totals can change as tests are added, removed
or parametrized.

### Recommended security checks before a demonstration

1.  Create two separate test accounts.
2.  Upload a harmless sample document as the owner.
3.  Share it with the second account using read permission.
4.  Confirm that the recipient can access it.
5.  Revoke the permission as the owner.
6.  Retry the same protected URL as the recipient and confirm access is
    denied.
7.  Attempt to access a private document by changing its identifier
    while logged in as the other user.
8.  Run the audit verifier against an unchanged test database.
9.  In a disposable test database only, alter an audit record and
    confirm the verifier detects the mismatch.

------------------------------------------------------------------------

## ☁️ Deployment

The project has a Render deployment:

**<https://trustvault-23ma.onrender.com/login>**

A reachable URL confirms that the application is deployed; it does not,
by itself, prove persistent file storage, database durability or
production readiness.

**Render free-service behaviour:** Free web services can spin down after
a period of inactivity and may take time to wake when a visitor returns.
This is different from a guaranteed scheduled data wipe. Data stored on
an ephemeral service filesystem is not durable and can be lost when the
service restarts, redeploys or is otherwise recycled. The exact
persistence of demo accounts, database records and uploaded files
depends on the database and storage configuration used by the
deployment. Do not describe it as "Render clears everything after
exactly 15 minutes" unless you have independently verified that
behaviour for this specific setup.

Before using the deployment with real users or sensitive documents,
verify:

-   The production database provider and connection settings.
-   Whether uploaded file storage survives restarts and redeployments.
-   That production secrets are strong and are not development defaults.
-   That demo accounts and automatic development seeding are disabled.
-   That debug mode is disabled.
-   That backups and restore procedures work.
-   That the deployed application is running the expected code version.

Use fabricated sample documents for public demonstrations. Never upload
real identity documents, financial receipts, private records or other
sensitive personal information to a public demo.

------------------------------------------------------------------------

## 📚 Project Documentation

-   [`THREATS.md`](THREATS.md) --- threat model, risks and mitigations.
-   [`PROMPTS.md`](PROMPTS.md) --- AI-assisted development notes, issues
    identified and corrections.

## Responsible Use

TrustVault is an educational and portfolio project. It is not a
substitute for a security-reviewed enterprise document management
system. Do not use the public demo to store confidential or regulated
information.

## Author

**Harieswar Reddy Gelli**\
GitHub: [@harieswarreddygelli](https://github.com/harieswarreddygelli)

------------------------------------------------------------------------

*Built to explore secure file handling, server-side authorization,
permission lifecycle management and tamper-evident audit logging.*

