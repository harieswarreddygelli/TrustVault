from datetime import date, datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import text
from werkzeug.utils import secure_filename

from app.audit_service import append_audit_event
from app.extensions import db
from app.models import AuditLog, Document, Permission, User

documents_bp = Blueprint("documents", __name__, url_prefix="/documents")

ALLOWED_CATEGORIES = [
    "General",
    "Financial",
    "Legal",
    "Engineering",
    "Regulatory",
    "HR",
]

ALLOWED_EXTENSIONS = {
    "txt", "md", "csv", "json", "log", "xml", "yaml", "yml", "ini", "cfg",
    "py", "sql", "html", "css", "js", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "png", "jpg", "jpeg", "gif",
}

FORBIDDEN_SIGNATURES = [
    (b"MZ", "Windows/DOS executable (PE)"),
    (b"\x7fELF", "Linux ELF executable"),
    (b"\xca\xfe\xba\xbe", "macOS Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", "macOS 64-bit Mach-O binary"),
]


@documents_bp.get("/dashboard")
@login_required
def dashboard():
    return render_template("documents/dashboard.html")


def _document_path(document):
    """Resolve a server-generated storage key inside private storage only."""
    root = Path(current_app.config["PRIVATE_UPLOAD_DIR"]).resolve()
    path = (root / document.storage_key).resolve()

    if path.parent != root:
        abort(404)

    return path


def _normalize_permission(perm_value):
    val = (perm_value or "").strip().lower()
    if val in {"edit", "write"}:
        return "write"
    if val == "read":
        return "read"
    return val


def _can_read(document):
    if document.is_deleted:
        return False

    current_user_id = str(current_user.get_id())
    if str(document.owner_id) == current_user_id:
        return True

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=current_user_id,
        is_revoked=False,
    ).first()

    return (
        permission is not None
        and _normalize_permission(permission.permission) in {"read", "write", "owner"}
    )


def _can_write(document):
    if document.is_deleted:
        return False

    current_user_id = str(current_user.get_id())
    if str(document.owner_id) == current_user_id:
        return True

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=current_user_id,
        is_revoked=False,
    ).first()

    return (
        permission is not None
        and _normalize_permission(permission.permission) in {"write", "owner"}
    )


def _owned_document_or_404(document_id):
    """Return an active document only when the current user owns it."""
    document = db.session.get(Document, document_id)

    if (
        document is None
        or document.is_deleted
        or str(document.owner_id) != str(current_user.get_id())
    ):
        abort(404)

    return document


def _validate_file_security(uploaded, original_filename):
    """
    Validate file extension and inspect magic bytes to block executable
    binaries or null-byte injection.
    """
    ext = Path(original_filename).suffix.lower().lstrip(".")
    if ext and ext not in ALLOWED_EXTENSIONS:
        return f"File extension '.{ext}' is not allowed by security policy."

    header = uploaded.stream.read(512)
    uploaded.stream.seek(0)

    for sig, desc in FORBIDDEN_SIGNATURES:
        if header.startswith(sig):
            return f"Blocked disallowed binary signature ({desc}) in {original_filename}."

    return None


def _parse_recipient_usernames(form):
    """Extract unique recipient usernames from multi-select and comma-separated input."""
    raw_list = form.getlist("usernames")
    single_or_csv = form.get("username", "")
    combined = list(raw_list)
    if single_or_csv:
        combined.extend(single_or_csv.replace(";", ",").split(","))

    cleaned = []
    seen = set()
    for item in combined:
        uname = item.strip()
        if uname and uname.lower() not in seen:
            seen.add(uname.lower())
            cleaned.append(uname)
    return cleaned


@documents_bp.get("/shared")
@login_required
def shared_documents():
    """List active documents shared with the current user."""
    user_id = str(current_user.get_id())

    shared_permissions = Permission.query.filter_by(
        user_id=user_id,
        is_revoked=False,
    ).all()

    shared = [
        permission.document
        for permission in shared_permissions
        if _normalize_permission(permission.permission) in {"read", "write", "owner"}
        and permission.document is not None
        and not permission.document.is_deleted
        and str(permission.document.owner_id) != user_id
    ]

    visible = {document.id: document for document in shared}

    shared_documents_list = sorted(
        visible.values(),
        key=lambda document: document.created_at,
        reverse=True,
    )

    return render_template(
        "documents/shared.html",
        documents=shared_documents_list,
    )


@documents_bp.get("/")
@login_required
def index():
    """List authorized documents and apply search/filter by name, owner, category, and date."""
    user_id = str(current_user.get_id())

    owned = Document.query.filter_by(
        owner_id=user_id,
        is_deleted=False,
    ).all()

    shared_permissions = Permission.query.filter_by(
        user_id=user_id,
        is_revoked=False,
    ).all()

    shared = [
        permission.document
        for permission in shared_permissions
        if _normalize_permission(permission.permission) in {"read", "write", "owner"}
        and permission.document is not None
        and not permission.document.is_deleted
        and str(permission.document.owner_id) != user_id
    ]

    visible = {document.id: document for document in owned + shared}
    all_documents = sorted(
        visible.values(),
        key=lambda document: document.created_at,
        reverse=True,
    )

    # Active users available for sharing checkboxes / multi-select (Oracle-compatible boolean comparison)
    shareable_users = (
        User.query.filter(User.is_active == True, User.id != user_id)
        .order_by(User.username.asc())
        .all()
    )

    # Read filter values from query parameters
    search_query = request.args.get("q", "").strip()[:200]
    owner_query = request.args.get("owner", "").strip()[:80]
    selected_category = request.args.get("category", "").strip()[:50]
    selected_type = request.args.get("file_type", "").strip().lower()
    exact_date_str = request.args.get("date", "").strip()
    uploaded_after = request.args.get("uploaded_after", "").strip()
    uploaded_before = request.args.get("uploaded_before", "").strip()

    file_types = sorted({
        Path(document.original_filename or "").suffix.lower().lstrip(".")
        for document in all_documents
        if Path(document.original_filename or "").suffix
    })

    categories = sorted(
        set(ALLOWED_CATEGORIES)
        | {
            document.category
            for document in all_documents
            if getattr(document, "category", None)
        }
    )

    filtered = all_documents

    # 1. Search by Name (title or original_filename)
    if search_query:
        needle = search_query.casefold()
        filtered = [
            document for document in filtered
            if needle in (document.title or "").casefold()
            or needle in (document.original_filename or "").casefold()
        ]

    # 2. Search by Owner (owner username)
    if owner_query:
        owner_needle = owner_query.casefold()
        filtered = [
            document for document in filtered
            if document.owner is not None
            and owner_needle in (document.owner.username or "").casefold()
        ]

    # 3. Search by Category
    if selected_category and selected_category.lower() != "all":
        cat_needle = selected_category.casefold()
        filtered = [
            document for document in filtered
            if (getattr(document, "category", "General") or "General").casefold() == cat_needle
        ]

    # Optional extension filter
    if selected_type and selected_type in file_types:
        filtered = [
            document for document in filtered
            if Path(document.original_filename or "")
            .suffix.lower().lstrip(".") == selected_type
        ]

    # 4. Search by Date (exact date OR date range)
    try:
        exact_date = date.fromisoformat(exact_date_str) if exact_date_str else None
    except ValueError:
        exact_date = None
        flash("Invalid date filter; that filter was ignored.", "warning")

    try:
        after_date = date.fromisoformat(uploaded_after) if uploaded_after else None
    except ValueError:
        after_date = None
        flash("Invalid start date; that filter was ignored.", "warning")

    try:
        before_date = date.fromisoformat(uploaded_before) if uploaded_before else None
    except ValueError:
        before_date = None
        flash("Invalid end date; that filter was ignored.", "warning")

    if after_date and before_date and after_date > before_date:
        flash("Start date must be on or before end date.", "warning")
        after_date = before_date = None

    if exact_date or after_date or before_date:
        date_filtered = []
        for document in filtered:
            created_at = document.created_at
            if isinstance(created_at, datetime):
                created_date = created_at.date()
            elif isinstance(created_at, date):
                created_date = created_at
            else:
                continue

            if exact_date and created_date != exact_date:
                continue
            if after_date and created_date < after_date:
                continue
            if before_date and created_date > before_date:
                continue

            date_filtered.append(document)

        filtered = date_filtered

    filters_active = bool(
        search_query
        or owner_query
        or selected_category
        or selected_type
        or exact_date_str
        or uploaded_after
        or uploaded_before
    )

    return render_template(
        "documents/index.html",
        documents=filtered,
        total_documents=len(all_documents),
        categories=categories,
        file_types=file_types,
        shareable_users=shareable_users,
        search_query=search_query,
        owner_query=owner_query,
        selected_category=selected_category,
        selected_type=selected_type,
        exact_date=exact_date_str,
        uploaded_after=uploaded_after,
        uploaded_before=uploaded_before,
        filters_active=filters_active,
    )


@documents_bp.get("/upload")
@login_required
def upload_page():
    if getattr(current_user, "role", "owner") == "viewer":
        abort(403)
    return render_template(
        "documents/upload.html",
        categories=ALLOWED_CATEGORIES,
    )


@documents_bp.post("/upload")
@login_required
def upload():
    """Upload multiple files to private storage and audit each upload."""
    if getattr(current_user, "role", "owner") == "viewer":
        try:
            append_audit_event(
                action="document_upload",
                outcome="denied",
                user_id=current_user.get_id(),
                details="Viewer role attempted to upload a document",
            )
        except Exception:
            current_app.logger.exception("Could not record denied viewer upload.")
        abort(403)

    uploaded_files = request.files.getlist("file")
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "General").strip()

    if not category or len(category) > 50:
        category = "General"

    uploaded_files = [
        uploaded
        for uploaded in uploaded_files
        if uploaded is not None and uploaded.filename
    ]

    if not uploaded_files:
        flash("Choose at least one file to upload.", "error")
        return redirect(url_for("documents.upload_page"))

    if not title or len(title) > 255:
        flash("Enter a title between 1 and 255 characters.", "error")
        return redirect(url_for("documents.upload_page"))

    prepared_files = []

    for uploaded in uploaded_files:
        original_filename = secure_filename(uploaded.filename)

        if not original_filename:
            flash(
                "One or more filenames are not supported. "
                "No files were uploaded.",
                "error",
            )
            return redirect(url_for("documents.upload_page"))

        validation_error = _validate_file_security(uploaded, original_filename)
        if validation_error:
            try:
                append_audit_event(
                    action="document_upload",
                    outcome="denied",
                    user_id=current_user.get_id(),
                    details=f"validation_failed={validation_error[:200]!r}",
                )
            except Exception:
                current_app.logger.exception("Could not record file validation refusal.")
            flash(validation_error, "error")
            return redirect(url_for("documents.upload_page"))

        prepared_files.append((uploaded, original_filename[:255]))

    successful_uploads = []

    for uploaded, original_filename in prepared_files:
        storage_key = uuid4().hex
        path = _document_path(
            type("NewDocument", (), {"storage_key": storage_key})()
        )

        if len(prepared_files) == 1:
            document_title = title
        else:
            suffix = f" - {original_filename}"
            document_title = title[:255 - len(suffix)] + suffix
            document_title = document_title[:255]

        document = Document(
            owner_id=current_user.get_id(),
            title=document_title,
            original_filename=original_filename,
            category=category,
            storage_key=storage_key,
        )

        file_saved = False
        document_committed = False

        try:
            with path.open("xb") as destination:
                file_saved = True
                uploaded.save(destination)

            db.session.add(document)
            db.session.commit()
            document_committed = True

            append_audit_event(
                action="document_upload",
                outcome="success",
                user_id=current_user.get_id(),
                document_id=document.id,
                details=f"filename={original_filename[:200]!r};category={category!r}",
            )

            successful_uploads.append(original_filename)

        except Exception:
            db.session.rollback()

            if document_committed and document.id is not None:
                try:
                    persisted = db.session.get(Document, document.id)

                    if persisted is not None:
                        db.session.delete(persisted)
                        db.session.commit()

                except Exception:
                    db.session.rollback()
                    current_app.logger.exception(
                        "Could not compensate for failed upload."
                    )

            if file_saved:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    current_app.logger.exception(
                        "Could not clean up the uploaded file."
                    )

            current_app.logger.exception(
                "Document upload failed for %s.",
                original_filename,
            )

            if successful_uploads:
                flash(
                    f"{len(successful_uploads)} file(s) uploaded successfully. "
                    "Another file failed. Check the server logs before retrying.",
                    "warning",
                )
            else:
                flash(
                    "Upload could not be completed. Check the server logs "
                    "before retrying.",
                    "error",
                )

            return redirect(url_for("documents.index"))

    flash(
        f"{len(successful_uploads)} document(s) uploaded successfully.",
        "success",
    )
    return redirect(url_for("documents.index"))


@documents_bp.get("/<document_id>/download")
@login_required
def download(document_id):
    """Authorize each download using current database permissions."""
    document = db.session.get(Document, document_id)

    if document is None or not _can_read(document):
        try:
            append_audit_event(
                action="document_download",
                outcome="denied",
                user_id=current_user.get_id(),
                document_id=document.id if document is not None else None,
                details="Document missing or user lacks active read permission",
            )
        except Exception:
            current_app.logger.exception(
                "Could not record denied download."
            )

        abort(404)

    path = _document_path(document)

    if not path.is_file():
        append_audit_event(
            action="document_download",
            outcome="failure",
            user_id=current_user.get_id(),
            document_id=document.id,
            details="Stored file is missing",
        )
        abort(404)

    append_audit_event(
        action="document_download",
        outcome="success",
        user_id=current_user.get_id(),
        document_id=document.id,
        details="Authorized download",
    )

    return send_file(
        path,
        as_attachment=True,
        download_name=document.original_filename,
    )


@documents_bp.route("/<document_id>/edit", methods=["GET", "POST"])
@login_required
def edit(document_id):
    """
    Allow owners and active write/edit-permission holders to edit:
    1. Document metadata (Title and Category),
    2. Plain-text UTF-8 content in the browser (up to 1 MiB), AND/OR
    3. Uploading a replacement file version (for any file type, including PDF, DOCX, images, or text).
    """
    document = db.session.get(Document, document_id)

    if document is None or not _can_write(document):
        try:
            append_audit_event(
                action="document_edit",
                outcome="denied",
                user_id=current_user.get_id(),
                document_id=document.id if document is not None else None,
                details="Document missing or user lacks active write permission",
            )
        except Exception:
            current_app.logger.exception("Could not record denied edit.")

        abort(404)

    path = _document_path(document)
    file_exists = path.is_file()

    is_text = True
    content = ""
    previous_bytes = b""

    if file_exists:
        try:
            previous_bytes = path.read_bytes()
            if len(previous_bytes) <= 1024 * 1024:
                content = previous_bytes.decode("utf-8")
            else:
                is_text = False
        except UnicodeDecodeError:
            is_text = False
    else:
        # If the database row exists from an earlier folder extraction and its physical file
        # is missing on disk, allow the authorized user to re-populate it via text or file upload!
        ext = Path(document.original_filename or "").suffix.lower().lstrip(".")
        if ext in {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "gif"}:
            is_text = False

    if request.method == "GET":
        return render_template(
            "documents/edit.html",
            document=document,
            content=content,
            is_text=is_text,
            file_missing=not file_exists,
            categories=ALLOWED_CATEGORIES,
        )

    # POST: Handle metadata updates, replacement file uploads, or text content updates
    old_title = document.title
    old_category = getattr(document, "category", "General") or "General"
    old_filename = document.original_filename

    new_title = request.form.get("title", "").strip() or old_title
    new_category = request.form.get("category", "").strip() or old_category

    if len(new_title) > 255:
        flash("Document title must be between 1 and 255 characters.", "error")
        return (
            render_template(
                "documents/edit.html",
                document=document,
                content=content,
                is_text=is_text,
                file_missing=not file_exists,
                categories=ALLOWED_CATEGORIES,
            ),
            400,
        )

    if len(new_category) > 50:
        new_category = "General"

    replacement_file = request.files.get("replacement_file")
    has_replacement_file = (
        replacement_file is not None and bool(replacement_file.filename)
    )

    write_new_bytes = False
    new_bytes = previous_bytes

    if has_replacement_file:
        cleaned_filename = secure_filename(replacement_file.filename)
        if not cleaned_filename:
            flash("Replacement filename is not supported.", "error")
            return (
                render_template(
                    "documents/edit.html",
                    document=document,
                    content=content,
                    is_text=is_text,
                    file_missing=not file_exists,
                    categories=ALLOWED_CATEGORIES,
                ),
                400,
            )

        validation_error = _validate_file_security(replacement_file, cleaned_filename)
        if validation_error:
            flash(validation_error, "error")
            return (
                render_template(
                    "documents/edit.html",
                    document=document,
                    content=content,
                    is_text=is_text,
                    file_missing=not file_exists,
                    categories=ALLOWED_CATEGORIES,
                ),
                400,
            )

        new_bytes = replacement_file.read()
        write_new_bytes = True
        new_filename = cleaned_filename[:255]
        audit_detail = f"replacement_file={new_filename!r};bytes_written={len(new_bytes)};title={new_title!r};category={new_category!r}"
    elif "content" in request.form and is_text:
        new_content = request.form.get("content", "")
        encoded = new_content.encode("utf-8")
        if len(encoded) > 1024 * 1024:
            flash("Document content exceeds the 1 MiB editor limit.", "error")
            return (
                render_template(
                    "documents/edit.html",
                    document=document,
                    content=new_content,
                    is_text=is_text,
                    file_missing=not file_exists,
                    categories=ALLOWED_CATEGORIES,
                ),
                400,
            )
        new_bytes = encoded
        write_new_bytes = True
        new_filename = old_filename
        audit_detail = f"bytes_written={len(encoded)};title={new_title!r};category={new_category!r}"
    else:
        new_filename = old_filename
        audit_detail = f"metadata_updated;title={new_title!r};category={new_category!r}"

    try:
        if write_new_bytes:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(new_bytes)

        document.title = new_title
        document.category = new_category
        document.original_filename = new_filename
        db.session.commit()

        append_audit_event(
            action="document_edit",
            outcome="success",
            user_id=current_user.get_id(),
            document_id=document.id,
            details=audit_detail[:1000],
        )
    except Exception:
        db.session.rollback()
        try:
            if file_exists:
                path.write_bytes(previous_bytes)
            elif write_new_bytes and path.exists():
                path.unlink(missing_ok=True)
        except OSError:
            current_app.logger.exception("Could not roll back file edit.")

        try:
            persisted = db.session.get(Document, document.id)
            if persisted is not None:
                persisted.title = old_title
                persisted.category = old_category
                persisted.original_filename = old_filename
                db.session.commit()
        except Exception:
            db.session.rollback()

        current_app.logger.exception("Document edit failed.")
        flash("Changes could not be saved. Please try again.", "error")
        return (
            render_template(
                "documents/edit.html",
                document=document,
                content=request.form.get("content", content),
                is_text=is_text,
                file_missing=not file_exists,
                categories=ALLOWED_CATEGORIES,
            ),
            503,
        )

    flash("Document updated successfully.", "success")
    if str(document.owner_id) == str(current_user.get_id()):
        return redirect(url_for("documents.index"))
    return redirect(url_for("documents.shared_documents"))


def _grant_permission_with_audit(document, recipient, permission_level):
    """
    Grant or update permission on a single document for a single recipient,
    with full rollback compensation if audit logging fails.
    """
    existing = Permission.query.filter_by(
        document_id=document.id,
        user_id=recipient.id,
    ).first()

    old_values = None

    if existing is not None:
        old_values = (
            existing.permission,
            existing.is_revoked,
            existing.revoked_at,
        )
        existing.permission = permission_level
        existing.is_revoked = False
        existing.revoked_at = None
    else:
        existing = Permission(
            document_id=document.id,
            user_id=recipient.id,
            permission=permission_level,
            is_revoked=False,
        )
        db.session.add(existing)

    try:
        db.session.commit()

        append_audit_event(
            action="document_share",
            outcome="success",
            user_id=current_user.get_id(),
            document_id=document.id,
            details=(
                f"recipient_username={recipient.username};"
                f"recipient_user_id={recipient.id};"
                f"permission={permission_level}"
            ),
        )
        return True
    except Exception:
        db.session.rollback()
        try:
            persisted = Permission.query.filter_by(
                document_id=document.id,
                user_id=recipient.id,
            ).first()
            if old_values is None:
                if persisted is not None:
                    db.session.delete(persisted)
            elif persisted is not None:
                (
                    persisted.permission,
                    persisted.is_revoked,
                    persisted.revoked_at,
                ) = old_values
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Could not compensate for failed share.")
        return False


@documents_bp.post("/<document_id>/share")
@login_required
def share(document_id):
    """Grant or update a document permission for one or multiple recipients; owner only."""
    document = _owned_document_or_404(document_id)

    usernames = _parse_recipient_usernames(request.form)
    raw_perm = request.form.get("permission", "read")
    permission_level = _normalize_permission(raw_perm)

    if not usernames or any(len(u) > 80 for u in usernames):
        flash("Select or enter at least one valid username.", "error")
        return redirect(url_for("documents.index"))

    if permission_level not in {"read", "write"}:
        flash("Choose a valid permission.", "error")
        return redirect(url_for("documents.index"))

    recipients = []
    for uname in usernames:
        recipient = User.query.filter_by(username=uname).first()
        if recipient is None or not recipient.is_active:
            flash(f"No active user was found with username '{uname}'.", "error")
            return redirect(url_for("documents.index"))
        if str(recipient.id) == str(current_user.get_id()):
            flash("You already own this document.", "error")
            return redirect(url_for("documents.index"))
        recipients.append(recipient)

    granted_count = 0
    for recipient in recipients:
        if _grant_permission_with_audit(document, recipient, permission_level):
            granted_count += 1
        else:
            flash("Sharing could not be completed.", "error")
            return redirect(url_for("documents.index"))

    if granted_count == 1:
        flash("Document access granted successfully.", "success")
    else:
        flash(f"Document access granted to {granted_count} users successfully.", "success")
    return redirect(url_for("documents.index"))


@documents_bp.post("/bulk-share")
@login_required
def bulk_share():
    """
    Share multiple owned documents with one or multiple users in a single operation.
    Every document is verified for ownership and every grant is individually audited.
    """
    document_ids = [d.strip() for d in request.form.getlist("document_ids") if d.strip()]
    usernames = _parse_recipient_usernames(request.form)
    permission_level = _normalize_permission(request.form.get("permission", "read"))

    if not document_ids:
        flash("Select at least one document to share.", "error")
        return redirect(url_for("documents.index"))

    if not usernames or any(len(u) > 80 for u in usernames):
        flash("Select or enter at least one valid recipient username.", "error")
        return redirect(url_for("documents.index"))

    if permission_level not in {"read", "write"}:
        flash("Choose a valid permission.", "error")
        return redirect(url_for("documents.index"))

    # Verify strict ownership of every selected document before mutating anything
    documents = []
    for doc_id in document_ids:
        doc = _owned_document_or_404(doc_id)
        documents.append(doc)

    recipients = []
    for uname in usernames:
        recipient = User.query.filter_by(username=uname).first()
        if recipient is None or not recipient.is_active:
            flash(f"No active user was found with username '{uname}'.", "error")
            return redirect(url_for("documents.index"))
        if str(recipient.id) == str(current_user.get_id()):
            flash("You already own the selected document(s).", "error")
            return redirect(url_for("documents.index"))
        recipients.append(recipient)

    total_grants = 0
    for doc in documents:
        for recipient in recipients:
            if _grant_permission_with_audit(doc, recipient, permission_level):
                total_grants += 1
            else:
                flash("Bulk sharing encountered an audit error and was stopped.", "error")
                return redirect(url_for("documents.index"))

    flash(
        f"Shared {len(documents)} document(s) with {len(recipients)} user(s) ({total_grants} permission grant(s) recorded).",
        "success",
    )
    return redirect(url_for("documents.index"))


@documents_bp.post("/<document_id>/revoke/<user_id>")
@login_required
def revoke(document_id, user_id):
    """Revoke a recipient's permission without deleting its history."""
    document = _owned_document_or_404(document_id)

    permission_record = Permission.query.filter_by(
        document_id=document.id,
        user_id=user_id,
    ).first()

    if permission_record is None or permission_record.is_revoked:
        flash("No active permission was found for that user.", "error")
        return redirect(url_for("documents.index"))

    old_values = (
        permission_record.permission,
        permission_record.is_revoked,
        permission_record.revoked_at,
    )

    permission_record.is_revoked = True
    permission_record.revoked_at = datetime.now(
        timezone.utc
    ).replace(tzinfo=None, microsecond=0)

    try:
        db.session.commit()

        append_audit_event(
            action="document_revoke",
            outcome="success",
            user_id=current_user.get_id(),
            document_id=document.id,
            details=(
                f"revoked_user_id={user_id};"
                f"permission={permission_record.permission}"
            ),
        )

    except Exception:
        db.session.rollback()

        try:
            persisted = Permission.query.filter_by(
                document_id=document.id,
                user_id=user_id,
            ).first()

            if persisted is not None:
                (
                    persisted.permission,
                    persisted.is_revoked,
                    persisted.revoked_at,
                ) = old_values

            db.session.commit()

        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Could not restore permission after failed revocation."
            )

        current_app.logger.exception("Revocation operation failed.")
        flash("Revocation could not be completed.", "error")
        return redirect(url_for("documents.index"))

    flash("Document access revoked.", "success")
    return redirect(url_for("documents.index"))


def _soft_delete_single_document(document):
    """
    Execute fail-closed soft deletion and physical file cleanup for one owned document.
    Returns (status, message) where status is 'success', 'partial', or 'error'.
    """
    path = _document_path(document)

    try:
        append_audit_event(
            action="document_delete",
            outcome="requested",
            user_id=current_user.get_id(),
            document_id=document.id,
            details="Owner requested document deletion",
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Could not record the document deletion request.")
        return "error", "Deletion was not started because the audit request could not be recorded."

    document.is_deleted = True

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Could not mark the document as deleted.")
        try:
            append_audit_event(
                action="document_delete",
                outcome="failure",
                user_id=current_user.get_id(),
                document_id=document.id,
                details="Could not persist the soft-delete flag",
            )
        except Exception:
            current_app.logger.exception("Could not record the failed deletion.")
        return "error", "The document could not be deleted."

    cleanup_succeeded = True
    try:
        path.unlink(missing_ok=True)
    except OSError:
        cleanup_succeeded = False
        current_app.logger.exception("Document was soft-deleted, but private-file cleanup failed.")

    try:
        append_audit_event(
            action="document_delete",
            outcome="success" if cleanup_succeeded else "failure",
            user_id=current_user.get_id(),
            document_id=document.id,
            details=(
                "soft_delete=success;"
                f"file_cleanup={'success' if cleanup_succeeded else 'failure'}"
            ),
        )
    except Exception:
        current_app.logger.exception(
            "Deletion completed or partially completed, but the final audit event could not be recorded."
        )
        return (
            "partial",
            "The document is inaccessible, but final audit recording failed. Check the server logs and verify audit integrity.",
        )

    if cleanup_succeeded:
        return "success", "Document deleted. Its database and audit history were preserved."
    return (
        "partial",
        "Document access was revoked, but its private file could not be removed. Check the server logs for cleanup.",
    )


@documents_bp.post("/<document_id>/delete")
@login_required
def delete_document(document_id):
    """Soft-delete an owned document and attempt private-file cleanup."""
    document = db.session.get(Document, document_id)
    if (
        document is None
        or str(document.owner_id) != str(current_user.get_id())
    ):
        abort(404)

    if document.is_deleted:
        flash("This document has already been deleted.", "error")
        return redirect(url_for("documents.index"))

    status, message = _soft_delete_single_document(document)
    flash(message, "success" if status == "success" else "error")
    return redirect(url_for("documents.index"))


@documents_bp.post("/bulk-delete")
@login_required
def bulk_delete():
    """Soft-delete multiple owned documents at once with per-document audit logging."""
    document_ids = [d.strip() for d in request.form.getlist("document_ids") if d.strip()]

    if not document_ids:
        flash("Select at least one document to delete.", "error")
        return redirect(url_for("documents.index"))

    # Verify strict ownership of every selected document before deleting any
    documents = []
    for doc_id in document_ids:
        doc = db.session.get(Document, doc_id)
        if (
            doc is None
            or doc.is_deleted
            or str(doc.owner_id) != str(current_user.get_id())
        ):
            abort(404)
        documents.append(doc)

    deleted_count = 0
    for doc in documents:
        status, message = _soft_delete_single_document(doc)
        if status == "error":
            flash(message, "error")
            return redirect(url_for("documents.index"))
        deleted_count += 1

    flash(
        f"{deleted_count} document(s) deleted. Database and audit history were preserved.",
        "success",
    )
    return redirect(url_for("documents.index"))


@documents_bp.get("/activity")
@login_required
def activity():
    """
    Show audit activity, system metrics, and permission changes.
    Administrators see system-wide metrics, refused access attempts,
    permission grants/revocations, and all audit events across all users.
    Regular users see their own activity.
    """
    user_id = str(current_user.get_id())
    is_admin = getattr(current_user, "role", "") == "admin"

    permissions_overview = []
    admin_metrics = {}
    if is_admin:
        permissions_overview = Permission.query.order_by(
            Permission.granted_at.desc()
        ).all()

        total_users = User.query.count()
        active_docs = Document.query.filter_by(is_deleted=False).count()
        deleted_docs = Document.query.filter_by(is_deleted=True).count()
        active_grants = Permission.query.filter_by(is_revoked=False).count()
        revoked_grants = Permission.query.filter_by(is_revoked=True).count()
        try:
            denied_row = db.session.execute(
                text("SELECT COUNT(*) AS cnt FROM TV_AUDIT_LOGS WHERE OUTCOME IN ('denied', 'failure')")
            ).mappings().first()
            refused_attempts = denied_row["cnt"] if denied_row else 0
        except Exception:
            refused_attempts = 0

        admin_metrics = {
            "total_users": total_users,
            "active_docs": active_docs,
            "deleted_docs": deleted_docs,
            "active_grants": active_grants,
            "revoked_grants": revoked_grants,
            "refused_attempts": refused_attempts,
        }

    try:
        if is_admin:
            result = db.session.execute(
                text("""
                    SELECT
                        ID AS "id",
                        USER_ID AS "user_id",
                        DOCUMENT_ID AS "document_id",
                        ACTION AS "action",
                        OUTCOME AS "outcome",
                        DETAILS AS "details",
                        CREATED_AT AS "created_at",
                        CHAIN_INDEX AS "chain_index"
                    FROM TV_AUDIT_LOGS
                    ORDER BY CHAIN_INDEX DESC
                """)
            )
        else:
            result = db.session.execute(
                text("""
                    SELECT
                        ID AS "id",
                        USER_ID AS "user_id",
                        DOCUMENT_ID AS "document_id",
                        ACTION AS "action",
                        OUTCOME AS "outcome",
                        DETAILS AS "details",
                        CREATED_AT AS "created_at",
                        CHAIN_INDEX AS "chain_index"
                    FROM TV_AUDIT_LOGS
                    WHERE USER_ID = :user_id
                    ORDER BY CHAIN_INDEX DESC
                """),
                {"user_id": user_id},
            )

        events = [dict(row) for row in result.mappings().all()[:200]]

    except Exception:
        current_app.logger.exception("Could not load activity.")
        flash("Activity could not be loaded. Please try again.", "error")
        events = []

    return render_template(
        "documents/activity.html",
        events=events,
        is_admin=is_admin,
        permissions_overview=permissions_overview,
        admin_metrics=admin_metrics,
    )


@documents_bp.get("/<document_id>/history")
@login_required
def history(document_id):
    """
    Display recorded audit events for a document.

    Only its owner (or an administrator for audit oversight) can view the
    full sharing history.
    """
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    is_owner = str(document.owner_id) == str(current_user.get_id())
    is_admin = getattr(current_user, "role", "") == "admin"

    if not (is_owner or is_admin):
        try:
            append_audit_event(
                action="document_history",
                outcome="denied",
                user_id=current_user.get_id(),
                document_id=document.id,
                details="Non-owner attempted to view document history",
            )
        except Exception:
            current_app.logger.exception(
                "Could not record denied history access."
            )

        abort(404)

    try:
        result = db.session.execute(
            text(
                """
                SELECT
                    ID AS "id",
                    CHAIN_INDEX AS "chain_index",
                    USER_ID AS "user_id",
                    ACTION AS "action",
                    OUTCOME AS "outcome",
                    DETAILS AS "details",
                    CREATED_AT AS "created_at",
                    EVENT_HASH AS "event_hash"
                FROM TV_AUDIT_LOGS
                WHERE DOCUMENT_ID = :document_id
                ORDER BY CHAIN_INDEX DESC
                """
            ),
            {"document_id": str(document.id)},
        )

        events = [dict(row) for row in result.mappings().all()]

    except Exception:
        current_app.logger.exception(
            "Could not load document audit history."
        )
        flash("The document history could not be loaded.", "error")
        return redirect(url_for("documents.index"))

    return render_template(
        "documents/history.html",
        document=document,
        events=events,
    )
