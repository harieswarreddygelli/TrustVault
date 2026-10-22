"""Authentication routes for TrustVault."""

from urllib.parse import urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.audit_service import append_audit_event
from app.models import User


auth_bp = Blueprint("auth", __name__)


def _safe_next_url(target):
    """Allow only relative, local redirect targets."""
    if not target:
        return False

    parsed = urlparse(target)
    return (
        not parsed.scheme
        and not parsed.netloc
        and parsed.path.startswith("/")
        and not parsed.path.startswith("//")
        and "\\" not in target
    )


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))

    if request.method == "GET":
        return render_template("auth/login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = User.query.filter_by(username=username[:80]).first()

    valid_login = (
        user is not None
        and user.is_active
        and user.check_password(password)
    )

    if not valid_login:
        try:
            append_audit_event(
                action="login",
                outcome="failure",
                user_id=user.id if user is not None else None,
                details=f"username_attempted={username[:80]!r}",
            )
        except Exception:
            current_app.logger.exception(
                "Could not record failed login attempt."
            )

        # Invalid credentials are always rejected.
        flash("Invalid username or password.", "error")
        return render_template("auth/login.html"), 401

    # Do not establish a session if successful-login auditing fails.
    try:
        append_audit_event(
            action="login",
            outcome="success",
            user_id=user.id,
            details="Authentication successful",
        )
    except Exception:
        current_app.logger.exception(
            "Could not record successful login; session not created."
        )
        flash(
            "Login is temporarily unavailable. Please try again later.",
            "error",
        )
        return render_template("auth/login.html"), 503

    login_user(user, remember=False, fresh=True)

    target = request.args.get("next", "")
    if _safe_next_url(target):
        return redirect(target)

    return redirect(url_for("documents.dashboard"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))

    if request.method == "GET":
        return render_template("auth/register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    requested_role = request.form.get("role", "owner").strip().lower()

    if requested_role not in {"owner", "viewer"}:
        requested_role = "owner"

    if not username or len(username) > 80:
        flash("Username must contain 1–80 characters.", "error")
        return render_template("auth/register.html"), 400

    if (
        not email
        or len(email) > 255
        or "@" not in email
        or email.startswith("@")
        or email.endswith("@")
    ):
        flash("Enter a valid email address.", "error")
        return render_template("auth/register.html"), 400

    if len(password) < 12:
        flash("Password must contain at least 12 characters.", "error")
        return render_template("auth/register.html"), 400

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return render_template("auth/register.html"), 400

    if User.query.filter_by(username=username).first():
        flash("That username is already registered.", "error")
        return render_template("auth/register.html"), 409

    if User.query.filter_by(email=email).first():
        flash("That email address is already registered.", "error")
        return render_template("auth/register.html"), 409

    user = User(
        username=username,
        email=email,
        role=requested_role,
        is_active=True,
    )
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(
            "That username or email is already registered.",
            "error",
        )
        return render_template("auth/register.html"), 409
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Account creation failed.")
        flash(
            "Registration is temporarily unavailable. Please try again.",
            "error",
        )
        return render_template("auth/register.html"), 503

    try:
        append_audit_event(
            action="register",
            outcome="success",
            user_id=user.id,
            details=f"Account created; username={username!r}; role={requested_role!r}",
        )
    except Exception:
        current_app.logger.exception(
            "Registration audit failed; attempting account cleanup."
        )
        try:
            db.session.delete(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Could not clean up account after audit failure."
            )

        flash(
            "Registration is temporarily unavailable. Please try again.",
            "error",
        )
        return render_template("auth/register.html"), 503

    flash("Account created successfully. You can now sign in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("auth/change_password.html")

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_user.check_password(current_password):
        flash("Your current password is incorrect.", "error")
        return render_template("auth/change_password.html"), 400

    if len(new_password) < 12:
        flash("Your new password must contain at least 12 characters.", "error")
        return render_template("auth/change_password.html"), 400

    if new_password != confirm_password:
        flash("The new passwords do not match.", "error")
        return render_template("auth/change_password.html"), 400

    if current_user.check_password(new_password):
        flash("Choose a password different from your current password.", "error")
        return render_template("auth/change_password.html"), 400

    user_id = current_user.get_id()

    # Record the request before changing the credential.
    try:
        append_audit_event(
            action="password_change",
            outcome="requested",
            user_id=user_id,
            details="Password change requested by authenticated user",
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Password change stopped because its audit request failed."
        )
        flash(
            "Password change is temporarily unavailable. Please try again.",
            "error",
        )
        return render_template("auth/change_password.html"), 503

    try:
        current_user.set_password(new_password)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Password update failed.")
        flash("The password could not be changed. Please try again.", "error")
        return render_template("auth/change_password.html"), 503

    try:
        append_audit_event(
            action="password_change",
            outcome="success",
            user_id=user_id,
            details="Password changed successfully",
        )
    except Exception:
        # The password has already changed; do not report that it failed.
        current_app.logger.exception(
            "Password changed, but the final audit event failed."
        )
        flash(
            "Password changed, but final audit recording failed. "
            "Please notify the administrator.",
            "warning",
        )
        return redirect(url_for("auth.profile"))

    flash("Your password has been changed successfully.", "success")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "GET":
        return render_template("auth/profile.html", user=current_user)

    new_username = request.form.get("username", "").strip()
    new_email = request.form.get("email", "").strip().lower()

    if not new_username or len(new_username) > 80:
        flash("Username must contain 1–80 characters.", "error")
        return render_template("auth/profile.html", user=current_user), 400

    if (
        not new_email
        or len(new_email) > 255
        or "@" not in new_email
        or new_email.startswith("@")
        or new_email.endswith("@")
    ):
        flash("Enter a valid email address.", "error")
        return render_template("auth/profile.html", user=current_user), 400

    if new_username != current_user.username:
        if User.query.filter_by(username=new_username).first():
            flash("That username is already taken.", "error")
            return render_template("auth/profile.html", user=current_user), 409

    if new_email != current_user.email:
        if User.query.filter_by(email=new_email).first():
            flash("That email address is already registered.", "error")
            return render_template("auth/profile.html", user=current_user), 409

    old_username = current_user.username
    old_email = current_user.email

    if new_username == old_username and new_email == old_email:
        flash("No changes were made to your profile.", "success")
        return redirect(url_for("auth.profile"))

    try:
        append_audit_event(
            action="profile_update",
            outcome="requested",
            user_id=current_user.get_id(),
            details=f"old_username={old_username!r};new_username={new_username!r};old_email={old_email!r};new_email={new_email!r}",
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Profile update stopped because audit request failed.")
        flash("Profile update is temporarily unavailable. Please try again.", "error")
        return render_template("auth/profile.html", user=current_user), 503

    current_user.username = new_username
    current_user.email = new_email

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Username or email already exists.", "error")
        return render_template("auth/profile.html", user=current_user), 409
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Profile update failed.")
        flash("Profile could not be updated. Please try again.", "error")
        return render_template("auth/profile.html", user=current_user), 503

    try:
        append_audit_event(
            action="profile_update",
            outcome="success",
            user_id=current_user.get_id(),
            details=f"username={new_username!r};email={new_email!r}",
        )
    except Exception:
        current_app.logger.exception("Profile updated, but final audit event failed.")
        flash("Profile updated, but final audit recording failed.", "warning")
        return redirect(url_for("auth.profile"))

    flash("Profile updated successfully.", "success")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    user_id = current_user.get_id()

    try:
        append_audit_event(
            action="logout",
            outcome="success",
            user_id=user_id,
            details="User logged out",
        )
    except Exception:
        current_app.logger.exception(
            "Could not record logout; clearing session anyway."
        )
        logout_user()
        flash(
            "You have been logged out, but the audit event could not be recorded.",
            "warning",
        )
        return redirect(url_for("auth.login"))

    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
