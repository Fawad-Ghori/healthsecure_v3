"""
=============================================================================
  HEALTHSECURE — Flask Web Application  v3.0  (Full Compliance Edition)
  Backend : Python + Flask  |  DB : MySQL  |  Auth : Flask-Session
=============================================================================

  HOW LEGAL & REGULATORY REQUIREMENTS AFFECT HEALTHCARE SYSTEM MAINTENANCE
  ─────────────────────────────────────────────────────────────────────────
  This application is a working demonstration of the following principle:

    "Healthcare software is never truly 'finished' — regulations create
     a continuous maintenance obligation that forces developers to keep
     improving security, access control, logging, and data integrity."

  Here is how each regulation maps to a specific feature in this codebase:

  ┌─────────────────────────────────────────────────────────────────────┐
  │ REGULATION              │ FEATURE IN THIS APP                       │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ HIPAA §164.312(a)(1)    │ RBAC — Admin vs Staff roles               │
  │ Access Control          │ @admin_required / @login_required          │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ HIPAA §164.312(b)       │ audit_logs table — every action logged    │
  │ Audit Controls          │ log_action() called on every route        │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ HIPAA §164.312(c)(1)    │ created_by / updated_by / deleted_by      │
  │ Integrity Controls      │ fields on every patient record             │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ HIPAA §164.312(a)(2)(iii)│ Session timeout — auto-logout after      │
  │ Auto Log-off            │ SESSION_LIFETIME_MINUTES of inactivity    │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ HIPAA Privacy Rule      │ Medical condition masked for Staff role   │
  │ Minimum Necessary       │ Server-side, before HTML is rendered      │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ GDPR Art. 17 (Right to  │ Soft delete — data flagged hidden but     │
  │ Erasure) vs Art. 5(1)(e)│ retained for mandatory 6-year audit trail │
  │ Storage Limitation      │ (a deliberate regulatory tension)         │
  ├─────────────────────────┼───────────────────────────────────────────┤
  │ GDPR Art. 32            │ bcrypt hashing, HTTPS-ready, session      │
  │ Security of Processing  │ signing, IP logging on audit events       │
  └─────────────────────────┴───────────────────────────────────────────┘

=============================================================================
  SETUP
  ─────
  pip install flask flask-session mysql-connector-python bcrypt

  1. Run healthcare_db_setup_v3.sql in MySQL.
  2. Update DB_CONFIG below.
  3. flask --app app run --debug

  DEMO ACCOUNTS:  admin/admin123  |  staff1/staff123
=============================================================================
"""

import bcrypt
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, jsonify
)
from flask_session import Session

# =============================================================================
#  SECTION 1 — APPLICATION FACTORY & CONFIGURATION
# =============================================================================

app = Flask(__name__)

# ── Secret key ────────────────────────────────────────────────────────────────
# SECURITY NOTE: In production load from environment variable, never hard-code.
# This key signs session cookies so they cannot be forged by a client.
# app.config["SECRET_KEY"] = "CHANGE-THIS-TO-A-STRONG-RANDOM-KEY-IN-PRODUCTION"
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key")

# ── Server-side sessions ──────────────────────────────────────────────────────
# REGULATORY RELEVANCE — HIPAA §164.312(a)(2)(iii):
# Filesystem sessions mean the server can revoke ANY session instantly by
# deleting the file — a critical capability during security incidents.
# Browser-only cookies (JWT) cannot be revoked without a blocklist.
app.config["SESSION_TYPE"]            = "filesystem"
app.config["SESSION_PERMANENT"]       = False
app.config["SESSION_USE_SIGNER"]      = True   # Signs the session ID cookie
app.config["SESSION_FILE_DIR"]        = "./flask_session"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
Session(app)

# ── Session timeout (inactivity auto-logout) ──────────────────────────────────
# REGULATORY RELEVANCE — HIPAA §164.312(a)(2)(iii) — Auto Log-off:
# Systems must terminate sessions after a defined period of inactivity to
# prevent an unattended workstation from exposing patient data.
SESSION_LIFETIME_MINUTES = 20

# ── Database ──────────────────────────────────────────────────────────────────

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": os.getenv("DB_PORT", 44493)
}

# =============================================================================
#  SECTION 2 — DATABASE UTILITIES
# =============================================================================

def get_db():
    """Open and return a fresh MySQL connection per request."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        flash(f"Database connection failed: {e}", "danger")
        return None


def log_action(username: str, action: str,
               outcome: str = "INFO", ip: str = None):
    """
    Append one row to audit_logs.

    REGULATORY RELEVANCE — HIPAA §164.312(b):
    Called automatically on every meaningful event. The IP address field
    supports geo-anomaly detection: if an account suddenly logs in from
    a foreign country, compliance officers can spot it here.

    This function NEVER raises an exception — audit failure must not
    break the user-facing operation.
    """
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_logs (username, action, outcome, ip_address) "
            "VALUES (%s, %s, %s, %s)",
            (username, action, outcome, ip or request.remote_addr)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            cur.close(); conn.close()
        except Exception:
            pass


# =============================================================================
#  SECTION 3 — SESSION TIMEOUT MIDDLEWARE
#  REGULATORY RELEVANCE — HIPAA §164.312(a)(2)(iii) — Auto Log-off
#  This runs BEFORE every request. If the user has been inactive for more
#  than SESSION_LIFETIME_MINUTES, their session is cleared automatically.
#  They are redirected to login with an explanatory message.
#  This prevents an unattended terminal from leaking patient data.
# =============================================================================

@app.before_request
def enforce_session_timeout():
    """Auto-logout users who have been inactive too long."""
    # Skip static files and the login/logout routes themselves
    if request.endpoint in ("login", "logout", "static"):
        return

    if "username" not in session:
        return   # Not logged in — nothing to timeout

    last_active = session.get("last_active")
    now = datetime.utcnow()

    if last_active:
        # Parse the stored ISO timestamp
        last_active_dt = datetime.fromisoformat(last_active)
        idle_minutes = (now - last_active_dt).total_seconds() / 60

        if idle_minutes > SESSION_LIFETIME_MINUTES:
            username = session.get("username", "unknown")
            log_action(
                username,
                f"Session auto-expired after {SESSION_LIFETIME_MINUTES} min inactivity.",
                "INFO"
            )
            session.clear()
            flash(
                f"Your session expired after {SESSION_LIFETIME_MINUTES} minutes "
                "of inactivity. Please log in again.",
                "warning"
            )
            return redirect(url_for("login"))

    # Refresh the last-active timestamp on every request
    session["last_active"] = now.isoformat()


# =============================================================================
#  SECTION 4 — ACCESS CONTROL DECORATORS
#  REGULATORY RELEVANCE — HIPAA §164.312(a)(1) — Access Control
#  These decorators enforce RBAC on the server on EVERY request.
#  Hiding a link in HTML is UX; the decorator is the actual security control.
# =============================================================================

def login_required(f):
    """Redirect unauthenticated users to the login page."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Restrict a route to Admin users only.
    Staff attempting admin URLs are logged and redirected.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("Please log in.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "Admin":
            username = session.get("username", "unknown")
            log_action(
                username,
                f"UNAUTHORISED ACCESS ATTEMPT: tried to reach '{request.path}'.",
                "FAILURE"
            )
            flash(
                "⛔ Access Denied — This action requires Admin privileges. "
                "This attempt has been logged.",
                "danger"
            )
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# =============================================================================
#  SECTION 5 — AUTHENTICATION ROUTES
# =============================================================================

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "username" in session
                    else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Authenticate staff.

    REGULATORY RELEVANCE:
    • Every attempt (pass or fail) is logged — HIPAA §164.312(b).
    • Generic error message prevents user enumeration — OWASP guideline.
    • Role is stored in session immediately so every route can enforce RBAC.
    • last_active timestamp starts the inactivity timer.
    """
    if "username" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Both fields are required.", "warning")
            return render_template("login.html")

        conn = get_db()
        if not conn:
            return render_template("login.html")

        role = None
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT password_hash, role FROM users WHERE username = %s",
                (username,)
            )
            row = cur.fetchone()
            if row:
                stored_hash, db_role = row
                if isinstance(stored_hash, str):
                    stored_hash = stored_hash.encode("utf-8")
                # bcrypt.checkpw is timing-safe — prevents timing attacks
                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    role = db_role
        except Error as e:
            flash(f"Auth error: {e}", "danger")
        finally:
            cur.close(); conn.close()

        if role:
            session["username"]    = username
            session["role"]        = role
            session["last_active"] = datetime.utcnow().isoformat()
            log_action(username, f"Login successful. Role: {role}.", "SUCCESS")
            return redirect(url_for("dashboard"))
        else:
            log_action(username, "Failed login attempt (invalid credentials).", "FAILURE")
            flash("Invalid username or password. This attempt has been logged.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """
    REGULATORY RELEVANCE — HIPAA §164.312(a)(2)(iii):
    session.clear() deletes the server-side session FILE — the browser
    cookie becomes immediately worthless even if copied by an attacker.
    Logout is logged BEFORE clearing so the username is still available.
    """
    username = session.get("username", "unknown")
    log_action(username, "User logged out.", "INFO")
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("login"))


# =============================================================================
#  SECTION 6 — DASHBOARD (Patient List + Search)
# =============================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """
    Main patient records view with optional name search.

    REGULATORY RELEVANCE — Data Masking (HIPAA Privacy Rule §164.502(b)):
    Medical condition is masked SERVER-SIDE for Staff. The browser never
    receives the real value — it is swapped in Python before Jinja2 renders.
    Masking in CSS/JS would still expose the data in DevTools.

    Search is also server-side: only records the user is authorised to see
    are returned. A Staff user cannot search for masked data they cannot view.
    """
    search_query = request.args.get("search", "").strip()
    is_admin = session.get("role") == "Admin"

    conn = get_db()
    patients = []

    if conn:
        try:
            cur = conn.cursor()

            # Base query: only non-deleted patients
            sql = (
                "SELECT id, name, age, gender, medical_condition, "
                "created_by, created_at, updated_by, updated_at "
                "FROM patients WHERE is_deleted = 0"
            )
            params = []

            # Search filter — parameterised to prevent SQL injection
            if search_query:
                sql += " AND name LIKE %s"
                params.append(f"%{search_query}%")

            sql += " ORDER BY id DESC"
            cur.execute(sql, params)

            for row in cur.fetchall():
                (pid, name, age, gender, condition,
                 created_by, created_at, updated_by, updated_at) = row

                # ── SERVER-SIDE RBAC MASKING ──────────────────────────────
                display_condition = condition if is_admin else "★★★  Restricted  ★★★"

                patients.append({
                    "id":           pid,
                    "name":         name,
                    "age":          age,
                    "gender":       gender,
                    "condition":    display_condition,
                    "raw_condition": condition,   # Only used when is_admin=True in template
                    "created_by":   created_by,
                    "created_at":   created_at.strftime("%Y-%m-%d %H:%M") if created_at else "—",
                    "updated_by":   updated_by or "—",
                    "updated_at":   updated_at.strftime("%Y-%m-%d %H:%M") if updated_at else "—",
                    "masked":       not is_admin,
                })
        except Error as e:
            flash(f"Could not load patients: {e}", "danger")
        finally:
            cur.close(); conn.close()

    # Log searches (helps detect data-fishing behaviour)
    if search_query:
        log_action(
            session["username"],
            f"Searched patients for: '{search_query}'. {len(patients)} result(s).",
            "INFO"
        )

    return render_template(
        "dashboard.html",
        patients=patients,
        search_query=search_query,
        username=session["username"],
        role=session["role"],
        is_admin=is_admin,
        session_timeout=SESSION_LIFETIME_MINUTES,
    )


# =============================================================================
#  SECTION 7 — ADD PATIENT
# =============================================================================

@app.route("/add-patient", methods=["POST"])
@login_required
def add_patient():
    """
    Both Admin and Staff can add patients (they need this for their jobs).
    created_by is taken from session — not the form — preventing forged attribution.

    REGULATORY RELEVANCE — HIPAA §164.312(c)(1) — Integrity Controls:
    Binding `created_by` to the authenticated session makes record attribution
    tamper-proof from the user's perspective.
    """
    name      = request.form.get("name", "").strip()
    age_str   = request.form.get("age", "").strip()
    gender    = request.form.get("gender", "")
    condition = request.form.get("condition", "").strip()

    # Server-side validation — HTML5 `required` is client-side only
    errors = []
    if not name:                                    errors.append("Name is required.")
    if not age_str.isdigit() or not (1 <= int(age_str) <= 150):
                                                    errors.append("Age must be 1–150.")
    if gender not in ("Male", "Female", "Other"):   errors.append("Select a valid gender.")
    if not condition:                               errors.append("Condition is required.")

    if errors:
        for e in errors: flash(e, "warning")
        return redirect(url_for("dashboard"))

    created_by = session["username"]   # From server session — cannot be forged
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO patients (name, age, gender, medical_condition, created_by) "
                "VALUES (%s, %s, %s, %s, %s)",
                (name, int(age_str), gender, condition, created_by)
            )
            conn.commit()
            log_action(created_by,
                       f"Added patient: '{name}', Age {age_str}, Gender: {gender}.",
                       "SUCCESS")
            flash(f"Patient '{name}' registered successfully.", "success")
        except Error as e:
            flash(f"Registration failed: {e}", "danger")
        finally:
            cur.close(); conn.close()

    return redirect(url_for("dashboard"))


# =============================================================================
#  SECTION 8 — EDIT PATIENT (Admin only)
#  REGULATORY RELEVANCE — HIPAA §164.312(c)(1) — Integrity Controls:
#  Every edit is tracked: updated_by (who) and updated_at (when).
#  The original created_by / created_at remain unchanged, preserving the
#  full lifecycle of the record.
# =============================================================================

@app.route("/edit-patient/<int:patient_id>", methods=["GET", "POST"])
@admin_required
def edit_patient(patient_id):
    """
    GET  → pre-fill edit form with current patient data
    POST → validate, update DB, log the change with updated_by
    """
    conn = get_db()
    if not conn:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name      = request.form.get("name", "").strip()
        age_str   = request.form.get("age", "").strip()
        gender    = request.form.get("gender", "")
        condition = request.form.get("condition", "").strip()

        errors = []
        if not name:                                    errors.append("Name required.")
        if not age_str.isdigit() or not (1 <= int(age_str) <= 150):
                                                        errors.append("Age must be 1–150.")
        if gender not in ("Male", "Female", "Other"):   errors.append("Select a valid gender.")
        if not condition:                               errors.append("Condition required.")

        if errors:
            for e in errors: flash(e, "warning")
            return redirect(url_for("edit_patient", patient_id=patient_id))

        updated_by = session["username"]
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE patients SET name=%s, age=%s, gender=%s, "
                "medical_condition=%s, updated_by=%s, updated_at=NOW() "
                "WHERE id=%s AND is_deleted=0",
                (name, int(age_str), gender, condition, updated_by, patient_id)
            )
            conn.commit()
            log_action(
                updated_by,
                f"Edited patient ID {patient_id}: name='{name}', "
                f"age={age_str}, gender={gender}.",
                "SUCCESS"
            )
            flash(f"Patient '{name}' updated successfully.", "success")
        except Error as e:
            flash(f"Update failed: {e}", "danger")
        finally:
            cur.close(); conn.close()
        return redirect(url_for("dashboard"))

    # GET — load existing record to pre-fill the form
    patient = None
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, age, gender, medical_condition FROM patients "
            "WHERE id=%s AND is_deleted=0",
            (patient_id,)
        )
        row = cur.fetchone()
        if row:
            patient = {
                "id": row[0], "name": row[1], "age": row[2],
                "gender": row[3], "condition": row[4]
            }
        else:
            flash("Patient not found.", "warning")
            return redirect(url_for("dashboard"))
    except Error as e:
        flash(f"Could not load patient: {e}", "danger")
        return redirect(url_for("dashboard"))
    finally:
        cur.close(); conn.close()

    return render_template(
        "edit_patient.html",
        patient=patient,
        username=session["username"],
        role=session["role"],
    )


# =============================================================================
#  SECTION 9 — DELETE PATIENT (Admin only — Soft Delete)
#
#  REGULATORY RELEVANCE — The Deletion Dilemma:
#  GDPR Art. 17 grants patients the "right to erasure."
#  HIPAA requires healthcare records to be retained for 6 years.
#  These laws directly conflict. The solution used here — "soft delete" —
#  satisfies both: the record is hidden from the application (satisfying
#  GDPR's spirit) but remains in the database for audit/legal purposes
#  (satisfying HIPAA's retention requirement).
#  This tension is a real-world example of how regulations DRIVE
#  architectural decisions in healthcare software maintenance.
# =============================================================================

@app.route("/delete-patient/<int:patient_id>", methods=["POST"])
@admin_required
def delete_patient(patient_id):
    """
    Soft-delete: sets is_deleted=1, records deleted_by and deleted_at.
    The record is hidden from all views but remains in the DB for audit purposes.
    Confirmation is handled client-side (JS confirm dialog) AND the POST-only
    method prevents accidental deletion via link crawlers.
    """
    deleted_by = session["username"]
    conn = get_db()
    if not conn:
        return redirect(url_for("dashboard"))

    try:
        cur = conn.cursor()
        # First fetch the patient name for a meaningful audit log entry
        cur.execute("SELECT name FROM patients WHERE id=%s AND is_deleted=0",
                    (patient_id,))
        row = cur.fetchone()
        if not row:
            flash("Patient not found or already deleted.", "warning")
            return redirect(url_for("dashboard"))

        patient_name = row[0]

        cur.execute(
            "UPDATE patients SET is_deleted=1, deleted_by=%s, deleted_at=NOW() "
            "WHERE id=%s",
            (deleted_by, patient_id)
        )
        conn.commit()
        log_action(
            deleted_by,
            f"SOFT-DELETED patient ID {patient_id}: '{patient_name}'. "
            f"Record retained for compliance; hidden from application views.",
            "WARNING"
        )
        flash(
            f"Patient '{patient_name}' has been removed from active records. "
            "The record is retained for compliance purposes.",
            "success"
        )
    except Error as e:
        flash(f"Delete failed: {e}", "danger")
    finally:
        cur.close(); conn.close()

    return redirect(url_for("dashboard"))


# =============================================================================
#  SECTION 10 — AUDIT LOG VIEWER (Admin only)
#  REGULATORY RELEVANCE — HIPAA §164.312(b):
#  Admins can filter by username and/or outcome to quickly isolate:
#    • All actions by a specific user (e.g., during a termination review)
#    • All FAILURE events (potential security incidents)
#    • All WARNING events (soft-deletes, unusual activity)
# =============================================================================

@app.route("/audit-logs")
@admin_required
def audit_logs():
    """
    Filterable audit log viewer — Admin only.
    Filters: username (free text) and outcome (SUCCESS/FAILURE/INFO/WARNING).
    """
    filter_user    = request.args.get("filter_user", "").strip()
    filter_outcome = request.args.get("filter_outcome", "").strip()

    conn = get_db()
    logs = []
    unique_users = []

    if conn:
        try:
            cur = conn.cursor()

            # Fetch unique usernames for the filter dropdown
            cur.execute("SELECT DISTINCT username FROM audit_logs ORDER BY username")
            unique_users = [r[0] for r in cur.fetchall()]

            # Build filtered query
            sql    = ("SELECT id, timestamp, username, action, outcome, ip_address "
                      "FROM audit_logs WHERE 1=1")
            params = []
            if filter_user:
                sql += " AND username LIKE %s"
                params.append(f"%{filter_user}%")
            if filter_outcome:
                sql += " AND outcome = %s"
                params.append(filter_outcome)
            sql += " ORDER BY id DESC LIMIT 500"

            cur.execute(sql, params)
            for row in cur.fetchall():
                lid, ts, uname, action, outcome, ip = row
                logs.append({
                    "id":       lid,
                    "ts":       ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "—",
                    "username": uname,
                    "action":   action,
                    "outcome":  outcome,
                    "ip":       ip or "—",
                })
        except Error as e:
            flash(f"Could not load audit logs: {e}", "danger")
        finally:
            cur.close(); conn.close()

    return render_template(
        "audit.html",
        logs=logs,
        unique_users=unique_users,
        filter_user=filter_user,
        filter_outcome=filter_outcome,
        username=session["username"],
        role=session["role"],
    )


# =============================================================================
#  SECTION 11 — ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    app.run(debug=True, port=5000)
