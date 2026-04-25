from flask import render_template, request, redirect, session, flash, url_for
from dbs.sql_db import get_connection
from dbs.mongo_db import log_audit_event, log_login_attempt
from datetime import datetime
import bcrypt
import os

# ---------------------------------------------------------------------------
# Demo-mode credentials
# Set DEMO_MODE=true + DEMO_PASSWORD=<something> in your Vercel env vars.
# The demo user gets role='Admin' so every page renders with full data,
# but the demo_guard blocks all actual write operations.
# ---------------------------------------------------------------------------
DEMO_MODE     = os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")
DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "demo")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo1234")


def register_auth_routes(app):
    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ip       = request.remote_addr
            ua       = request.headers.get("User-Agent", "")

            # ── Demo login ───────────────────────────────────────────────────
            # Give the demo user role='Admin' so every role_required gate
            # passes and all pages render with full data.
            # Writes are still blocked by the demo_guard (which checks
            # session['is_demo'], not the role name).
            if DEMO_MODE and username == DEMO_USERNAME and password == DEMO_PASSWORD:
                session['user_id']   = 0
                session['username']  = DEMO_USERNAME
                session['full_name'] = "Demo Viewer"
                session['role']      = "Admin"        # ← full view access
                session['permissions'] = []
                session['is_demo']   = True            # ← write-block flag
                return redirect(url_for('dashboard'))

            # ── Normal DB login ──────────────────────────────────────────────
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute("""
                SELECT u.user_id, u.username, u.full_name, r.role_name, r.permissions,
                       u.password_hash
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.username = %s AND u.is_active = TRUE;
            """, (username,))
            row = cur.fetchone()

            user = None
            if row:
                user_id, username_db, full_name, role_name, permissions, stored_hash = row
                try:
                    if stored_hash and stored_hash.startswith("$2"):
                        if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                            user = (user_id, username_db, full_name, role_name, permissions)
                    else:
                        import hashlib
                        if stored_hash == hashlib.sha256(password.encode()).hexdigest():
                            new_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                            cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s;",
                                        (new_hash, user_id))
                            conn.commit()
                            user = (user_id, username_db, full_name, role_name, permissions)
                except Exception:
                    user = None

            if user:
                user_id, username_db, full_name, role_name, permissions = user
                cur.execute("UPDATE users SET last_login_at = NOW() WHERE user_id = %s;", (user_id,))
                conn.commit()
                session['user_id']    = user_id
                session['username']   = username_db
                session['full_name']  = full_name
                session['role']       = role_name
                session['permissions'] = permissions
                session['is_demo']    = False

                log_login_attempt(username=username_db, user_id=user_id,
                                  ip_address=ip, user_agent=ua, success=True)
                log_audit_event(user_id=user_id, action="LOGIN", object_type="session",
                                description=f"User {username_db} logged in", ip_address=ip)
                cur.close(); conn.close()
                return redirect(url_for('dashboard'))
            else:
                log_login_attempt(username=username, user_id=None,
                                  ip_address=ip, user_agent=ua, success=False)
                cur.close(); conn.close()
                flash('Invalid username or password', 'error')
                return render_template("login.html", error="Invalid username or password")

        return render_template("login.html", demo_mode=DEMO_MODE,
                               demo_user=DEMO_USERNAME if DEMO_MODE else None)

    @app.route("/logout")
    def logout():
        if 'user_id' in session:
            try:
                log_audit_event(user_id=session['user_id'], action="LOGOUT",
                                object_type="session",
                                description=f"User {session['username']} logged out",
                                ip_address=request.remote_addr)
            except Exception:
                pass
        session.clear()
        return redirect(url_for('login'))
