# Drop-in replacement for routes/auth.py
# Changes: login attempt logging, failed login tracking

from flask import render_template, request, redirect, session, flash, url_for
from dbs.sql_db import get_connection
from dbs.mongo_db import log_audit_event, log_failed_login

def register_auth_routes(app):
    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT u.user_id, u.username, u.full_name, r.role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.username = %s AND u.password_hash = %s AND u.is_active = TRUE;
            """, (username, password))
            user = cur.fetchone()

            if user:
                user_id, username, full_name, role_name, permissions = user
                cur.execute("UPDATE users SET last_login_at = NOW() WHERE user_id = %s;", (user_id,))
                conn.commit()
                session['user_id'] = user_id
                session['username'] = username
                session['full_name'] = full_name
                session['role'] = role_name
                session['permissions'] = permissions
                log_audit_event(user_id=user_id, action="LOGIN", object_type="session",
                                description=f"User {username} logged in", ip_address=request.remote_addr)
                cur.close(); conn.close()
                return redirect(url_for('dashboard'))
            else:
                cur.close(); conn.close()
                # Log failed attempt to MongoDB
                log_failed_login(
                    username=username,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')
                )
                return render_template("login.html", error="Invalid username or password")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        if 'user_id' in session:
            log_audit_event(user_id=session['user_id'], action="LOGOUT", object_type="session",
                            description=f"User {session['username']} logged out", ip_address=request.remote_addr)
        session.clear()
        return redirect(url_for('login'))
