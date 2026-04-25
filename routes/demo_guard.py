"""
demo_guard.py  –  Read-only / demo-mode middleware for the digital evidence platform.

How it works
------------
1.  DEMO_MODE=true in env activates the guard globally.
2.  When the demo user logs in (auth.py) they get:
        session['role']    = 'Admin'    → every role_required gate passes
        session['is_demo'] = True       → this guard uses to block writes
3.  before_request blocks every POST/PUT/PATCH/DELETE for demo sessions.
    AJAX/fetch callers get a 403 JSON response.
    Form submitters get a flash + redirect back.
4.  context_processor injects demo_mode=True into every template so
    the layout can show the banner, dim buttons, and patch fetch/XHR.
"""

import os
from flask import request, flash, redirect, url_for, session, jsonify

DEMO_MODE = os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")

# POST to "/" (login) must always work
_WRITE_WHITELIST = {"/", "/logout"}


def _this_is_demo_session() -> bool:
    """True when the current session belongs to the demo user."""
    return bool(session.get("is_demo", False))


def register_demo_guard(app):
    """Call once in app.py AFTER all routes are registered."""

    @app.before_request
    def block_writes_in_demo():
        # Guard only active when DEMO_MODE env var is set
        if not DEMO_MODE:
            return

        # Only intercept write methods
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return

        # Login form must keep working
        if request.path in _WRITE_WHITELIST:
            return

        # Only block demo-session users (real Admin logins still work)
        if not _this_is_demo_session():
            return

        # ── AJAX / fetch callers (return JSON 403) ────────────────────────
        if (
            request.is_json
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.path.startswith("/api/")
            or request.headers.get("Accept", "").startswith("application/json")
        ):
            return jsonify({
                "error": "demo_mode",
                "message": (
                    "Read-only demo — write operations are disabled. "
                    "Email srijanani.s2025@amrita.edu to request the full project."
                )
            }), 403

        # ── Regular form POST (flash + redirect) ──────────────────────────
        flash(
            "🔒 Read-only demo — write operations are disabled. "
            "Email srijanani.s2025@amrita.edu to request the full project.",
            "warning",
        )
        referrer = request.referrer
        if referrer:
            return redirect(referrer)
        return redirect(url_for("dashboard"))

    @app.context_processor
    def inject_demo_flag():
        """
        Injects into every template:
          demo_mode  – True when DEMO_MODE env is set (controls banner/JS)
          is_demo    – True when *this session* is the demo user
        """
        is_demo_session = _this_is_demo_session() if DEMO_MODE else False
        return {
            "demo_mode": DEMO_MODE,
            "is_demo":   is_demo_session,
        }
