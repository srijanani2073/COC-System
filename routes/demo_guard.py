"""
demo_guard.py  –  Read-only / demo-mode middleware for the digital evidence platform.

How it works
------------
1. A single environment variable DEMO_MODE=true activates guard mode.
2. On every incoming request the before_request hook checks whether the
   request is a state-changing operation (POST / PUT / PATCH / DELETE or
   any GET url that is known to trigger a write).
3. If it is, the request is aborted and the user gets a friendly "demo mode"
   flash message instead of an error.
4. A global template variable `demo_mode` is injected so templates can hide
   or dim action buttons without touching any route logic.
"""

import os
from flask import request, flash, redirect, url_for, g

# ---------------------------------------------------------------------------
# Routes that are GET but still trigger writes (seal, verify, download-log…)
# Add any extra paths here if needed.
# ---------------------------------------------------------------------------
_WRITE_GET_PREFIXES = (
    "/evidence/",   # seal / unseal / verify / signed-url are POST, but keep as safety net
)

# Routes that must remain fully functional in demo mode (login, static, APIs
# that are read-only).
_ALWAYS_ALLOWED = {
    "/",            # login page
    "/logout",
    "/dashboard",
    "/cases",
    "/evidence",
    "/custody",
    "/timeline",
    "/reports",
    "/alerts",
    "/users",
    "/analytics",
    "/crypto",
    "/neo4j",
    "/experiments",
}

_ALWAYS_ALLOWED_PREFIXES = (
    "/static/",
    "/analytics",
    "/api/evidence/",   # read-only bulk-verify GET + custody graph GET
    "/api/custody/",
    "/evidence/api/",
    "/neo4j",
)

DEMO_MODE = os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")


def _is_write_request() -> bool:
    """Return True if this request would modify data."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    # GET routes that are still write-adjacent (none in this app currently,
    # but this future-proofs the guard).
    return False


def _is_allowed_in_demo() -> bool:
    """Return True if the request should proceed even in demo mode."""
    path = request.path
    if path in _ALWAYS_ALLOWED:
        return True
    for prefix in _ALWAYS_ALLOWED_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def register_demo_guard(app):
    """Call this once in app.py – after all routes are registered."""

    @app.before_request
    def block_writes_in_demo():
        if not DEMO_MODE:
            return  # guard is off; proceed normally

        if _is_write_request() and not _is_allowed_in_demo():
            flash(
                "🔒 Demo mode – this is a read-only showcase. "
                "All data-changing actions are disabled. "
                "Contact us to request the full project.",
                "warning",
            )
            # Redirect back to the referring page, or dashboard as fallback.
            referrer = request.referrer
            if referrer:
                return redirect(referrer)
            return redirect(url_for("dashboard"))

    @app.context_processor
    def inject_demo_flag():
        """Makes `demo_mode` available in every Jinja template."""
        return {"demo_mode": DEMO_MODE}
