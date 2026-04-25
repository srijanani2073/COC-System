from flask import Flask, session, redirect, url_for
from functools import wraps
import secrets
from datetime import datetime, timedelta, timezone

from routes.auth import register_auth_routes
from routes.cases import register_case_routes
from routes.evidence import register_evidence_routes
from routes.custody import register_custody_routes
from routes.other import register_other_routes
from routes.analytics import register_analytics_routes
from routes.experiments import register_experiments_route

# ── Demo-mode guard (read-only enforcement) ──────────────────────────────────
from routes.demo_guard import register_demo_guard

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

_IST = timezone(timedelta(hours=5, minutes=30))

def _to_ist(dt):
    """Convert a naive UTC datetime (from psycopg2) or aware datetime to IST."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(_IST)
    return dt

@app.template_filter('ist_dt')
def ist_dt_filter(dt, fmt='%d %b %Y, %H:%M'):
    """Render a UTC datetime as IST with the given format."""
    converted = _to_ist(dt)
    if converted is None:
        return '—'
    return converted.strftime(fmt)

@app.template_filter('ist_date')
def ist_date_filter(dt, fmt='%d %b %Y'):
    return ist_dt_filter(dt, fmt)

@app.template_filter('ist_time')
def ist_time_filter(dt, fmt='%H:%M'):
    return ist_dt_filter(dt, fmt)

@app.template_filter('ist_full')
def ist_full_filter(dt):
    return ist_dt_filter(dt, '%d %b %Y, %H:%M:%S')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in allowed_roles:
                from flask import flash
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

register_auth_routes(app)
register_case_routes(app, login_required, role_required)
register_evidence_routes(app, login_required, role_required)
register_custody_routes(app, login_required, role_required)
register_other_routes(app, login_required, role_required)
register_analytics_routes(app, login_required, role_required)

from routes.new_routes import register_crypto_page
register_crypto_page(app, login_required)

from routes.neo4j_explorer import register_neo4j_explorer
register_neo4j_explorer(app, login_required)

register_experiments_route(app, login_required)

# ── Register demo guard LAST (after all routes are defined) ──────────────────
register_demo_guard(app)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
