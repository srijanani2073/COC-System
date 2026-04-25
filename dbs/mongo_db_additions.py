# Additions to mongo_db.py — paste these functions into dbs/mongo_db.py

def log_failed_login(username, ip_address, user_agent=None):
    db.failed_logins.insert_one({
        "username": username,
        "ip": ip_address,
        "user_agent": user_agent,
        "timestamp": datetime.utcnow()
    })

def get_failed_logins(limit=50):
    """Return recent failed login attempts with per-IP count."""
    from pymongo import DESCENDING
    raw = list(db.failed_logins.find().sort("timestamp", DESCENDING).limit(limit))
    results = []
    for r in raw:
        results.append({
            "username": r.get("username"),
            "ip": r.get("ip"),
            "timestamp": r.get("timestamp"),
            "count": db.failed_logins.count_documents({"ip": r.get("ip")})
        })
    return results

def get_user_activity(actor_id, limit=8):
    """Get recent activity for a specific user."""
    events = db.case_activity_logs.find({"actor_id": actor_id}).sort("timestamp", -1).limit(limit)
    return [{"event_type": e.get("event_type"), "description": e.get("description"),
             "timestamp": e.get("timestamp"), "actor_id": e.get("actor_id")} for e in events]

def get_all_recent_activity(limit=8):
    """Get recent activity across all users."""
    events = db.case_activity_logs.find().sort("timestamp", -1).limit(limit)
    return [{"event_type": e.get("event_type"), "description": e.get("description"),
             "timestamp": e.get("timestamp"), "actor_id": e.get("actor_id")} for e in events]
