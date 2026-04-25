"""
mongo_db.py
========================================
Collections 

  audit_logs          action, case_id, description, ip_address, object_id,
                      object_type, timestamp, user_id

  case_activity_logs  actor_id(int), case_id(int), description, entity,
                      entity_id(int), event_type, timestamp

  case_logs           actor(null), case_id(int), description, entity,
                      entity_id(null), event_type, timestamp
                      — system/automated events with no actor

  custody_logs        evidence_id(int), from_user(int), to_user(int),
                      location, reason, timestamp

  evidence_metadata   evidence_id(int), case_id(int),
                      metadata{content_type,description,evidence_code,
                               evidence_tag,file_type,filename,hash,
                               is_new_version,notes,original_name,
                               public_url,size,source,storage,
                               storage_path,version},
                      created_at

  evidence_versions   case_id(int), content_hash, evidence_code,
                      evidence_id(int), file_hash, file_size(int),
                      filename, is_duplicate(bool), parent_version(int|null),
                      status, storage_path, uploaded_at, uploaded_by(int),
                      version(int)

  login_attempts      ip_address, success(bool), timestamp, user_agent,
                      user_id(int|null), username

  security_alerts     alert_type, attempt_count(int), description,
                      ip_address, severity, timestamp, username_attempted
"""

from pymongo import MongoClient, DESCENDING
from datetime import datetime, timedelta, timezone
import os

# IST = UTC+5:30
_IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    """Return current datetime in IST with tzinfo preserved.
    Stored as timezone-aware so JS new Date() parses the +05:30 offset correctly.
    """
    return datetime.now(_IST)

MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
  raise ValueError("MONGO_URI not set in environment variables")
      
client    = MongoClient(MONGO_URI)
db        = client["evidence_db"]


# ─────────────────────────────────────────────────────────────────────────────
#  audit_logs
#  Required: action, case_id, description, ip_address, object_id,
#            object_type, timestamp, user_id
# ─────────────────────────────────────────────────────────────────────────────
def log_audit_event(user_id, action, object_type, object_id=None,
                    case_id=None, description=None, ip_address=None):
    db.audit_logs.insert_one({
        "user_id":     int(user_id) if user_id is not None else 0,
        "action":      str(action),
        "object_type": str(object_type),
        "object_id":   object_id,          # int | str | null — allowed by schema
        "case_id":     int(case_id) if case_id is not None else None,
        "description": str(description) if description else "",
        "ip_address":  str(ip_address) if ip_address else None,
        "timestamp":   now_ist(),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  evidence_download_logs
#  Dedicated audit trail for every evidence file access attempt.
#  Separate from generic audit_logs so it can be queried independently
#  for chain-of-custody reporting.
# ─────────────────────────────────────────────────────────────────────────────
def log_evidence_download(
    user_id: int,
    username: str,
    evidence_id: int,
    evidence_code: str,
    case_id: int,
    filename: str,
    success: bool,
    failure_reason: str = None,
    ip_address: str = None,
    user_agent: str = None,
):
    """
    Record every download attempt — successful or not — with full context.

    Stored in its own MongoDB collection ('evidence_download_logs') so that
    chain-of-custody reports can query it directly without sifting through
    the general audit log.
    """
    db.evidence_download_logs.insert_one({
        "user_id":        int(user_id) if user_id is not None else 0,
        "username":       str(username) if username else "",
        "evidence_id":    int(evidence_id),
        "evidence_code":  str(evidence_code),
        "case_id":        int(case_id),
        "filename":       str(filename),
        "success":        bool(success),
        "failure_reason": str(failure_reason) if failure_reason else None,
        "ip_address":     str(ip_address) if ip_address else None,
        "user_agent":     str(user_agent) if user_agent else None,
        "timestamp":      now_ist(),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  case_activity_logs
#  Required: actor_id(int), case_id(int), description, entity,
#            entity_id(int), event_type, timestamp
# ─────────────────────────────────────────────────────────────────────────────
def log_case_activity(case_id, event_type, description,
                      entity=None, entity_id=None, actor_id=None):
    db.case_activity_logs.insert_one({
        "case_id":    int(case_id),
        "event_type": str(event_type),
        "entity":     str(entity) if entity else "",
        "entity_id":  int(entity_id) if entity_id is not None else 0,
        "description": str(description) if description else "",
        "actor_id":   int(actor_id) if actor_id is not None else 0,
        "timestamp":  now_ist(),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  case_logs  (automated / system events — actor is always null)
#  Required: actor(null), case_id(int), description, entity,
#            entity_id(null), event_type, timestamp
# ─────────────────────────────────────────────────────────────────────────────
def log_case_system_event(case_id, event_type, description, entity=""):
    """System-generated events with no actor (bulk verify, scheduled jobs, etc.)."""
    db.case_logs.insert_one({
        "case_id":    int(case_id),
        "event_type": str(event_type),
        "entity":     str(entity) if entity else "",
        "entity_id":  None,    # schema specifies null type
        "actor":      None,    # schema specifies null type
        "description": str(description) if description else "",
        "timestamp":  now_ist(),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  custody_logs
#  Required: evidence_id(int), from_user(int), to_user(int),
#            location, reason, timestamp
# ─────────────────────────────────────────────────────────────────────────────
def log_custody_activity(evidence_id, from_user, to_user, location, reason):
    db.custody_logs.insert_one({
        "evidence_id": int(evidence_id),
        "from_user":   int(from_user) if from_user is not None else 0,
        "to_user":     int(to_user)   if to_user   is not None else 0,
        "location":    str(location) if location else "",
        "reason":      str(reason)   if reason   else "",
        "timestamp":   now_ist(),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  evidence_metadata
#  Required: evidence_id(int), case_id(int), metadata{...}, created_at
# ─────────────────────────────────────────────────────────────────────────────
def store_evidence_metadata(evidence_id, case_id, metadata: dict):
    # Ensure metadata keys match the defined schema properties
    safe_meta = {
        "content_type":  metadata.get("content_type", ""),
        "description":   metadata.get("description", ""),
        "evidence_code": metadata.get("evidence_code", ""),
        "evidence_tag":  metadata.get("evidence_tag", ""),
        "file_type":     metadata.get("file_type", ""),
        "filename":      metadata.get("filename", ""),
        "hash":          metadata.get("hash", ""),
        "is_new_version": bool(metadata.get("is_new_version", False)),
        "notes":         metadata.get("notes", ""),
        "original_name": metadata.get("original_name", ""),
        "public_url":    metadata.get("public_url", ""),
        "size":          int(metadata.get("size", 0)) if metadata.get("size") else 0,
        "source":        metadata.get("source", ""),
        "storage":       metadata.get("storage", ""),
        "storage_path":  metadata.get("storage_path", ""),
        "version":       int(metadata.get("version", 1)),
    }
    safe_meta = {k: v for k, v in safe_meta.items() if v not in ("", False, 0) or k in ("version", "is_new_version", "size")}
    db.evidence_metadata.insert_one({
        "evidence_id": int(evidence_id),
        "case_id":     int(case_id),
        "metadata":    safe_meta,
        "created_at":  now_ist(),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  evidence_versions
#  All fields required; parent_version is int|null
# ─────────────────────────────────────────────────────────────────────────────
def store_evidence_version(evidence_id, case_id, evidence_code, file_hash,
                           file_size, filename, version, storage_path,
                           content_hash, uploaded_by, is_duplicate=False,
                           parent_version=None):
    db.evidence_versions.insert_one({
        "evidence_id":    int(evidence_id),
        "case_id":        int(case_id),
        "evidence_code":  str(evidence_code),
        "file_hash":      str(file_hash)      if file_hash      else "",
        "content_hash":   str(content_hash)   if content_hash   else str(file_hash) if file_hash else "",
        "filename":       str(filename)       if filename       else "",
        "file_size":      int(file_size)      if file_size      else 0,
        "version":        int(version),
        "is_duplicate":   bool(is_duplicate),
        "parent_version": int(parent_version) if parent_version is not None else None,
        "status":         "active",
        "storage_path":   str(storage_path)   if storage_path   else "",
        "uploaded_at":    now_ist(),
        "uploaded_by":    int(uploaded_by),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  login_attempts
#  Required: ip_address, success(bool), timestamp, user_agent,
#            user_id(int|null), username
# ─────────────────────────────────────────────────────────────────────────────
def log_login_attempt(username, user_id, ip_address, user_agent, success):
    db.login_attempts.insert_one({
        "username":   str(username)   if username   else "",
        "user_id":    int(user_id)    if user_id    is not None else None,
        "ip_address": str(ip_address) if ip_address else "",
        "user_agent": str(user_agent) if user_agent else "",
        "success":    bool(success),
        "timestamp":  now_ist(),
    })
    # Brute-force detection on failed logins
    if not success:
        cutoff       = now_ist() - timedelta(minutes=10)
        failed_count = db.login_attempts.count_documents({
            "ip_address": ip_address,
            "success":    False,
            "timestamp":  {"$gte": cutoff},
        })
        if failed_count >= 5:
            existing = db.security_alerts.find_one({
                "alert_type": "brute_force",
                "ip_address": str(ip_address),
                "timestamp":  {"$gte": cutoff},
            })
            if not existing:
                # security_alerts — all fields required, none nullable
                db.security_alerts.insert_one({
                    "alert_type":         "brute_force",
                    "severity":           "high",
                    "ip_address":         str(ip_address),
                    "username_attempted": str(username) if username else "",
                    "attempt_count":      int(failed_count),
                    "description": (
                        f"Brute-force suspected: {failed_count} failed logins "
                        f"from {ip_address} in 10 min"
                    ),
                    "timestamp": now_ist(),
                })


# ─────────────────────────────────────────────────────────────────────────────
#  READ helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_case_timeline(case_id=None):
    """Recent activity from case_activity_logs, newest first."""
    query  = {"case_id": int(case_id)} if case_id else {}
    events = db.case_activity_logs.find(query).sort("timestamp", DESCENDING).limit(100)
    return [{
        "event_type":  e.get("event_type"),
        "description": e.get("description"),
        "entity":      e.get("entity"),
        "entity_id":   e.get("entity_id"),
        "actor_id":    e.get("actor_id"),
        "timestamp":   e.get("timestamp"),
        "case_id":     e.get("case_id"),
    } for e in events]


def get_failed_login_attempts(limit=20):
    """Recent failed login attempts from login_attempts collection."""
    attempts = (
        db.login_attempts
        .find({"success": False})
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    return [{
        "username":   a.get("username"),
        "ip_address": a.get("ip_address"),
        "timestamp":  a.get("timestamp"),
        "user_agent": a.get("user_agent"),
    } for a in attempts]


def get_security_alerts(limit=30):
    """Security alerts from security_alerts collection."""
    alerts = db.security_alerts.find().sort("timestamp", DESCENDING).limit(limit)
    return [{
        "alert_type":         a.get("alert_type"),
        "severity":           a.get("severity"),
        "description":        a.get("description"),
        "ip_address":         a.get("ip_address"),
        "username_attempted": a.get("username_attempted"),
        "attempt_count":      a.get("attempt_count"),
        "timestamp":          a.get("timestamp"),
    } for a in alerts]


def get_alerts():
    """Composite alerts list for the alerts page."""
    alerts = []

    # 1. Missing custody — evidence uploaded but never transferred
    evidence_events      = list(db.case_activity_logs.find({
        "event_type": {"$in": ["evidence_uploaded", "evidence_version_uploaded"]}
    }))
    custody_evidence_ids = {c["evidence_id"] for c in db.custody_logs.find()}
    for ev in evidence_events:
        if ev.get("entity_id") not in custody_evidence_ids:
            alerts.append({
                "type":        "missing_custody",
                "severity":    "medium",
                "description": f"Evidence {ev.get('entity_id')} has no custody record",
                "evidence_id": ev.get("entity_id"),
                "timestamp":   ev.get("timestamp"),
            })

    # 2. Duplicate upload attempts (logged to audit_logs with action DUPLICATE_UPLOAD_BLOCKED)
    for dup in (db.audit_logs
                .find({"action": "DUPLICATE_UPLOAD_BLOCKED"})
                .sort("timestamp", DESCENDING)
                .limit(20)):
        alerts.append({
            "type":        "duplicate_attempt",
            "severity":    "low",
            "description": f"Duplicate upload blocked for evidence {dup.get('object_id')}",
            "evidence_id": dup.get("object_id"),
            "user_id":     dup.get("user_id"),
            "timestamp":   dup.get("timestamp"),
        })

    # 3. Duplicate version files
    for dup in (db.evidence_versions
                .find({"is_duplicate": True})
                .sort("uploaded_at", DESCENDING)
                .limit(20)):
        alerts.append({
            "type":          "version_duplicate",
            "severity":      "low",
            "description":   f"Duplicate file: {dup.get('evidence_code')} v{dup.get('version')}",
            "evidence_code": dup.get("evidence_code"),
            "case_id":       dup.get("case_id"),
            "filename":      dup.get("filename"),
            "timestamp":     dup.get("uploaded_at"),
        })

    # 4. Rapid versioning — 3+ versions of same evidence uploaded today
    today = now_ist().replace(hour=0, minute=0, second=0, microsecond=0)
    for rv in db.evidence_versions.aggregate([
        {"$match": {"is_duplicate": False, "uploaded_at": {"$gte": today}}},
        {"$group": {
            "_id":           {"evidence_code": "$evidence_code", "case_id": "$case_id"},
            "version_count": {"$sum": 1},
            "latest_upload": {"$max": "$uploaded_at"},
        }},
        {"$match": {"version_count": {"$gte": 3}}},
    ]):
        alerts.append({
            "type":          "rapid_versioning",
            "severity":      "medium",
            "description":   f"Multiple versions ({rv['version_count']}) uploaded today for {rv['_id']['evidence_code']}",
            "evidence_code": rv["_id"]["evidence_code"],
            "case_id":       rv["_id"]["case_id"],
            "version_count": rv["version_count"],
            "timestamp":     rv.get("latest_upload"),
        })

    # 5. Security alerts (brute-force etc.)
    for sa in db.security_alerts.find().sort("timestamp", DESCENDING).limit(10):
        alerts.append({
            "type":        "security",
            "severity":    sa.get("severity", "high"),
            "description": sa.get("description"),
            "ip_address":  sa.get("ip_address"),
            "timestamp":   sa.get("timestamp"),
        })

    alerts.sort(key=lambda x: x.get("timestamp") or datetime.min, reverse=True)
    return alerts[:50]


def get_recent_activity_for_user(user_id, limit=10):
    events = (
        db.case_activity_logs
        .find({"actor_id": int(user_id)})
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    return [{
        "event_type":  e.get("event_type"),
        "description": e.get("description"),
        "timestamp":   e.get("timestamp"),
        "case_id":     e.get("case_id"),
    } for e in events]


def get_recent_activity_all(limit=10):
    events = db.case_activity_logs.find().sort("timestamp", DESCENDING).limit(limit)
    return [{
        "event_type":  e.get("event_type"),
        "description": e.get("description"),
        "timestamp":   e.get("timestamp"),
        "case_id":     e.get("case_id"),
        "actor_id":    e.get("actor_id"),
    } for e in events]


# Backwards-compat aliases
def get_user_activity(actor_id, limit=8):
    return get_recent_activity_for_user(actor_id, limit)

def get_all_recent_activity(limit=8):
    return get_recent_activity_all(limit)
