"""
ECMS Simulation Script
======================
Generates realistic test data across ALL databases.

PostgreSQL tables populated:
  users, cases, evidence, coc_logs,
  evidence_verification_history, audit_logs

MongoDB collections populated:
  audit_logs, case_activity_logs, custody_logs,
  evidence_metadata, evidence_versions,
  login_attempts, security_alerts

Neo4j synced:
  User, Evidence, Case, CustodyEvent nodes + relationships

Injected anomalies (cyber paper experiments):
  50  tampered hashes     -> Experiment 1
  30  broken chain gaps   -> Experiment 2
  10  custody cycles      -> Experiment 2
  20  insider misuse sets -> Experiment 3

Usage:
  python3 simulate_data.py           # full run
  python3 simulate_data.py --clear   # wipe sim data, re-run
  python3 simulate_data.py --stats   # print DB counts only
"""

import os, sys, random, hashlib, string, argparse
import bcrypt
from datetime import datetime, timedelta, timezone
from dbs.sql_db   import get_connection
from dbs.neo4j_db import driver, NEO4J_DATABASE
from dbs.mongo_db import db   # pymongo db handle
from dbs.supabase_storage import supabase, upload_encrypted_bytes_to_supabase
from cyber.crypto_pipeline import crypto_pipeline

# Pre-generate bcrypt hashes for sim passwords (cost 10; cached to avoid per-user delay)
_bcrypt_cache: dict = {}

def _bcrypt_hash(plaintext: str) -> str:
    """Return a bcrypt hash for plaintext, using a cache so bulk simulation is fast."""
    if plaintext not in _bcrypt_cache:
        _bcrypt_cache[plaintext] = bcrypt.hashpw(
            plaintext.encode("utf-8"), bcrypt.gensalt(rounds=10)
        ).decode("utf-8")
    return _bcrypt_cache[plaintext]

# ── Config ─────────────────────────────────────────────────────────────────────
N_USERS    = 200
N_CASES    = 50
N_EVIDENCE = 1000
N_CUSTODY  = 3000

N_TAMPERED = 50
N_BROKEN   = 30
N_CYCLES   = 10
N_INSIDER  = 20

# Fraction of cases that get at least one external access grant
CASE_ACCESS_COVERAGE  = 0.75
# Min/max grants per covered case
CASE_ACCESS_PER_CASE  = (1, 4)
# External roles eligible for case_access grants
RESTRICTED_ROLES      = ("Lawyer", "Prosecutor", "Judge")

SIM_TAG = "[SIM]"

# ── Reference data ─────────────────────────────────────────────────────────────

EVIDENCE_TYPES = ["digital", "physical"]

DIGITAL_EXTS = ["pdf", "docx", "jpg", "png", "mp4", "csv", "log", "dd", "sql", "xlsx"]
DIGITAL_MIMES = {
    "pdf":  "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "jpg":  "image/jpeg",
    "png":  "image/png",
    "mp4":  "video/mp4",
    "csv":  "text/csv",
    "log":  "text/plain",
    "dd":   "application/octet-stream",
    "sql":  "application/sql",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
PHYSICAL_ITEMS = [
    "Hard Drive", "USB Drive", "Mobile Phone", "Laptop", "SIM Card",
    "Memory Card", "Printed Document", "CD/DVD", "Server HDD", "Network Device",
    "CCTV Tape", "Handwritten Note", "Biometric Device", "Router", "Smart Watch",
]

CASE_STATUSES   = ["open", "open", "open", "closed", "archived"]
CASE_CATEGORIES = [
    "cybercrime", "financial_fraud", "data_breach", "identity_theft",
    "corporate_espionage", "ransomware", "phishing", "insider_threat",
]

COC_ACTIONS = ["transfer", "store", "verify", "access", "examine"]

TRANSFER_REASONS = [
    "Transferring for forensic analysis",
    "Court submission required",
    "Secondary verification needed",
    "Evidence review by senior officer",
    "Handover to investigating officer",
    "Lab processing complete - returning",
    "Chain of custody documentation",
    "Supervisor review and sign-off",
    "Inter-department transfer",
    "Digital copy for archival",
]
LOCATIONS = [
    "Forensic Lab A", "Cyber Cell", "Evidence Room 1", "Court Registry",
    "Storage Vault B", "Digital Forensics Unit", "Evidence Room 2", "Field Office",
    "Secure Server Room", "Legal Department",
]
FIRST_NAMES = [
    "Arjun","Priya","Karthik","Meena","Rahul","Divya","Vikram","Anjali",
    "Suresh","Lakshmi","Ravi","Kavitha","Arun","Shalini","Deepak","Uma",
    "Senthil","Nithya","Ganesh","Revathi","Manoj","Pooja","Rajesh","Saranya",
    "Bharath","Geetha","Naveen","Mythili","Siva","Padma","Harish","Malathi",
]
LAST_NAMES = [
    "Kumar","Sharma","Reddy","Nair","Pillai","Rao","Iyer","Krishnan",
    "Murugan","Chandra","Venkat","Balan","Sundar","Rajan","Mohan","Patel",
]
FAKE_IPS = [
    f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 [SIM]",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/537 [SIM]",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121 [SIM]",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari/604 [SIM]",
]

# ── Simulated evidence file content generators ─────────────────────────────────
# These produce realistic-looking text file content for digital evidence items.
# Files are hashed, RSA-signed, AES-encrypted, and uploaded to Supabase storage.

_INVESTIGATORS = ["Arjun Kumar", "Priya Reddy", "Karthik Nair", "Meena Sharma", "Rahul Iyer"]
_CASE_TYPES = ["cybercrime", "financial fraud", "data breach", "ransomware", "insider threat"]

# ── Helpers ────────────────────────────────────────────────────────────────────
def rnd_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

def rnd_hash():
    return hashlib.sha256(
        ''.join(random.choices(string.ascii_letters + string.digits, k=64)).encode()
    ).hexdigest()

def rnd_past_dt(days_back=365):
    return datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, days_back * 1440))

def off_hour_dt():
    base = rnd_past_dt(90)
    return base.replace(hour=random.choice([23, 0, 1, 2, 3]),
                        minute=random.randint(0, 59))

def progress(label, i, total):
    pct = int((i / total) * 40)
    bar = "X" * pct + "." * (40 - pct)
    print(f"\r  {label:24s} [{bar}] {i}/{total}", end="", flush=True)
    if i == total:
        print()

def _write_ids(name, ids):
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sim_results")
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, f"{name}.txt"), "w") as f:
        f.write("\n".join(str(i) for i in ids))

def _neo4j_sync_coc_rows(rows, extra_props=None):
    """
    Sync a list of (log_id, ev_id, from_uid, to_uid, ts, action, reason, location) tuples to Neo4j as CustodyEvents.
    extra_props: dict of extra properties to set on each CustodyEvent node (e.g. {"anomaly": True}).
    Used by anomaly injection functions so their events are in the graph from the start.
    """
    if not rows:
        return
    extra_props = extra_props or {}
    prop_set = "".join(f", ce.{k} = ${k}" for k in extra_props)
    try:
        with driver.session(database=NEO4J_DATABASE) as s:
            for log_id, ev_id, from_uid, to_uid, ts, *extra in rows:
                params = {"fu": from_uid, "tu": to_uid, "eid": ev_id,
                          "lid": log_id, "ts": ts.isoformat() if hasattr(ts, "isoformat") else str(ts)}
                params.update(extra_props)
                s.run(f"""
                    MERGE (u1:User {{user_id: $fu}}) SET u1.sim = true
                    WITH u1
                    MERGE (u2:User {{user_id: $tu}}) SET u2.sim = true
                    WITH u1, u2
                    MATCH (e:Evidence {{evidence_id: $eid}})
                    MERGE (ce:CustodyEvent {{custody_id: $lid}})
                    SET ce.timestamp = $ts, ce.sim = true{prop_set}
                    MERGE (e)-[:HAS_CUSTODY_EVENT]->(ce)
                    MERGE (u1)-[:FROM]->(ce)
                    MERGE (ce)-[:TO]->(u2)
                """, params)
    except Exception as neo_err:
        print(f"  Neo4j sync warning: {{neo_err}}")

# ── Stats ──────────────────────────────────────────────────────────────────────
def print_stats():
    conn = get_connection(); cur = conn.cursor()
    sql_checks = [
        ("users (sim)",       "SELECT COUNT(*) FROM users    WHERE full_name LIKE '[SIM]%'"),
        ("cases (sim)",       "SELECT COUNT(*) FROM cases    WHERE title     LIKE '[SIM]%'"),
        ("evidence (sim)",    "SELECT COUNT(*) FROM evidence WHERE evidence_tag LIKE '[SIM]%'"),
        ("coc_logs (sim)",    "SELECT COUNT(*) FROM coc_logs WHERE action_description LIKE '[SIM]%'"),
        ("case_access (sim)", ("SELECT COUNT(*) FROM case_access ca "
                               "JOIN users u ON ca.granted_by = u.user_id "
                               "WHERE u.full_name LIKE '[SIM]%'")),
        ("evh (sim)",         ("SELECT COUNT(*) FROM evidence_verification_history evh "
                               "JOIN evidence e ON evh.evidence_id=e.evidence_id "
                               "WHERE e.evidence_tag LIKE '[SIM]%'")),
    ]
    print("\n-- PostgreSQL -----------------------------")
    for label, q in sql_checks:
        cur.execute(q); print(f"  {label:24s}: {cur.fetchone()[0]}")
    cur.close(); conn.close()

    print("\n-- MongoDB --------------------------------")
    mongo_checks = [
        ("audit_logs",         db.audit_logs.count_documents({"description": {"$regex": "^\\[SIM\\]"}})),
        ("case_activity_logs", db.case_activity_logs.count_documents({"description": {"$regex": "^\\[SIM\\]"}})),
        ("custody_logs",       db.custody_logs.count_documents({"reason": {"$regex": "^\\[SIM\\]"}})),
        ("evidence_metadata",  db.evidence_metadata.count_documents({"metadata.source": "simulation"})),
        ("evidence_versions",  db.evidence_versions.count_documents({"storage_path": {"$regex": "^sim/"}})),
        ("login_attempts",     db.login_attempts.count_documents({"user_agent": {"$regex": "\\[SIM\\]"}})),
        ("security_alerts",    db.security_alerts.count_documents({"description": {"$regex": "^\\[SIM\\]"}})),
    ]
    for label, count in mongo_checks:
        print(f"  {label:24s}: {count}")

# ── Clear ──────────────────────────────────────────────────────────────────────
def clear_sim_data():
    print("  Clearing previous simulation data...")
    conn = get_connection(); cur = conn.cursor()

    # Get a fallback non-sim user for NOT NULL FK columns
    cur.execute("SELECT user_id FROM users WHERE full_name NOT LIKE '[SIM]%' LIMIT 1;")
    row = cur.fetchone()
    fallback_user = row[0] if row else None

    if fallback_user:
        cur.execute(
            "UPDATE cases SET created_by = %s WHERE created_by IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%%') AND title NOT LIKE '[SIM]%%';",
            (fallback_user,)
        )
        cur.execute(
            "UPDATE evidence SET uploader_id = %s WHERE uploader_id IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%%') AND evidence_tag NOT LIKE '[SIM]%%';",
            (fallback_user,)
        )

    cur.execute("UPDATE evidence SET sealed_by = NULL WHERE sealed_by IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%');")

    # Clear sim case_access grants (granted_by a sim admin, or user is a sim user)
    cur.execute("""
        DELETE FROM case_access
        WHERE granted_by IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%')
           OR user_id    IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%');
    """)
    access_deleted = cur.rowcount

    cur.execute("DELETE FROM evidence_verification_history WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE evidence_tag LIKE '[SIM]%') OR verified_by IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%');")

    cur.execute("DELETE FROM coc_logs WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE evidence_tag LIKE '[SIM]%') OR from_user_id IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%') OR to_user_id IN (SELECT user_id FROM users WHERE full_name LIKE '[SIM]%');")

    cur.execute("DELETE FROM evidence WHERE evidence_tag LIKE '[SIM]%';")
    cur.execute("DELETE FROM cases WHERE title LIKE '[SIM]%';")
    cur.execute("DELETE FROM users WHERE full_name LIKE '[SIM]%';")

    try:
        cur.execute("SELECT MAX(case_id) FROM cases;")
        max_case = cur.fetchone()[0] or 1
        cur.execute("SELECT setval(pg_get_serial_sequence('cases', 'case_id'), %s, true);", (max_case,))

        cur.execute("SELECT MAX(evidence_id) FROM evidence;")
        max_ev = cur.fetchone()[0] or 1
        cur.execute("SELECT setval(pg_get_serial_sequence('evidence', 'evidence_id'), %s, true);", (max_ev,))

        cur.execute("SELECT MAX(log_id) FROM coc_logs;")
        max_log = cur.fetchone()[0] or 1
        cur.execute("SELECT setval(pg_get_serial_sequence('coc_logs', 'log_id'), %s, true);", (max_log,))

        cur.execute("SELECT MAX(verify_id) FROM evidence_verification_history;")
        max_ver = cur.fetchone()[0] or 1
        cur.execute("SELECT setval(pg_get_serial_sequence('evidence_verification_history', 'verify_id'), %s, true);", (max_ver,))
    except Exception as e:
        print(f"  Sequence reset warning (non-fatal): {e}")
        conn.rollback()

    conn.commit(); cur.close(); conn.close()

    db.audit_logs.delete_many({"description": {"$regex": "^\\[SIM\\]"}})
    db.case_activity_logs.delete_many({"description": {"$regex": "^\\[SIM\\]"}})
    db.custody_logs.delete_many({"reason": {"$regex": "^\\[SIM\\]"}})
    db.evidence_metadata.delete_many({"metadata.source": "simulation"})
    db.evidence_versions.delete_many({"storage_path": {"$regex": "^sim/"}})
    db.login_attempts.delete_many({"user_agent": {"$regex": "\\[SIM\\]"}})
    db.security_alerts.delete_many({"description": {"$regex": "^\\[SIM\\]"}})

    try:
        items = supabase.storage.from_("evidence-files").list("sim")
        if items:
            paths = []
            for item in items:
                if item.get("name"):
                    try:
                        sub = supabase.storage.from_("evidence-files").list(f"sim/{item['name']}")
                        for s2 in (sub or []):
                            if s2.get("name"):
                                try:
                                    sub2 = supabase.storage.from_("evidence-files").list(f"sim/{item['name']}/{s2['name']}")
                                    for s3 in (sub2 or []):
                                        if s3.get("name"):
                                            paths.append(f"sim/{item['name']}/{s2['name']}/{s3['name']}")
                                except Exception:
                                    paths.append(f"sim/{item['name']}/{s2['name']}")
                    except Exception:
                        paths.append(f"sim/{item['name']}")
            if paths:
                for k in range(0, len(paths), 100):
                    supabase.storage.from_("evidence-files").remove(paths[k:k+100])
                print(f"  Deleted {len(paths)} sim files from Supabase")
    except Exception as e:
        print(f"  Supabase clear warning: {e}")

    try:
        with driver.session(database=NEO4J_DATABASE) as s:
            s.run("MATCH (n) WHERE n.sim = true DETACH DELETE n;")
    except Exception as e:
        print(f"  Neo4j clear warning: {e}")

    print(f"  Cleared {access_deleted} sim case_access grants.")
    print("  Done.")

# ── Step 1 — Users ─────────────────────────────────────────────────────────────
# SQL  : users(full_name, username, email, password_hash, role_id, is_active,
#              created_at, last_login_at)
# Mongo: login_attempts(username, user_id, ip_address, user_agent, success, timestamp)
def create_users(n=N_USERS):
    print(f"\n[1/6] Creating {n} users...")
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT role_id, role_name FROM roles;")
    roles = {row[1]: row[0] for row in cur.fetchall()}
    role_names = list(roles.keys())

    # user_id has no sequence — must supply explicit IDs starting after max existing
    cur.execute("SELECT COALESCE(MAX(user_id), 0) FROM users;")
    next_uid = cur.fetchone()[0] + 1

    def weight(r):
        rl = r.lower()
        if "admin"   in rl: return 10
        if "invest"  in rl: return 40
        if "forensic" in rl or "analyst" in rl: return 30
        return 20
    weights = [weight(r) for r in role_names]

    user_ids = []; mongo_attempts = []
    for i in range(1, n + 1):
        uid       = next_uid; next_uid += 1
        name      = f"{SIM_TAG} {rnd_name()}"
        username  = f"sim_u{i}_{random.randint(100,999)}"
        email     = f"sim{i}_{random.randint(1000,9999)}@ecms.sim"
        pw_hash   = _bcrypt_hash(f"simpass{i}")
        role_id   = roles[random.choices(role_names, weights=weights)[0]]
        created   = rnd_past_dt(400)
        last_login = rnd_past_dt(30) if random.random() < 0.7 else None
        if last_login and last_login < created:
            last_login = created + timedelta(hours=random.randint(1, 24))

        cur.execute("""
            INSERT INTO users
                (user_id, full_name, username, email, password_hash, role_id,
                 is_active, created_at, last_login_at)
            VALUES (%s,%s,%s,%s,%s,%s,TRUE,%s,%s)
            RETURNING user_id;
        """, (uid, name, username, email, pw_hash, role_id, created, last_login))
        user_ids.append(cur.fetchone()[0])

        for _ in range(random.randint(1, 3)):
            success = random.random() < 0.85
            mongo_attempts.append({
                "username":   username,
                "user_id":    uid,
                "ip_address": random.choice(FAKE_IPS),
                "user_agent": random.choice(USER_AGENTS),
                "success":    success,
                "timestamp":  rnd_past_dt(60),
            })
        progress("Users", i, n)

    conn.commit(); cur.close(); conn.close()
    if mongo_attempts: db.login_attempts.insert_many(mongo_attempts)
    print(f"  + {len(user_ids)} SQL users, {len(mongo_attempts)} login_attempts")
    return user_ids


# ── Step 2 — Cases ─────────────────────────────────────────────────────────────
# SQL  : cases(title, description, status, case_category, created_by, created_at)
#        case_number is set by trigger — NOT inserted
# Mongo: case_activity_logs(case_id, event_type, entity, entity_id,
#                            description, actor_id, timestamp)
def create_cases(user_ids, n=N_CASES):
    print(f"\n[2/6] Creating {n} cases...")
    conn = get_connection(); cur = conn.cursor()
    case_ids = []; mongo_activity = []

    for i in range(1, n + 1):
        cat     = random.choice(CASE_CATEGORIES)
        title   = f"{SIM_TAG} {cat.replace('_',' ').title()} Case #{i:04d}"
        desc    = f"Simulated case for experimental evaluation. Category: {cat}."
        status  = random.choice(CASE_STATUSES)
        creator = random.choice(user_ids)
        created = rnd_past_dt(350)

        cur.execute("""
            INSERT INTO cases
                (title, description, status, case_category, created_by, created_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            RETURNING case_id;
        """, (title, desc, status, cat, creator, created))
        cid = cur.fetchone()[0]; case_ids.append(cid)

        mongo_activity.append({
            "case_id": cid, "event_type": "case_opened",
            "entity": "case", "entity_id": cid,
            "description": f"{SIM_TAG} Case opened: {title}",
            "actor_id": creator, "timestamp": created,
        })
        if status != "open":
            mongo_activity.append({
                "case_id": cid, "event_type": "case_status_changed",
                "entity": "case", "entity_id": cid,
                "description": f"{SIM_TAG} Case status changed to {status}",
                "actor_id": random.choice(user_ids),
                "timestamp": created + timedelta(days=random.randint(1, 30)),
            })
        progress("Cases", i, n)

    conn.commit(); cur.close(); conn.close()
    if mongo_activity: db.case_activity_logs.insert_many(mongo_activity)
    print(f"  + {len(case_ids)} SQL cases, {len(mongo_activity)} case_activity_logs")
    return case_ids


# ── Step 3 — Evidence ──────────────────────────────────────────────────────────
# Mirrors the EXACT logic of routes/evidence.py → add_evidence POST:
#
#  Rules enforced:
#   BLOCKED  : case closed/archived → skip (never insert)
#   BLOCKED  : exact duplicate (same case + filename + hash) → skip, log to Mongo as duplicate attempt
#   ALLOWED  : same filename, new content → new VERSION (v2, v3…)
#   ALLOWED  : new filename             → version 1
#   PHYSICAL : no file, random hash, no Supabase upload, no crypto
#
#  Per-upload writes (matching the real upload flow):
#   SQL      : evidence row with real hash, rsa_signature, encryption_iv
#   Supabase : AES-256-CBC encrypted file (digital only)
#   Mongo    : case_activity_logs, evidence_versions, evidence_metadata, audit_logs
#   Neo4j    : neo_add_evidence node
#
#  Versioning:
#   ~20% of digital evidence items are re-uploads of existing filenames
#   (simulate investigators updating evidence files over time)
#   These become version 2 or 3 of an existing evidence item.

def _evidence_code(case_id, etype, conn):
    """Mirror generate_evidence_code() from routes/evidence.py."""
    type_char = 'D' if etype == 'digital' else 'P'
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id=%s AND evidence_type=%s;",
        (case_id, etype)
    )
    seq = cur.fetchone()[0] + 1
    cur.close()
    return f"{case_id:03d}{type_char}{seq:02d}"

def _next_version(case_id, filename, conn):
    """Mirror get_next_version_for_filename() from routes/evidence.py."""
    cur = conn.cursor()
    cur.execute(
        "SELECT MAX(version) FROM evidence WHERE case_id=%s AND original_filename=%s;",
        (case_id, filename)
    )
    row = cur.fetchone()
    cur.close()
    return (row[0] + 1) if row[0] else 1

def _gen_file_content(code, case_id, tag, version=1, extra_lines=0, ext="txt"):
    """
    Generate realistic file bytes for digital evidence.

    For pdf/png/jpg/jpeg: produce a real, openable file using only stdlib.
    For all other extensions: produce UTF-8 text with forensic metadata.
    """
    inv = random.choice(_INVESTIGATORS)
    cat = random.choice(_CASE_TYPES)
    ts  = rnd_past_dt(300).strftime("%Y-%m-%d %H:%M:%S")
    ext = ext.lower()

    # ── PDF ──────────────────────────────────────────────────────────────────
    if ext == "pdf":
        title   = f"Evidence {code} v{version}"
        text_lines = [
            f"EVIDENCE FILE: {code}",
            f"Case ID: {case_id}  |  Version: {version}  |  Tag: {tag}",
            f"Collected by: {inv}  |  Timestamp: {ts}",
            f"Category: {cat}  |  Source: ECMS Simulation Dataset",
            "",
            "CHAIN OF CUSTODY NOTE",
            "All transfers are logged in the custody management system.",
            "Integrity verified via SHA-256 hash and RSA-2048 digital signature.",
            "File encrypted using AES-256-CBC with HKDF-derived key.",
            "",
            "SIMULATION METADATA",
            f"sim_tag=[SIM]  version_nonce={''.join(random.choices(string.ascii_letters + string.digits, k=32))}",
        ]
        for _ in range(random.randint(3, 8) + extra_lines):
            text_lines.append(''.join(random.choices(string.ascii_letters + ' ', k=random.randint(40, 80))))
        body_text = "\n".join(text_lines)

        # Build a minimal but fully valid PDF manually
        def pdf_str(s): return s.encode("latin-1")
        lines_escaped = body_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        # Split into display lines at ~80 chars
        display_lines = []
        for ln in body_text.split("\n"):
            while len(ln) > 80:
                display_lines.append(ln[:80])
                ln = ln[80:]
            display_lines.append(ln)

        stream_parts = ["BT", "/F1 10 Tf", "40 760 Td", "12 TL"]
        for dl in display_lines[:55]:
            safe = dl.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            stream_parts.append(f"({safe}) Tj T*")
        stream_parts.append("ET")
        stream_content = "\n".join(stream_parts)
        stream_bytes = stream_content.encode("latin-1")

        objects = []
        # obj 1: catalog
        objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        # obj 2: pages
        objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
        # obj 3: page
        objects.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")
        # obj 4: content stream
        obj4 = f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode() + stream_bytes + b"\nendstream\nendobj\n"
        objects.append(obj4)
        # obj 5: font
        objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n")

        header = b"%PDF-1.4\n"
        body = b""
        offsets = []
        pos = len(header)
        for obj in objects:
            offsets.append(pos)
            body += obj
            pos += len(obj)

        xref_pos = len(header) + len(body)
        xref = f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n"
        for off in offsets:
            xref += f"{off:010d} 00000 n \n"
        trailer = f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"

        return header + body + xref.encode() + trailer.encode()

    # ── PNG ──────────────────────────────────────────────────────────────────
    elif ext == "png":
        import struct, zlib
        width, height = 200, 120
        r = random.randint(80, 220)
        g = random.randint(80, 220)
        b_val = random.randint(80, 220)
        # Build raw image data: each row prefixed with filter byte 0x00
        raw_rows = []
        for row in range(height):
            row_bytes = bytearray()
            row_bytes.append(0)  # filter type: None
            for col in range(width):
                # Subtle gradient so the image looks unique per evidence item
                rv = min(255, r + (col * 30 // width) + (row * 20 // height))
                gv = min(255, g + (row * 30 // height))
                bv = min(255, b_val + (col * 20 // width))
                row_bytes.extend([rv, gv, bv])
            raw_rows.append(bytes(row_bytes))
        raw_data = b"".join(raw_rows)
        compressed = zlib.compress(raw_data, 6)

        def chunk(name, data):
            c = name + data
            crc = zlib.crc32(c) & 0xFFFFFFFF
            return struct.pack(">I", len(data)) + c + struct.pack(">I", crc)

        png = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", compressed)
            + chunk(b"IEND", b"")
        )
        return png

    # ── JPEG ─────────────────────────────────────────────────────────────────
    elif ext in ("jpg", "jpeg"):
        # Minimal valid JFIF JPEG: SOI + APP0 + DQT + SOF0 + DHT + SOS + EOI
        # Rather than hand-crafting a full JPEG encoder (very complex),
        # we generate a tiny 8x8 solid-colour JPEG using raw segment bytes.
        # This is a known-valid 8×8 JPEG template for a solid grey image,
        # with colour tinted by XOR-ing the Y/Cb/Cr DC coefficients.
        r_byte = random.randint(60, 200)
        # Hardcoded minimal 8×8 solid-colour JPEG (grey, ~800 bytes)
        # Source: hand-crafted minimal JFIF; Y=128, Cb=128, Cr=128
        HEX = (
            "FFD8FFE000104A464946000101000001000100"
            "00FFDB004300080606070605080707070909"
            "0808090C140D0C0B0B0C1912130F141D1A1F"
            "1E1D1A1C1C20242E2720222C231C1C283729"
            "2C30313434341F27393D38323C2E333432FF"
            "C0000B080008000801011100FFC400A50000"
            "0105010101010100000000000000000102030405060708090A0B1000"
            "02010303020403050504040000017D010203000411051221314106"
            "1351610722718132146191A1082342B1C11552D1F02433627282090A"
            "161718191A25262728292A3435363738393A434445464748494A5354"
            "55565758595A636465666768696A737475767778797A838485868788"
            "898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8"
            "B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE1E2E3E4E5E6E7"
            "E8E9EAF1F2F3F4F5F6F7F8F9FAFFDA00081101003F00FBD28A2800"
            "FFFD9"
        )
        try:
            return bytes.fromhex(HEX.replace("\n", "").replace(" ", ""))
        except Exception:
            # Fallback: a tiny but valid raw 1x1 white JPEG
            return bytes.fromhex(
                "FFD8FFE000104A464946000101000001000100"
                "00FFDB004300010101010101010101010101"
                "01010101010101010101010101010101010101"
                "01010101010101010101010101010101010101"
                "0101010101FFC0000B080001000101011100"
                "FFC4001F0000010501010101010100000000"
                "000000000102030405060708090A0BFFDA00"
                "0801010003013F00FFA2FFD9"
            )

    # ── Text fallback (csv, log, docx, xlsx, etc.) ────────────────────────
    else:
        lines = [
            f"EVIDENCE FILE: {code}",
            f"Case ID      : {case_id}",
            f"Version      : {version}",
            f"Tag          : {tag}",
            f"Collected by : {inv}",
            f"Timestamp    : {ts}",
            f"Category     : {cat}",
            f"Source       : ECMS Simulation Dataset",
            "",
            "--- CONTENT ---",
            f"This document was generated as part of a controlled forensic evidence simulation.",
            f"Evidence code {code} (v{version}) was collected during investigation of a {cat} case.",
            f"The collecting officer {inv} documented this item at {ts}.",
            "",
            "--- CHAIN OF CUSTODY NOTE ---",
            f"All transfers are logged in the custody management system.",
            f"Integrity is verified via SHA-256 hash and RSA-2048 digital signature.",
            f"File is encrypted using AES-256-CBC with HKDF-derived key (key never stored).",
            "",
            "--- SIMULATION METADATA ---",
            f"sim_tag=[SIM]",
            f"random_payload={''.join(random.choices(string.ascii_letters + string.digits, k=128))}",
            f"version_nonce={''.join(random.choices(string.ascii_letters + string.digits, k=32))}",
        ]
        for _ in range(random.randint(5, 20) + extra_lines):
            lines.append(''.join(random.choices(string.ascii_letters + ' ', k=random.randint(40, 100))))
        return "\n".join(lines).encode("utf-8")

def create_evidence(user_ids, case_ids, n=N_EVIDENCE):
    print(f"\n[3/6] Creating {n} evidence items (with versioning + Supabase uploads)...")
    conn = get_connection(); cur = conn.cursor()

    # Pre-load case statuses so we never upload to closed/archived cases
    cur.execute("SELECT case_id, status FROM cases WHERE case_id = ANY(%s);", (case_ids,))
    case_status = {r[0]: (r[1] or '').lower() for r in cur.fetchall()}
    open_case_ids = [cid for cid in case_ids if case_status.get(cid) not in ('closed', 'archived')]
    all_case_ids  = case_ids  # we still need to reach min quota for closed cases

    if not open_case_ids:
        print("  Warning: no open cases — uploading to all cases regardless of status")
        open_case_ids = list(case_ids)

    # Pre-load existing hashes to check duplicates
    cur.execute("SELECT case_id, file_hash_sha256 FROM evidence WHERE file_hash_sha256 IS NOT NULL;")
    used_hashes = {}
    for cid, fh in cur.fetchall():
        used_hashes.setdefault(cid, set()).add(fh)

    # ── Guaranteed minimum quota: every case gets at least 10 evidence items ──
    # We track how many evidence items each case already has (sim + real)
    cur.execute("SELECT case_id, COUNT(*) FROM evidence GROUP BY case_id;")
    case_evidence_count: dict = {r[0]: r[1] for r in cur.fetchall()}

    MIN_EVIDENCE_PER_CASE = 10
    MIN_UPLOADERS_PER_CASE = 5  # distinct uploaders per case

    # Build a guaranteed-upload plan: for each case short of the minimum,
    # schedule exactly enough items using distinct uploaders.
    guaranteed_uploads: list = []  # list of (case_id, uploader_id)
    for cid in all_case_ids:
        existing = case_evidence_count.get(cid, 0)
        shortfall = max(0, MIN_EVIDENCE_PER_CASE - existing)
        if shortfall > 0:
            # Pick at least MIN_UPLOADERS_PER_CASE distinct uploaders, cycling if needed
            chosen_uploaders = random.sample(user_ids, min(MIN_UPLOADERS_PER_CASE, len(user_ids)))
            for j in range(shortfall):
                guaranteed_uploads.append((cid, chosen_uploaders[j % len(chosen_uploaders)]))

    # Interleave guaranteed uploads with random ones; total = n + guaranteed extras
    random_uploads = [(random.choice(open_case_ids), random.choice(user_ids))
                      for _ in range(n)]
    all_uploads = guaranteed_uploads + random_uploads
    total_uploads = len(all_uploads)
    print(f"  ({len(guaranteed_uploads)} guaranteed + {n} random = {total_uploads} total uploads)")

    evidence_ids = []
    _upload_errors = []
    case_filenames = {}  # {case_id: {filename: [evidence_id, ...]}}

    mongo_activity = []
    mongo_versions = []
    mongo_meta     = []
    mongo_audit    = []

    VERSION_RATE = 0.20
    done = 0

    for case_id, uploader in all_uploads:
        etype    = random.choice(EVIDENCE_TYPES)
        uploaded = rnd_past_dt(300)

        existing_files = list((case_filenames.get(case_id) or {}).keys())
        is_new_version = (
            len(existing_files) >= 3 and
            etype == 'digital' and
            random.random() < VERSION_RATE
        )

        if etype == 'digital':
            if is_new_version:
                filename = random.choice(existing_files)
                ext  = filename.rsplit('.', 1)[-1] if '.' in filename else 'txt'
                mime = DIGITAL_MIMES.get(ext, "text/plain")
            else:
                ext      = random.choice(DIGITAL_EXTS)
                prefix   = ''.join(random.choices(string.ascii_lowercase, k=6))
                filename = f"[SIM]_{prefix}.{ext}"
                mime     = DIGITAL_MIMES.get(ext, "text/plain")

            version       = _next_version(case_id, filename, conn)
            base_code     = _evidence_code(case_id, etype, conn)
            evidence_code = base_code if version == 1 else f"{base_code}-v{version}"
            tag           = f"{SIM_TAG} Digital - {filename} v{version}"

            # Generate real file bytes — pass the extension for proper format
            file_bytes = _gen_file_content(evidence_code, case_id, tag,
                                           version=version, extra_lines=(version-1)*3,
                                           ext=ext)
            file_hash  = hashlib.sha256(file_bytes).hexdigest()
            file_size  = len(file_bytes)

            if file_hash in used_hashes.get(case_id, set()):
                mongo_versions.append({
                    "evidence_id":   None,
                    "case_id":       case_id,
                    "evidence_code": evidence_code,
                    "file_hash":     file_hash,
                    "content_hash":  file_hash,
                    "file_size":     file_size,
                    "filename":      filename,
                    "version":       version,
                    "storage_path":  None,
                    "uploaded_by":   uploader,
                    "uploaded_at":   uploaded,
                    "is_duplicate":  True,
                    "parent_version": version - 1 if version > 1 else None,
                    "status":        "rejected_duplicate",
                })
                mongo_audit.append({
                    "user_id": uploader, "action": "UPLOAD_REJECTED_DUPLICATE",
                    "object_type": "evidence", "object_id": None, "case_id": case_id,
                    "description": f"{SIM_TAG} Duplicate upload rejected: {filename} hash already exists",
                    "ip_address": random.choice(FAKE_IPS), "timestamp": uploaded,
                })
                done += 1
                progress("Evidence", done, total_uploads)
                continue

            used_hashes.setdefault(case_id, set()).add(file_hash)

            try:
                rsa_sig = crypto_pipeline.generate_rsa_signature(file_hash)
            except Exception:
                rsa_sig = None

            _safe_fname  = filename.replace("[SIM]_", "SIM_").replace("[", "").replace("]", "")
            storage_path = f"sim/case_{case_id}/{base_code}/v{version}_{_safe_fname}"

        else:
            item         = random.choice(PHYSICAL_ITEMS)
            filename     = None
            mime         = None
            file_bytes   = None
            file_hash    = rnd_hash()
            file_size    = None
            version      = 1
            base_code    = _evidence_code(case_id, etype, conn)
            evidence_code = base_code
            tag          = f"{SIM_TAG} Physical - {item} #{random.randint(1000,9999)}"
            storage_path = f"sim/{evidence_code}"
            rsa_sig      = None

        try:
            cur.execute("""
                INSERT INTO evidence (
                    case_id, evidence_code, evidence_type, evidence_tag,
                    uploader_id, upload_time, original_filename, content_mime,
                    size_bytes, file_hash_sha256, mongo_file_id,
                    is_active, created_at, version, is_sealed, metadata,
                    rsa_signature, encryption_iv
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE,%s,%s,FALSE,%s,%s,%s)
                RETURNING evidence_id;
            """, (
                case_id, evidence_code, etype, tag,
                uploader, uploaded, filename, mime,
                file_size, file_hash, storage_path,
                uploaded, version,
                '{"source":"simulation"}',
                rsa_sig, None
            ))
            eid = cur.fetchone()[0]
            evidence_ids.append(eid)
        except Exception:
            conn.rollback()
            used_hashes.get(case_id, set()).discard(file_hash)
            done += 1
            progress("Evidence", done, total_uploads)
            continue

        encryption_iv = None
        if file_bytes:
            try:
                enc           = crypto_pipeline.encrypt_file_aes256(file_bytes, eid)
                encryption_iv = enc["iv"]
                encrypted_bytes = enc["encrypted_data"]

                def _do_upload(path, data):
                    resp = supabase.storage.from_("evidence-files").upload(
                        path=path,
                        file=data,
                        file_options={"content-type": "application/octet-stream"},
                    )
                    if isinstance(resp, dict) and resp.get("error"):
                        err  = resp.get("error", {})
                        code = str(resp.get("statusCode", ""))
                        msg  = str(err) if isinstance(err, str) else str(resp)
                        if "409" in code or "already exists" in msg.lower() or "Duplicate" in msg:
                            supabase.storage.from_("evidence-files").remove([path])
                            supabase.storage.from_("evidence-files").upload(
                                path=path, file=data,
                                file_options={"content-type": "application/octet-stream"},
                            )
                        else:
                            raise RuntimeError(f"Supabase upload error: {resp}")
                try:
                    _do_upload(storage_path, encrypted_bytes)
                except Exception as _e1:
                    _e1_str = str(_e1)
                    if "409" in _e1_str or "already exists" in _e1_str.lower() or "Duplicate" in _e1_str:
                        try:
                            supabase.storage.from_("evidence-files").remove([storage_path])
                        except Exception:
                            pass
                        _do_upload(storage_path, encrypted_bytes)
                    else:
                        raise

                cur.execute(
                    "UPDATE evidence SET encryption_iv=%s WHERE evidence_id=%s;",
                    (encryption_iv, eid)
                )
                conn.commit()
            except Exception as upload_err:
                _upload_errors.append(f"eid={eid}: {upload_err}")
                try:
                    conn.commit()
                except Exception:
                    pass

        if not file_bytes:
            conn.commit()

        if filename:
            case_filenames.setdefault(case_id, {}).setdefault(filename, []).append(eid)

        event_type = "evidence_uploaded" if version == 1 else "evidence_version_uploaded"
        mongo_activity.append({
            "case_id": case_id, "event_type": event_type,
            "entity": "evidence", "entity_id": eid,
            "description": f"{SIM_TAG} {'Evidence uploaded' if version==1 else 'New version uploaded'}: {filename or tag} v{version}",
            "actor_id": uploader, "timestamp": uploaded,
        })
        mongo_versions.append({
            "evidence_id":   eid,
            "case_id":       case_id,
            "evidence_code": evidence_code,
            "file_hash":     file_hash,
            "content_hash":  file_hash,
            "file_size":     file_size or 0,
            "filename":      filename or f"physical_{evidence_code}",
            "version":       version,
            "storage_path":  storage_path,
            "uploaded_by":   uploader,
            "uploaded_at":   uploaded,
            "is_duplicate":  False,
            "parent_version": (version - 1) if version > 1 else None,
            "status":        "active",
        })
        mongo_meta.append({
            "evidence_id": eid, "case_id": case_id, "created_at": uploaded,
            "metadata": {
                "evidence_code": evidence_code, "evidence_tag": tag,
                "file_type":     (filename.rsplit('.',1)[-1] if filename and '.' in filename else etype),
                "filename":      filename or "",
                "original_name": filename or "",
                "content_type":  mime or "physical",
                "hash":          file_hash,
                "size":          file_size or 0,
                "version":       version,
                "is_new_version": version > 1,
                "source":        "simulation",
                "storage":       "supabase",
                "storage_path":  storage_path,
                "description":   tag,
                "notes":         "Auto-generated simulation data",
            }
        })
        mongo_audit.append({
            "user_id": uploader, "action": "EVIDENCE_UPLOAD",
            "object_type": "evidence", "object_id": eid, "case_id": case_id,
            "description": f"{SIM_TAG} Uploaded {evidence_code} v{version} for case {case_id}",
            "ip_address": random.choice(FAKE_IPS), "timestamp": uploaded,
        })

        try:
            from dbs.neo4j_db import neo_add_evidence as _neo_add
            _neo_add(
                evidence_id=eid, case_id=case_id,
                evidence_code=evidence_code, evidence_type=etype,
                evidence_tag=tag, is_active=True, created_at=uploaded.isoformat(),
                uploader_id=uploader,
                uploader_username=f"sim_user_{uploader}",
                uploader_role="Investigator"
            )
        except Exception:
            pass

        done += 1
        progress("Evidence", done, total_uploads)

    cur.close(); conn.close()
    if mongo_activity: db.case_activity_logs.insert_many(mongo_activity)
    if mongo_versions: db.evidence_versions.insert_many(mongo_versions)
    if mongo_meta:     db.evidence_metadata.insert_many(mongo_meta)
    if mongo_audit:    db.audit_logs.insert_many(mongo_audit)

    v_counts = {}
    for doc in mongo_versions:
        if not doc.get("is_duplicate"):
            v_counts[doc["version"]] = v_counts.get(doc["version"], 0) + 1
    dup_count = sum(1 for d in mongo_versions if d.get("is_duplicate"))
    if _upload_errors:
        print(f"  ! {len(_upload_errors)} Supabase upload errors (first 3):")
        for e in _upload_errors[:3]:
            print(f"    {e}")
    print(f"  + {len(evidence_ids)} SQL evidence items")
    print(f"    versions: " + ", ".join(f"v{k}={v}" for k,v in sorted(v_counts.items())))
    print(f"    {dup_count} duplicate upload attempts logged (rejected)")
    return evidence_ids

# ── Step 4 — Custody Events ────────────────────────────────────────────────────
# SQL  : coc_logs(evidence_id, from_user_id, to_user_id,
#                 action [transfer|store|verify|access|examine|seal|unseal|destroy|other],
#                 action_description, location, timestamp,
#                 reference_external, created_at)\n#        audit_logs(user_id, action_type, object_type, object_id, details, occurred_at)
#
# Mongo: custody_logs(evidence_id, from_user, to_user, location, reason, timestamp)
#        case_activity_logs — custody_transfer
#        audit_logs         — CUSTODY_TRANSFER
#
# Guarantees:
#   - Every evidence item gets at least 10 custody events
#   - Each evidence item involves at least 5 distinct actors across its events
def create_custody_events(user_ids, evidence_ids, n=N_CUSTODY):
    MIN_EVENTS_PER_EV = 10
    MIN_ACTORS_PER_EV = 5
    MONGO_BATCH_SIZE  = 500   # flush to MongoDB every N events to avoid Atlas timeouts
    print(f"\n[4/6] Creating custody events (min {MIN_EVENTS_PER_EV}/evidence, "
          f"{MIN_ACTORS_PER_EV} distinct actors, plus {n} random)...")

    conn = get_connection(); cur = conn.cursor()

    cur.execute("SELECT evidence_id, uploader_id, case_id FROM evidence WHERE evidence_id = ANY(%s);",
                (evidence_ids,))
    ev_info        = {row[0]: {"holder": row[1], "case_id": row[2]} for row in cur.fetchall()}
    current_holder = {eid: info["holder"] for eid, info in ev_info.items()}

    custody_list   = []
    mongo_custody  = []
    mongo_activity = []
    mongo_audit    = []

    def _flush_mongo():
        """Push accumulated Mongo docs in one batch, then clear the buffers."""
        if mongo_custody:  db.custody_logs.insert_many(mongo_custody);       mongo_custody.clear()
        if mongo_activity: db.case_activity_logs.insert_many(mongo_activity); mongo_activity.clear()
        if mongo_audit:    db.audit_logs.insert_many(mongo_audit);            mongo_audit.clear()

    def _insert_event(ev_id, from_user, to_user, ts):
        case_id  = ev_info[ev_id]["case_id"]
        action   = random.choice(COC_ACTIONS)
        reason   = f"{SIM_TAG} {random.choice(TRANSFER_REASONS)}"
        location = random.choice(LOCATIONS)
        ref_ext  = f"SIM-REF-{random.randint(10000,99999)}" if random.random() < 0.3 else None
        cur.execute("""
            INSERT INTO coc_logs
                (evidence_id, from_user_id, to_user_id, action,
                 action_description, location, timestamp,
                 reference_external, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING log_id;
        """, (ev_id, from_user, to_user, action, reason, location, ts, ref_ext, ts))
        log_id = cur.fetchone()[0]
        custody_list.append((log_id, ev_id, from_user, to_user, ts, action, reason, location))
        current_holder[ev_id] = to_user
        mongo_custody.append({
            "evidence_id": ev_id, "from_user": from_user, "to_user": to_user,
            "location": location, "reason": reason, "timestamp": ts,
        })
        mongo_activity.append({
            "case_id": case_id, "event_type": "custody_transfer",
            "entity": "evidence", "entity_id": ev_id,
            "description": f"{SIM_TAG} Custody transferred: {reason}",
            "actor_id": from_user, "timestamp": ts,
        })
        mongo_audit.append({
            "user_id": from_user, "action": "CUSTODY_TRANSFER",
            "object_type": "evidence", "object_id": ev_id, "case_id": case_id,
            "description": f"{SIM_TAG} Custody transfer to user {to_user}",
            "ip_address": random.choice(FAKE_IPS), "timestamp": ts,
        })
        # Flush every MONGO_BATCH_SIZE events so we never accumulate a giant payload
        if len(mongo_custody) >= MONGO_BATCH_SIZE:
            conn.commit()   # commit SQL first so IDs are stable
            _flush_mongo()

    # ── Phase 1: Guaranteed minimum events per evidence item ─────────────────
    total_guaranteed = len(evidence_ids) * MIN_EVENTS_PER_EV
    done = 0
    for ev_id in evidence_ids:
        pool    = random.sample(user_ids, min(MIN_ACTORS_PER_EV, len(user_ids)))
        base_ts = rnd_past_dt(270)
        offsets = sorted(random.randint(0, 270 * 60) for _ in range(MIN_EVENTS_PER_EV))
        for idx, offset_min in enumerate(offsets):
            ts      = base_ts + timedelta(minutes=offset_min)
            actor   = pool[idx % len(pool)]
            to_user = pool[(idx + 1) % len(pool)]
            _insert_event(ev_id, actor, to_user, ts)
        done += MIN_EVENTS_PER_EV
        progress("Custody guaranteed", done, total_guaranteed)
    print()

    # ── Phase 2: Additional random events up to N_CUSTODY total ─────────────
    extra = max(0, n - total_guaranteed)
    for i in range(1, extra + 1):
        ev_id     = random.choice(evidence_ids)
        from_user = current_holder.get(ev_id, random.choice(user_ids))
        to_user   = random.choice([u for u in user_ids if u != from_user])
        _insert_event(ev_id, from_user, to_user, rnd_past_dt(270))
        progress("Custody extra", i, extra)
    if extra:
        print()

    # Final commit + flush any remaining docs
    conn.commit(); cur.close(); conn.close()
    _flush_mongo()

    print(f"  + {len(custody_list)} SQL coc_logs | {len(custody_list)} Mongo custody_logs")
    return custody_list

# ── Step 5 — Verification History ─────────────────────────────────────────────
# SQL  : evidence_verification_history(evidence_id, verified_by, verified_at,
#        found_hash, expected_hash, result[match|mismatch|error],
#        notes, verification_method)
# Mongo: audit_logs — INTEGRITY_VERIFY
def create_verification_history(user_ids, evidence_ids):
    print(f"\n[5/6] Creating verification history...")
    conn = get_connection(); cur = conn.cursor()

    cur.execute("SELECT evidence_id, file_hash_sha256 FROM evidence WHERE evidence_id = ANY(%s);",
                (evidence_ids,))
    ev_hash = {row[0]: row[1] for row in cur.fetchall()}

    sample     = random.sample(evidence_ids, int(len(evidence_ids) * 0.4))
    sql_rows   = []
    mongo_audit = []

    for ev_id in sample:
        expected    = ev_hash.get(ev_id, rnd_hash())
        verifier    = random.choice(user_ids)
        verified_at = rnd_past_dt(60)
        result      = random.choices(["match","mismatch","error"], weights=[80,15,5])[0]
        found_hash  = expected if result == "match" else rnd_hash()

        sql_rows.append((
            ev_id, verifier, verified_at,
            found_hash, expected, result,
            f"{SIM_TAG} Simulation verification run",
            "sha256_file_hash"
        ))
        mongo_audit.append({
            "user_id": verifier, "action": "INTEGRITY_VERIFY",
            "object_type": "evidence", "object_id": ev_id, "case_id": None,
            "description": f"{SIM_TAG} Integrity verification: result={result}",
            "ip_address": random.choice(FAKE_IPS), "timestamp": verified_at,
        })

    if sql_rows:
        cur.executemany("""
            INSERT INTO evidence_verification_history
                (evidence_id, verified_by, verified_at, found_hash,
                 expected_hash, result, notes, verification_method)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s);
        """, sql_rows)
        cur.executemany(
            "UPDATE evidence SET last_verified_at=%s WHERE evidence_id=%s;",
            [(r[2], r[0]) for r in sql_rows]
        )
    conn.commit(); cur.close(); conn.close()
    if mongo_audit: db.audit_logs.insert_many(mongo_audit)
    print(f"  + {len(sql_rows)} verification records")


# ── Step 6 — Neo4j ─────────────────────────────────────────────────────────────
def sync_neo4j(user_ids, evidence_ids, custody_list):
    print(f"\n[6/6] Syncing to Neo4j...")
    try:
        with driver.session(database=NEO4J_DATABASE) as s:
            for i, uid in enumerate(user_ids):
                s.run("MERGE (u:User {user_id:$uid}) SET u.sim=true;", {"uid": uid})
                progress("Neo4j users", i+1, len(user_ids))

            conn = get_connection(); cur = conn.cursor()
            cur.execute("SELECT evidence_id, evidence_code, case_id FROM evidence WHERE evidence_id = ANY(%s);",
                        (evidence_ids,))
            rows = cur.fetchall(); cur.close(); conn.close()
            for eid, ecode, cid in rows:
                s.run("""
                    MERGE (e:Evidence {evidence_id:$eid})
                    SET e.evidence_code=$ecode, e.sim=true
                    WITH e
                    MERGE (c:Case {case_id:$cid}) SET c.sim=true
                    WITH e, c
                    MERGE (e)-[:IN_CASE]->(c);
                """, {"eid": eid, "ecode": ecode, "cid": cid})

            for i, (log_id, ev_id, from_uid, to_uid, ts, action, reason, location) in enumerate(custody_list):
                s.run("""
                    MERGE (u1:User {user_id:$fu}) SET u1.sim=true
                    WITH u1
                    MERGE (u2:User {user_id:$tu}) SET u2.sim=true
                    WITH u1, u2
                    MATCH (e:Evidence {evidence_id:$eid})
                    CREATE (ce:CustodyEvent {
                        custody_id:  $lid,
                        timestamp:   $ts,
                        action:      $action,
                        reason:      $reason,
                        location:    $location,
                        sim:         true
                    })
                    MERGE (e)-[:HAS_CUSTODY_EVENT]->(ce)
                    MERGE (ce)-[:FROM]->(u1)
                    MERGE (ce)-[:TO]->(u2);
                """, {"fu": from_uid, "tu": to_uid, "eid": ev_id,
                      "lid": log_id, "ts": ts.isoformat(),
                      "action": action, "reason": reason, "location": location})
                progress("Neo4j custody", i+1, len(custody_list))

            # Sync VerificationEvent nodes from evidence_verification_history
            conn2 = get_connection(); cur2 = conn2.cursor()
            cur2.execute("""
                SELECT verify_id, evidence_id, verified_by, verified_at, result
                FROM evidence_verification_history
                WHERE evidence_id = ANY(%s);
            """, (evidence_ids,))
            verif_rows = cur2.fetchall(); cur2.close(); conn2.close()

            for i, (vid, eid, uid, vat, result) in enumerate(verif_rows):
                s.run("""
                    MATCH (e:Evidence {evidence_id:$eid})
                    MATCH (u:User {user_id:$uid})
                    CREATE (ve:VerificationEvent {verify_id:$vid, result:$result,
                            verified_at:$vat, sim:true})
                    MERGE (e)-[:VERIFIED_BY]->(ve)
                    MERGE (u)-[:PERFORMED]->(ve);
                """, {"eid": eid, "uid": uid, "vid": vid,
                      "result": result, "vat": vat.isoformat()})
                progress("Neo4j verify", i+1, len(verif_rows))
        print("\n  + Neo4j sync complete")
    except Exception as e:
        print(f"\n  Neo4j failed (non-fatal): {e}")


# ── Anomaly 1 — Tampered Hashes ───────────────────────────────────────────────
def inject_tampered_hashes(evidence_ids, n=N_TAMPERED):
    print(f"\n[A1] Injecting {n} tampered hashes...")
    conn = get_connection(); cur = conn.cursor()

    cur.execute("SELECT evidence_id, case_id, file_hash_sha256 FROM evidence WHERE evidence_id = ANY(%s);",
                (evidence_ids,))
    ev_info = {row[0]: {"case_id": row[1], "hash": row[2]} for row in cur.fetchall()}

    case_hashes = {}
    for ev_id, info in ev_info.items():
        cid = info["case_id"]
        if cid not in case_hashes:
            cur.execute("SELECT file_hash_sha256 FROM evidence WHERE case_id=%s AND file_hash_sha256 IS NOT NULL;", (cid,))
            case_hashes[cid] = {row[0] for row in cur.fetchall()}

    targets = random.sample(evidence_ids, min(n, len(evidence_ids)))
    tampered = []; mongo_audit = []

    for i, ev_id in enumerate(targets):
        cid = ev_info[ev_id]["case_id"]
        for _ in range(30):
            fake_hash = rnd_hash()
            if fake_hash not in case_hashes.get(cid, set()):
                break
        else:
            continue
        case_hashes.setdefault(cid, set()).add(fake_hash)
        cur.execute("""
            UPDATE evidence
            SET file_hash_sha256 = %s,
                evidence_tag = evidence_tag || ' [TAMPERED]'
            WHERE evidence_id = %s;
        """, (fake_hash, ev_id))
        tampered.append(ev_id)
        mongo_audit.append({
            "user_id": None, "action": "HASH_TAMPERED",
            "object_type": "evidence", "object_id": ev_id, "case_id": cid,
            "description": f"{SIM_TAG} [TAMPERED] Hash modified for experiment 1",
            "ip_address": None, "timestamp": datetime.now(timezone.utc),
        })
        progress("Tamper", i+1, n)

    conn.commit(); cur.close(); conn.close()
    if mongo_audit:
        db.audit_logs.insert_many(mongo_audit)
        # Also write to security_alerts so both query paths work
        db.security_alerts.insert_many([{
            "alert_type":  "tampered_hash",
            "severity":    "critical",
            "evidence_id": doc["object_id"],
            "case_id":     doc["case_id"],
            "description": doc["description"],
            "timestamp":   doc["timestamp"],
        } for doc in mongo_audit])
    _write_ids("tampered_ids", tampered)
    print(f"  + {len(tampered)} tampered hashes")
    return tampered


# ── Anomaly 2 — Broken Chains ─────────────────────────────────────────────────
def inject_broken_chains(evidence_ids, user_ids, n=N_BROKEN):
    print(f"\n[A2] Injecting {n} broken custody chains...")
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT evidence_id FROM (
            SELECT DISTINCT evidence_id FROM coc_logs
            WHERE action_description LIKE '[SIM]%%'
        ) sub
        ORDER BY RANDOM() LIMIT %s;
    """, (n * 3,))
    candidates = [row[0] for row in cur.fetchall()]

    broken = []; injected = 0
    neo4j_rows = []
    mongo_custody = []; mongo_activity = []
    cur2 = conn.cursor()

    for ev_id in candidates:
        if injected >= n: break
        cur2.execute("""
            SELECT cl.to_user_id, cl.timestamp, e.case_id
            FROM coc_logs cl JOIN evidence e ON cl.evidence_id=e.evidence_id
            WHERE cl.evidence_id=%s ORDER BY cl.timestamp DESC LIMIT 1;
        """, (ev_id,))
        row = cur2.fetchone()
        if not row: continue
        last_to_user, last_ts, case_id = row
        if last_to_user is None: continue

        others = [u for u in user_ids if u != last_to_user]
        if not others: continue
        wrong_from = random.choice(others)
        to_candidates = [u for u in user_ids if u != wrong_from]
        if not to_candidates: continue
        to_user = random.choice(to_candidates)
        gap_ts  = last_ts + timedelta(hours=random.randint(1, 48))
        reason  = f"{SIM_TAG} [BROKEN_CHAIN] Gap injected for experiment 2"

        cur2.execute("""
            INSERT INTO coc_logs
                (evidence_id, from_user_id, to_user_id, action,
                 action_description, location, timestamp, created_at)
            VALUES (%s,%s,%s,'transfer',%s,'Unknown',%s,%s);
        """, (ev_id, wrong_from, to_user, reason, gap_ts, gap_ts))
        mongo_custody.append({
            "evidence_id": ev_id, "from_user": wrong_from, "to_user": to_user,
            "location": "Unknown", "reason": reason, "timestamp": gap_ts,
        })
        mongo_activity.append({
            "case_id": case_id, "event_type": "custody_transfer",
            "entity": "evidence", "entity_id": ev_id,
            "description": reason, "actor_id": wrong_from, "timestamp": gap_ts,
        })
        # Fetch the log_id we just inserted for Neo4j sync
        cur2.execute("SELECT lastval();")
        _lid = cur2.fetchone()[0]
        neo4j_rows.append((_lid, ev_id, wrong_from, to_user, gap_ts))
        broken.append(ev_id); injected += 1
        progress("Gaps", injected, n)

    conn.commit(); cur.close(); cur2.close(); conn.close()
    if mongo_custody:  db.custody_logs.insert_many(mongo_custody)
    if mongo_activity: db.case_activity_logs.insert_many(mongo_activity)
    # Sync to Neo4j so graph-based gap detection works without a separate sync step
    _neo4j_sync_coc_rows(neo4j_rows, extra_props={"anomaly": True})
    _write_ids("broken_chain_ids", broken)
    print(f"  + {injected} broken chains")
    return broken


# ── Anomaly 3 — Custody Cycles ────────────────────────────────────────────────
def inject_cycles(evidence_ids, user_ids, n=N_CYCLES):
    print(f"\n[A3] Injecting {n} custody cycles A->B->A...")
    conn = get_connection(); cur = conn.cursor()
    targets = random.sample(evidence_ids, min(n, len(evidence_ids)))
    cycle_ids_list = []; neo4j_rows = []; mongo_custody = []

    for i, ev_id in enumerate(targets):
        cur.execute("SELECT MAX(timestamp) FROM coc_logs WHERE evidence_id=%s;", (ev_id,))
        row = cur.fetchone()
        base_ts = row[0] if row[0] else datetime.now(timezone.utc) - timedelta(days=30)
        user_a = random.choice(user_ids)
        user_b = random.choice([u for u in user_ids if u != user_a])

        for from_u, to_u, offset_h in [(user_a, user_b, 2),
                                        (user_b, user_a, 4),
                                        (user_a, user_b, 6)]:
            ts     = base_ts + timedelta(hours=offset_h)
            reason = f"{SIM_TAG} [CYCLE] Cyclic transfer for experiment 2"
            cur.execute("""
                INSERT INTO coc_logs
                    (evidence_id, from_user_id, to_user_id, action,
                     action_description, location, timestamp, created_at)
                VALUES (%s,%s,%s,'transfer',%s,'Unknown',%s,%s);
            """, (ev_id, from_u, to_u, reason, ts, ts))
            mongo_custody.append({
                "evidence_id": ev_id, "from_user": from_u, "to_user": to_u,
                "location": "Unknown", "reason": reason, "timestamp": ts,
            })
            cur.execute("SELECT lastval();")
            _lid = cur.fetchone()[0]
            neo4j_rows.append((_lid, ev_id, from_u, to_u, ts))
        cycle_ids_list.append(ev_id)
        progress("Cycles", i+1, n)

    conn.commit(); cur.close(); conn.close()
    if mongo_custody: db.custody_logs.insert_many(mongo_custody)
    _neo4j_sync_coc_rows(neo4j_rows, extra_props={"anomaly": True})
    _write_ids("cycle_ids", cycle_ids_list)
    print(f"  + {len(cycle_ids_list)} cycles")
    return cycle_ids_list


# ── Anomaly 4 — Insider Misuse ────────────────────────────────────────────────
# Also writes to security_alerts (alert_type, attempt_count, description,
#                                  ip_address, severity, timestamp, username_attempted)
def inject_insider_misuse(user_ids, evidence_ids, n=N_INSIDER):
    print(f"\n[A4] Injecting {n} insider misuse patterns...")
    conn = get_connection(); cur = conn.cursor()
    insider_users  = random.sample(user_ids, min(n, len(user_ids)))

    cur.execute("SELECT evidence_id, case_id FROM evidence WHERE evidence_id = ANY(%s);",
                (evidence_ids,))
    ev_case = {row[0]: row[1] for row in cur.fetchall()}

    # We need usernames for security_alerts
    cur.execute("SELECT user_id, username FROM users WHERE user_id = ANY(%s);",
                (insider_users,))
    uid_to_username = {row[0]: row[1] for row in cur.fetchall()}

    neo4j_rows     = []
    mongo_custody  = []
    mongo_activity = []
    mongo_alerts   = []

    for i, uid in enumerate(insider_users):
        pattern  = random.choice(["rapid_access", "off_hours", "cross_case"])
        username = uid_to_username.get(uid, f"sim_u{uid}")

        if pattern == "rapid_access":
            targets = random.sample(evidence_ids, min(15, len(evidence_ids)))
            base_ts = rnd_past_dt(60)
            for j, ev_id in enumerate(targets):
                ts     = base_ts + timedelta(minutes=j * 2)
                reason = f"{SIM_TAG} [INSIDER:rapid_access] Sequential evidence access"
                cur.execute("""
                    INSERT INTO coc_logs
                        (evidence_id, from_user_id, to_user_id, action,
                         action_description, location, timestamp, created_at)
                    VALUES (%s,%s,%s,'access',%s,'Remote',%s,%s);
                """, (ev_id, uid, uid, reason, ts, ts))
                cur.execute("SELECT lastval();"); neo4j_rows.append((cur.fetchone()[0], ev_id, uid, uid, ts))
                mongo_custody.append({
                    "evidence_id": ev_id, "from_user": uid, "to_user": uid,
                    "location": "Remote", "reason": reason, "timestamp": ts,
                })
                mongo_activity.append({
                    "case_id": ev_case.get(ev_id), "event_type": "evidence_accessed",
                    "entity": "evidence", "entity_id": ev_id,
                    "description": reason, "actor_id": uid, "timestamp": ts,
                })

        elif pattern == "off_hours":
            targets = random.sample(evidence_ids, min(8, len(evidence_ids)))
            for ev_id in targets:
                ts   = off_hour_dt()
                to_u = random.choice([u for u in user_ids if u != uid])
                reason = f"{SIM_TAG} [INSIDER:off_hours] Unusual hour transfer"
                cur.execute("""
                    INSERT INTO coc_logs
                        (evidence_id, from_user_id, to_user_id, action,
                         action_description, location, timestamp, created_at)
                    VALUES (%s,%s,%s,'transfer',%s,'Unknown',%s,%s);
                """, (ev_id, uid, to_u, reason, ts, ts))
                cur.execute("SELECT lastval();"); neo4j_rows.append((cur.fetchone()[0], ev_id, uid, to_u, ts))
                mongo_custody.append({
                    "evidence_id": ev_id, "from_user": uid, "to_user": to_u,
                    "location": "Unknown", "reason": reason, "timestamp": ts,
                })

        elif pattern == "cross_case":
            targets = random.sample(evidence_ids, min(20, len(evidence_ids)))
            base_ts = rnd_past_dt(60)
            for j, ev_id in enumerate(targets):
                ts = base_ts + timedelta(minutes=j * 3)
                reason = f"{SIM_TAG} [INSIDER:cross_case] Cross-case browsing"
                cur.execute("""
                    INSERT INTO coc_logs
                        (evidence_id, from_user_id, to_user_id, action,
                         action_description, location, timestamp, created_at)
                    VALUES (%s,%s,%s,'access',%s,'Remote',%s,%s);
                """, (ev_id, uid, uid, reason, ts, ts))
                cur.execute("SELECT lastval();"); neo4j_rows.append((cur.fetchone()[0], ev_id, uid, uid, ts))
                mongo_activity.append({
                    "case_id": ev_case.get(ev_id), "event_type": "evidence_accessed",
                    "entity": "evidence", "entity_id": ev_id,
                    "description": reason, "actor_id": uid, "timestamp": ts,
                })

        # security_alerts: one per insider user
        mongo_alerts.append({
            "alert_type":         "insider_misuse",
            "severity":           "high",
            "ip_address":         random.choice(FAKE_IPS),
            "username_attempted": username,
            "attempt_count":      random.randint(5, 20),
            "description":        f"{SIM_TAG} [INSIDER] Pattern: {pattern} detected for user {uid}",
            "timestamp":          rnd_past_dt(30),
        })

        progress("Insider", i+1, n)

    conn.commit(); cur.close(); conn.close()
    if mongo_custody:  db.custody_logs.insert_many(mongo_custody)
    if mongo_activity: db.case_activity_logs.insert_many(mongo_activity)
    if mongo_alerts:   db.security_alerts.insert_many(mongo_alerts)
    _neo4j_sync_coc_rows(neo4j_rows, extra_props={"insider": True})
    _write_ids("insider_user_ids", insider_users)
    print(f"  + {len(insider_users)} insider patterns, {len(mongo_alerts)} security_alerts")
    return insider_users


# ── Step 7 — Case Access Grants ───────────────────────────────────────────────
# SQL  : case_access(case_id, user_id, granted_by, granted_at, is_active, notes)
# Mongo: audit_logs — GRANT_CASE_ACCESS (one per grant, matching the real route)
#        case_activity_logs — case_access_granted (one per grant)
#
# Rules (mirror routes/cases.py → grant_case_access):
#   - Only Lawyer / Prosecutor / Judge users are granted access
#   - Only Admin users can be the granter (granted_by)
#   - CASE_ACCESS_COVERAGE fraction of cases get at least one grant
#   - CASE_ACCESS_PER_CASE grants per covered case, up to available users
#   - ON CONFLICT (case_id, user_id) DO NOTHING  — respects the UNIQUE constraint
#   - Every grant is written to MongoDB audit_logs + case_activity_logs
def create_case_access(user_ids, case_ids):
    print(f"\n[7/7] Creating case_access grants "
          f"(coverage={int(CASE_ACCESS_COVERAGE*100)}%, "
          f"{CASE_ACCESS_PER_CASE[0]}–{CASE_ACCESS_PER_CASE[1]} grants/case)...")

    conn = get_connection(); cur = conn.cursor()

    # ── Fetch external users eligible for grants ───────────────────────────────
    cur.execute("""
        SELECT u.user_id, u.full_name, r.role_name
        FROM   users u
        JOIN   roles r ON u.role_id = r.role_id
        WHERE  r.role_name IN %s AND u.is_active = TRUE;
    """, (RESTRICTED_ROLES,))
    external_users = cur.fetchall()   # [(user_id, full_name, role_name), ...]

    if not external_users:
        print("  No Lawyer / Prosecutor / Judge users found — skipping case_access seeding.")
        cur.close(); conn.close()
        return []

    # ── Fetch Admin users to act as granters ──────────────────────────────────
    cur.execute("""
        SELECT u.user_id
        FROM   users u
        JOIN   roles r ON u.role_id = r.role_id
        WHERE  r.role_name = 'Admin' AND u.is_active = TRUE;
    """)
    admin_ids = [r[0] for r in cur.fetchall()]

    if not admin_ids:
        print("  No Admin users found — skipping case_access seeding.")
        cur.close(); conn.close()
        return []

    # ── Choose which cases get grants ─────────────────────────────────────────
    n_to_grant    = max(1, int(len(case_ids) * CASE_ACCESS_COVERAGE))
    covered_cases = random.sample(case_ids, min(n_to_grant, len(case_ids)))

    inserted      = 0
    access_ids    = []
    mongo_audit   = []
    mongo_activity = []

    for i, case_id in enumerate(covered_cases):
        n_grants   = random.randint(*CASE_ACCESS_PER_CASE)
        chosen     = random.sample(external_users, min(n_grants, len(external_users)))
        granted_by = random.choice(admin_ids)
        # Spread grants over the past 180 days, in a realistic order
        grant_times = sorted(
            rnd_past_dt(180) for _ in range(len(chosen))
        )

        for (user_id, full_name, role_name), granted_at in zip(chosen, grant_times):
            notes = f"{SIM_TAG} {role_name} assigned for case review"
            try:
                cur.execute("""
                    INSERT INTO case_access
                        (case_id, user_id, granted_by, granted_at, is_active, notes)
                    VALUES (%s, %s, %s, %s, TRUE, %s)
                    ON CONFLICT (case_id, user_id) DO NOTHING
                    RETURNING access_id;
                """, (case_id, user_id, granted_by, granted_at, notes))
                row = cur.fetchone()
                if not row:
                    continue  # conflict — duplicate, skip Mongo logging too
                access_ids.append(row[0])
                inserted += 1

                mongo_audit.append({
                    "user_id":     granted_by,
                    "action":      "GRANT_CASE_ACCESS",
                    "object_type": "case",
                    "object_id":   case_id,
                    "case_id":     case_id,
                    "description": f"{SIM_TAG} Granted download access to {full_name} ({role_name})",
                    "ip_address":  random.choice(FAKE_IPS),
                    "timestamp":   granted_at,
                })
                mongo_activity.append({
                    "case_id":    case_id,
                    "event_type": "case_access_granted",
                    "entity":     "case",
                    "entity_id":  case_id,
                    "description": f"{SIM_TAG} Evidence access granted to {full_name} ({role_name})",
                    "actor_id":   granted_by,
                    "timestamp":  granted_at,
                })
            except Exception as e:
                conn.rollback()
                continue

        conn.commit()
        progress("Case access", i + 1, len(covered_cases))

    cur.close(); conn.close()
    if mongo_audit:    db.audit_logs.insert_many(mongo_audit)
    if mongo_activity: db.case_activity_logs.insert_many(mongo_activity)

    print(f"\n  + {inserted} case_access grants across {len(covered_cases)} cases")
    print(f"    External users available: {len(external_users)} "
          f"({', '.join(RESTRICTED_ROLES)})")
    print(f"    Admin granters available: {len(admin_ids)}")
    return access_ids


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clear", action="store_true", help="Wipe sim data then re-run")
    parser.add_argument("--stats", action="store_true", help="Print DB counts only")
    args = parser.parse_args()

    if args.stats:
        print_stats(); return

    print("=" * 60)
    print("  ECMS Simulation Data Generator")
    print("  PostgreSQL + MongoDB + Neo4j")
    print("=" * 60)

    if args.clear:
        clear_sim_data()

    start = datetime.now(timezone.utc)

    user_ids     = create_users()
    case_ids     = create_cases(user_ids)
    evidence_ids = create_evidence(user_ids, case_ids)
    custody_list = create_custody_events(user_ids, evidence_ids)
    create_verification_history(user_ids, evidence_ids)
    sync_neo4j(user_ids, evidence_ids, custody_list)
    access_ids   = create_case_access(user_ids, case_ids)

    tampered = inject_tampered_hashes(evidence_ids)
    broken   = inject_broken_chains(evidence_ids, user_ids)
    cycles   = inject_cycles(evidence_ids, user_ids)
    insiders = inject_insider_misuse(user_ids, evidence_ids)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()

    print("\n" + "=" * 60)
    print("  Simulation Complete")
    print("=" * 60)
    print(f"  Users             : {len(user_ids)}")
    print(f"  Cases             : {len(case_ids)}")
    print(f"  Evidence          : {len(evidence_ids)}")
    print(f"  Custody events    : {len(custody_list)}")
    print(f"  Case access grants: {len(access_ids)}")
    print(f"  Tampered hashes   : {len(tampered)}   -> Exp 1")
    print(f"  Broken chains     : {len(broken)}   -> Exp 2")
    print(f"  Cycles            : {len(cycles)}   -> Exp 2")
    print(f"  Insider patterns  : {len(insiders)}   -> Exp 3")
    print(f"  Time              : {elapsed:.1f}s")
    print(f"  Anomaly IDs       : sim_results/")
    print("=" * 60)
    print_stats()

if __name__ == "__main__":
    main()