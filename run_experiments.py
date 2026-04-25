"""
run_experiments.py  —  ECMS Multi-Model Database Experiments
=============================================================
Runs four experiments that compare the detection capabilities
of PostgreSQL, Neo4j, and MongoDB in the ECMS system.

Experiments
-----------
  1. Tamper Detection          — Hash mismatch detection via SQL vs verified status
  2. Broken Chain Detection    — Custody gap / cycle detection: SQL JOIN vs Neo4j path
  3. Insider Misuse Profiling  — Cross-DB user behaviour: SQL + MongoDB + Neo4j
  4. Cross-DB Query Performance — Latency comparison: single-DB vs multi-model query

Prerequisites
-------------
  1. python3 simulate_data.py   (creates sim_results/ with anomaly IDs)
  2. App databases must be running (PostgreSQL, Neo4j, MongoDB)

Output
------
  sim_results/experiment_results.txt   — plain-text report
  sim_results/experiment_results.json  — machine-readable results

Usage
-----
  cd dbms_project
  python3 run_experiments.py
  python3 run_experiments.py --exp 2        # run only experiment 2
  python3 run_experiments.py --summary      # print saved results
"""

import os, sys, json, time, argparse
from datetime import datetime, timedelta

# ── path setup so we can import project modules ────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dbs.sql_db   import get_connection
from dbs.mongo_db import db as mongo_db
from dbs.neo4j_db import driver, NEO4J_DATABASE

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sim_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _load_ids(name):
    """Load anomaly IDs written by simulate_data.py."""
    path = os.path.join(RESULTS_DIR, f"{name}.txt")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [int(x.strip()) for x in f if x.strip().isdigit()]


def _timed(fn, *args, **kwargs):
    """Run fn, return (result, elapsed_seconds)."""
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, round(time.perf_counter() - t0, 4)


def _hr(title="", width=62):
    if title:
        pad = width - len(title) - 4
        print(f"\n{'─'*2}  {title}  {'─'*max(pad,2)}")
    else:
        print("─" * width)


def _ok(msg):  print(f"  ✓  {msg}")
def _warn(msg):print(f"  ⚠  {msg}")
def _info(msg):print(f"     {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 1 — Tamper Detection
#  Simulated: 50 evidence rows have their file_hash_sha256 deliberately
#             changed by inject_tampered_hashes().
#  Approach A (SQL):   SELECT where file_hash mismatch vs verification_history
#  Approach B (Neo4j): MATCH VerificationEvent nodes where result = 'mismatch'
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_1():
    _hr("Experiment 1 — Tamper Detection")
    tampered_ids = _load_ids("tampered_ids")
    _info(f"Injected tampered evidence IDs loaded: {len(tampered_ids)}")

    results = {"experiment": 1, "name": "Tamper Detection",
               "injected": len(tampered_ids)}

    # ── A: SQL — find evidence whose stored hash differs from last verification ─
    def sql_tamper_detect():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT e.evidence_id, e.evidence_code,
                   e.file_hash_sha256       AS stored_hash,
                   vh.found_hash            AS found_hash,
                   vh.result
            FROM evidence e
            JOIN evidence_verification_history vh
              ON e.evidence_id = vh.evidence_id
            WHERE vh.result = 'mismatch'
              AND e.evidence_tag LIKE '[SIM]%'
            ORDER BY vh.verified_at DESC;
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    sql_rows, sql_time = _timed(sql_tamper_detect)
    _ok(f"SQL detected {len(sql_rows)} tamper events  ({sql_time}s)")
    results["sql"] = {"detected": len(sql_rows), "latency_s": sql_time}

    # ── B: Neo4j — find VerificationEvent nodes with result='mismatch' ─────────
    def neo_tamper_detect():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence)-[:VERIFIED_BY]->(ve:VerificationEvent)
                WHERE ve.result = 'mismatch'
                RETURN e.evidence_id AS eid, ve.verify_id AS vid,
                       ve.result AS result
            """)
            return list(r)

    try:
        neo_rows, neo_time = _timed(neo_tamper_detect)
        _ok(f"Neo4j detected {len(neo_rows)} tamper events  ({neo_time}s)")
        results["neo4j"] = {"detected": len(neo_rows), "latency_s": neo_time}
    except Exception as e:
        _warn(f"Neo4j query failed: {e}")
        results["neo4j"] = {"detected": 0, "error": str(e)}

    # ── C: MongoDB — audit_logs with action = HASH_TAMPERED ─────────────────────
    # simulate_data writes action="HASH_TAMPERED" to audit_logs AND
    # alert_type="tampered_hash" to security_alerts for each tampered item.
    def mongo_tamper_detect():
        return list(mongo_db.audit_logs.find(
            {"action": "HASH_TAMPERED"}, {"_id": 0}
        ).limit(200))

    mongo_rows, mongo_time = _timed(mongo_tamper_detect)
    _ok(f"MongoDB audit_logs (HASH_TAMPERED): {len(mongo_rows)} entries  ({mongo_time}s)")
    results["mongodb"] = {"detected": len(mongo_rows), "latency_s": mongo_time}

    # ── Summary ─────────────────────────────────────────────────────────────────
    detected = max(results["sql"]["detected"], results["mongodb"]["detected"])
    recall   = round(detected / len(tampered_ids) * 100, 1) if tampered_ids else 0
    _info(f"Recall: {detected}/{len(tampered_ids)} = {recall}%")
    results["recall_pct"] = recall

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 2 — Broken Custody Chain Detection
#  Simulated: 30 custody gaps (to_user != next from_user)
#             10 custody cycles (user appears as recipient >1 time)
#  Approach A (SQL):   N self-JOINs on coc_logs ordered by timestamp
#  Approach B (Neo4j): MATCH path with WHERE gap detected or cycle count
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_2():
    _hr("Experiment 2 — Broken Chain & Cycle Detection")
    broken_ids  = _load_ids("broken_chain_ids")
    cycle_ids   = _load_ids("cycle_ids")
    _info(f"Broken chain evidence IDs: {len(broken_ids)}")
    _info(f"Cycle evidence IDs:        {len(cycle_ids)}")

    results = {"experiment": 2, "name": "Broken Chain & Cycle Detection",
               "injected_broken": len(broken_ids),
               "injected_cycles": len(cycle_ids)}

    # ── SQL gap detection ────────────────────────────────────────────────────────
    def sql_gap_detect():
        conn = get_connection(); cur = conn.cursor()
        # Compare each custody event's to_user with the next event's from_user
        cur.execute("""
            WITH ordered AS (
                SELECT evidence_id,
                       from_user_id, to_user_id, timestamp,
                       LEAD(from_user_id) OVER (
                           PARTITION BY evidence_id ORDER BY timestamp
                       ) AS next_from
                FROM coc_logs
                WHERE action_description LIKE '[SIM]%'
            )
            SELECT evidence_id, to_user_id, next_from, timestamp
            FROM ordered
            WHERE next_from IS NOT NULL
              AND to_user_id <> next_from
            ORDER BY evidence_id, timestamp;
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    sql_gaps, sql_gap_time = _timed(sql_gap_detect)
    # Count unique evidence IDs with gaps
    sql_gap_evidence = len(set(r[0] for r in sql_gaps))
    _ok(f"SQL detected {sql_gap_evidence} evidence items with chain gaps  ({sql_gap_time}s)")
    results["sql_gaps"] = {
        "evidence_with_gaps": sql_gap_evidence,
        "total_gap_events": len(sql_gaps),
        "latency_s": sql_gap_time
    }

    # ── SQL cycle detection ──────────────────────────────────────────────────────
    def sql_cycle_detect():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT evidence_id, to_user_id, COUNT(*) AS appearances
            FROM coc_logs
            WHERE action_description LIKE '[SIM]%'
            GROUP BY evidence_id, to_user_id
            HAVING COUNT(*) > 1
            ORDER BY appearances DESC;
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    sql_cycles, sql_cycle_time = _timed(sql_cycle_detect)
    sql_cycle_evidence = len(set(r[0] for r in sql_cycles))
    _ok(f"SQL detected {sql_cycle_evidence} evidence items with cycles  ({sql_cycle_time}s)")
    results["sql_cycles"] = {
        "evidence_with_cycles": sql_cycle_evidence,
        "total_cycle_events": len(sql_cycles),
        "latency_s": sql_cycle_time
    }

    # ── Neo4j gap detection ──────────────────────────────────────────────────────
    def neo_gap_detect():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce1:CustodyEvent),
                      (e)-[:HAS_CUSTODY_EVENT]->(ce2:CustodyEvent)
                WHERE ce1.timestamp < ce2.timestamp
                  AND NOT EXISTS {
                      MATCH (e)-[:HAS_CUSTODY_EVENT]->(cex:CustodyEvent)
                      WHERE cex.timestamp > ce1.timestamp
                        AND cex.timestamp < ce2.timestamp
                  }
                MATCH (ce1)-[:TO]->(u1:User), (u2:User)-[:FROM]->(ce2)
                WHERE u1 <> u2
                RETURN DISTINCT e.evidence_id AS eid,
                       u1.user_id AS expected_from,
                       u2.user_id AS actual_from
                LIMIT 200
            """)
            return list(r)

    try:
        neo_gaps, neo_gap_time = _timed(neo_gap_detect)
        neo_gap_evidence = len(set(r["eid"] for r in neo_gaps))
        _ok(f"Neo4j detected {neo_gap_evidence} evidence items with chain gaps  ({neo_gap_time}s)")
        results["neo4j_gaps"] = {
            "evidence_with_gaps": neo_gap_evidence,
            "total_gap_events": len(neo_gaps),
            "latency_s": neo_gap_time
        }
    except Exception as e:
        _warn(f"Neo4j gap query failed: {e}")
        results["neo4j_gaps"] = {"evidence_with_gaps": 0, "error": str(e)}

    # ── Neo4j cycle detection ────────────────────────────────────────────────────
    def neo_cycle_detect():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                MATCH (ce)-[:TO]->(u:User)
                WITH e.evidence_id AS eid, u.user_id AS uid, COUNT(*) AS n
                WHERE n > 1
                RETURN eid, uid, n
                ORDER BY n DESC
                LIMIT 200
            """)
            return list(r)

    try:
        neo_cycles, neo_cycle_time = _timed(neo_cycle_detect)
        neo_cycle_evidence = len(set(r["eid"] for r in neo_cycles))
        _ok(f"Neo4j detected {neo_cycle_evidence} evidence items with cycles  ({neo_cycle_time}s)")
        results["neo4j_cycles"] = {
            "evidence_with_cycles": neo_cycle_evidence,
            "total_cycle_events": len(neo_cycles),
            "latency_s": neo_cycle_time
        }
    except Exception as e:
        _warn(f"Neo4j cycle query failed: {e}")
        results["neo4j_cycles"] = {"evidence_with_cycles": 0, "error": str(e)}

    # ── Recall comparison ────────────────────────────────────────────────────────
    sql_recall_gaps   = round(sql_gap_evidence / len(broken_ids) * 100, 1) if broken_ids else 0
    neo_recall_gaps   = round(results.get("neo4j_gaps", {}).get("evidence_with_gaps", 0) / len(broken_ids) * 100, 1) if broken_ids else 0
    sql_recall_cycles = round(sql_cycle_evidence / len(cycle_ids) * 100, 1) if cycle_ids else 0
    neo_recall_cycles = round(results.get("neo4j_cycles", {}).get("evidence_with_cycles", 0) / len(cycle_ids) * 100, 1) if cycle_ids else 0

    _info(f"Gap recall    — SQL: {sql_recall_gaps}%  |  Neo4j: {neo_recall_gaps}%")
    _info(f"Cycle recall  — SQL: {sql_recall_cycles}%  |  Neo4j: {neo_recall_cycles}%")
    results["recall"] = {
        "gaps_sql_pct": sql_recall_gaps, "gaps_neo4j_pct": neo_recall_gaps,
        "cycles_sql_pct": sql_recall_cycles, "cycles_neo4j_pct": neo_recall_cycles
    }

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 3 — Insider Misuse Profiling
#  Simulated: 20 users with inflated custody action counts (from inject_insider_misuse)
#  Approach A (SQL):   Identify users with unusually high custody event counts
#  Approach B (MongoDB): Aggregate audit_logs by user_id, flag outliers
#  Approach C (Neo4j): Find users connected to many CustodyEvents
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_3():
    _hr("Experiment 3 — Insider Misuse Profiling")
    insider_ids = _load_ids("insider_user_ids")
    _info(f"Injected insider user IDs: {len(insider_ids)}")

    results = {"experiment": 3, "name": "Insider Misuse Profiling",
               "injected_insiders": len(insider_ids)}

    # ── SQL: users with high custody event count ─────────────────────────────────
    def sql_insider_detect():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT u.user_id, u.full_name,
                   COUNT(cl.log_id) AS event_count
            FROM users u
            JOIN coc_logs cl ON (cl.from_user_id = u.user_id
                                  OR cl.to_user_id = u.user_id)
            WHERE cl.action_description LIKE '[SIM]%'
            GROUP BY u.user_id, u.full_name
            ORDER BY event_count DESC
            LIMIT 50;
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows

    sql_users, sql_time = _timed(sql_insider_detect)

    # Compute mean and flag those > mean + 2*stdev
    if sql_users:
        counts = [r[2] for r in sql_users]
        mean   = sum(counts) / len(counts)
        stdev  = (sum((c - mean)**2 for c in counts) / len(counts)) ** 0.5
        threshold = mean + 2 * stdev
        flagged_sql = [(r[0], r[1], r[2]) for r in sql_users if r[2] >= threshold]
    else:
        flagged_sql = []; mean = stdev = threshold = 0

    detected_sql = len(set(r[0] for r in flagged_sql) & set(insider_ids))
    _ok(f"SQL flagged {len(flagged_sql)} users (threshold={threshold:.0f})  ({sql_time}s)")
    _ok(f"  True positives: {detected_sql}/{len(insider_ids)}")
    results["sql"] = {
        "flagged": len(flagged_sql),
        "true_positives": detected_sql,
        "threshold": round(threshold, 1),
        "latency_s": sql_time
    }

    # ── MongoDB: audit_log count per user ────────────────────────────────────────
    def mongo_insider_detect():
        pipeline = [
            {"$group": {"_id": "$user_id", "count": {"$sum": 1}}},
            {"$sort":  {"count": -1}},
            {"$limit": 50}
        ]
        return list(mongo_db.audit_logs.aggregate(pipeline))

    mongo_users, mongo_time = _timed(mongo_insider_detect)

    if mongo_users:
        m_counts = [r["count"] for r in mongo_users]
        m_mean   = sum(m_counts) / len(m_counts)
        m_stdev  = (sum((c - m_mean)**2 for c in m_counts) / len(m_counts)) ** 0.5
        m_thresh = m_mean + 2 * m_stdev
        flagged_mongo = [r for r in mongo_users if r["count"] >= m_thresh]
    else:
        flagged_mongo = []; m_thresh = 0

    detected_mongo = len(
        set(r["_id"] for r in flagged_mongo if r["_id"]) & set(insider_ids)
    )
    _ok(f"MongoDB flagged {len(flagged_mongo)} users (threshold={m_thresh:.0f})  ({mongo_time}s)")
    _ok(f"  True positives: {detected_mongo}/{len(insider_ids)}")
    results["mongodb"] = {
        "flagged": len(flagged_mongo),
        "true_positives": detected_mongo,
        "threshold": round(m_thresh, 1),
        "latency_s": mongo_time
    }

    # ── Neo4j: users connected to many CustodyEvent nodes ────────────────────────
    def neo_insider_detect():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (u:User)-[r:FROM|TO]-(ce:CustodyEvent)
                WITH u.user_id AS uid, COUNT(DISTINCT ce) AS degree
                ORDER BY degree DESC
                LIMIT 50
                RETURN uid, degree
            """)
            return list(r)

    try:
        neo_users, neo_time = _timed(neo_insider_detect)
        if neo_users:
            n_counts  = [r["degree"] for r in neo_users]
            n_mean    = sum(n_counts) / len(n_counts)
            n_stdev   = (sum((c - n_mean)**2 for c in n_counts) / len(n_counts)) ** 0.5
            n_thresh  = n_mean + 2 * n_stdev
            flagged_neo = [r for r in neo_users if r["degree"] >= n_thresh]
        else:
            flagged_neo = []; n_thresh = 0

        detected_neo = len(
            set(r["uid"] for r in flagged_neo if r["uid"]) & set(insider_ids)
        )
        _ok(f"Neo4j flagged {len(flagged_neo)} users (threshold={n_thresh:.0f})  ({neo_time}s)")
        _ok(f"  True positives: {detected_neo}/{len(insider_ids)}")
        results["neo4j"] = {
            "flagged": len(flagged_neo),
            "true_positives": detected_neo,
            "threshold": round(n_thresh, 1),
            "latency_s": neo_time
        }
    except Exception as e:
        _warn(f"Neo4j insider query failed: {e}")
        results["neo4j"] = {"flagged": 0, "true_positives": 0, "error": str(e)}

    # ── Recall ────────────────────────────────────────────────────────────────────
    def recall(tp): return round(tp / len(insider_ids) * 100, 1) if insider_ids else 0
    r_sql   = recall(results["sql"]["true_positives"])
    r_mongo = recall(results["mongodb"]["true_positives"])
    r_neo   = recall(results.get("neo4j", {}).get("true_positives", 0))
    _info(f"Recall — SQL: {r_sql}%  |  MongoDB: {r_mongo}%  |  Neo4j: {r_neo}%")
    results["recall"] = {"sql_pct": r_sql, "mongodb_pct": r_mongo, "neo4j_pct": r_neo}

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 4 — Cross-DB Query Performance
#  Measures latency of: SQL-only, Neo4j-only, MongoDB-only, and combined queries
#  Each query is a realistic use case from the system
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_4():
    _hr("Experiment 4 — Query Performance Comparison")

    results = {"experiment": 4, "name": "Query Performance Comparison",
               "trials": 5, "queries": {}}

    # Pick a real evidence_id and case_id from the DB
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT e.evidence_id, e.case_id
        FROM evidence e
        JOIN coc_logs cl ON e.evidence_id = cl.evidence_id
        WHERE e.evidence_tag LIKE '[SIM]%'
        GROUP BY e.evidence_id, e.case_id
        ORDER BY COUNT(cl.log_id) DESC
        LIMIT 1;
    """)
    row = cur.fetchone()
    cur.close(); conn.close()

    if not row:
        _warn("No simulated evidence found — run simulate_data.py first")
        return results

    test_ev_id, test_case_id = row[0], row[1]
    _info(f"Using evidence_id={test_ev_id}, case_id={test_case_id} for benchmarks")

    TRIALS = results["trials"]

    def bench(name, fn, *args, **kwargs):
        times = []
        for _ in range(TRIALS):
            _, t = _timed(fn, *args, **kwargs)
            times.append(t)
        avg = round(sum(times) / len(times), 4)
        mn  = round(min(times), 4)
        mx  = round(max(times), 4)
        _ok(f"{name:<45} avg={avg}s  min={mn}s  max={mx}s")
        return {"avg_s": avg, "min_s": mn, "max_s": mx}

    # ── Q1: SQL — evidence list for a case ───────────────────────────────────────
    def q1_sql():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT e.evidence_id, e.evidence_code, e.evidence_type, u.full_name
            FROM evidence e JOIN users u ON e.uploader_id = u.user_id
            WHERE e.case_id = %s AND e.is_active = TRUE;
        """, (test_case_id,))
        rows = cur.fetchall(); cur.close(); conn.close(); return rows

    results["queries"]["Q1_SQL_evidence_by_case"] = bench(
        "Q1  SQL: evidence by case", q1_sql)

    # ── Q2: SQL — full custody chain with JOIN ────────────────────────────────────
    def q2_sql():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT cl.log_id, cl.action, cl.timestamp,
                   uf.full_name, ut.full_name
            FROM coc_logs cl
            LEFT JOIN users uf ON cl.from_user_id = uf.user_id
            LEFT JOIN users ut ON cl.to_user_id   = ut.user_id
            WHERE cl.evidence_id = %s ORDER BY cl.timestamp;
        """, (test_ev_id,))
        rows = cur.fetchall(); cur.close(); conn.close(); return rows

    results["queries"]["Q2_SQL_custody_chain_join"] = bench(
        "Q2  SQL: custody chain (JOIN)", q2_sql)

    # ── Q3: SQL — window function gap detection ────────────────────────────────
    def q3_sql_window():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            WITH ordered AS (
                SELECT from_user_id, to_user_id, timestamp,
                       LEAD(from_user_id) OVER (ORDER BY timestamp) AS next_from
                FROM coc_logs WHERE evidence_id = %s
            )
            SELECT * FROM ordered
            WHERE next_from IS NOT NULL AND to_user_id <> next_from;
        """, (test_ev_id,))
        rows = cur.fetchall(); cur.close(); conn.close(); return rows

    results["queries"]["Q3_SQL_gap_window_fn"] = bench(
        "Q3  SQL: gap detection (window fn)", q3_sql_window)

    # ── Q4: Neo4j — graph custody chain traversal ─────────────────────────────
    def q4_neo():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence {evidence_id: $eid})-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                OPTIONAL MATCH (u1:User)-[:FROM]->(ce)
                OPTIONAL MATCH (ce)-[:TO]->(u2:User)
                RETURN ce.custody_id, ce.action, ce.timestamp,
                       u1.user_id, u2.user_id
                ORDER BY ce.timestamp
            """, {"eid": test_ev_id})
            return list(r)

    try:
        results["queries"]["Q4_Neo4j_chain_traversal"] = bench(
            "Q4  Neo4j: chain traversal", q4_neo)
    except Exception as e:
        _warn(f"Neo4j Q4 failed: {e}")
        results["queries"]["Q4_Neo4j_chain_traversal"] = {"error": str(e)}

    # ── Q5: Neo4j — cycle detection via pattern match ─────────────────────────
    def q5_neo_cycle():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence {evidence_id: $eid})-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                MATCH (ce)-[:TO]->(u:User)
                WITH u.user_id AS uid, COUNT(*) AS n WHERE n > 1
                RETURN uid, n
            """, {"eid": test_ev_id})
            return list(r)

    try:
        results["queries"]["Q5_Neo4j_cycle_detection"] = bench(
            "Q5  Neo4j: cycle detection", q5_neo_cycle)
    except Exception as e:
        _warn(f"Neo4j Q5 failed: {e}")
        results["queries"]["Q5_Neo4j_cycle_detection"] = {"error": str(e)}

    # ── Q6: MongoDB — case activity log fetch ─────────────────────────────────
    def q6_mongo():
        return list(mongo_db.case_activity_logs.find(
            {"case_id": test_case_id}, {"_id": 0}
        ).sort("timestamp", -1).limit(50))

    results["queries"]["Q6_MongoDB_activity_logs"] = bench(
        "Q6  MongoDB: case activity logs", q6_mongo)

    # ── Q7: MongoDB — audit log aggregation ───────────────────────────────────
    def q7_mongo_agg():
        pipeline = [
            {"$match":  {"case_id": test_case_id}},
            {"$group":  {"_id": "$action", "count": {"$sum": 1}}},
            {"$sort":   {"count": -1}}
        ]
        return list(mongo_db.audit_logs.aggregate(pipeline))

    results["queries"]["Q7_MongoDB_audit_aggregate"] = bench(
        "Q7  MongoDB: audit aggregation", q7_mongo_agg)

    # ── Q8: Combined cross-DB — evidence profile (SQL + Neo4j + MongoDB) ──────
    def q8_combined():
        # SQL
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT e.evidence_id, e.evidence_code, e.file_hash_sha256,
                   COUNT(cl.log_id) AS custody_count
            FROM evidence e
            LEFT JOIN coc_logs cl ON e.evidence_id = cl.evidence_id
            WHERE e.evidence_id = %s
            GROUP BY e.evidence_id, e.evidence_code, e.file_hash_sha256;
        """, (test_ev_id,))
        sql_row = cur.fetchone(); cur.close(); conn.close()

        # Neo4j
        try:
            with driver.session(database=NEO4J_DATABASE) as s:
                r = s.run("""
                    MATCH (e:Evidence {evidence_id: $eid})-[:HAS_CUSTODY_EVENT]->(ce)
                    RETURN COUNT(ce) AS chain_len
                """, {"eid": test_ev_id})
                neo_row = r.single()
        except Exception:
            neo_row = None

        # MongoDB
        mongo_count = mongo_db.case_activity_logs.count_documents(
            {"entity_id": test_ev_id}
        )

        return {"sql": sql_row, "neo": neo_row, "mongo": mongo_count}

    results["queries"]["Q8_Combined_evidence_profile"] = bench(
        "Q8  Combined (SQL+Neo4j+MongoDB) profile", q8_combined)

    # ── Performance summary table ─────────────────────────────────────────────
    _hr("Performance Summary")
    qs = results["queries"]
    print(f"  {'Query':<42}  {'Avg (s)':>8}  {'vs Q2 (SQL JOIN)':>16}")
    print(f"  {'─'*42}  {'─'*8}  {'─'*16}")
    baseline = qs.get("Q2_SQL_custody_chain_join", {}).get("avg_s", 1)
    for qname, qdata in qs.items():
        avg = qdata.get("avg_s")
        if avg is None:
            print(f"  {qname:<42}  {'ERROR':>8}")
            continue
        ratio = f"{avg/baseline:.2f}x" if baseline else "—"
        print(f"  {qname:<42}  {avg:>8.4f}  {ratio:>16}")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Report writer
# ═══════════════════════════════════════════════════════════════════════════════

def write_report(all_results, elapsed_total):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 62,
        "  ECMS Multi-Model Database Experiment Results",
        f"  Generated: {ts}",
        f"  Total runtime: {elapsed_total:.1f}s",
        "=" * 62,
    ]

    for r in all_results:
        lines.append("")
        lines.append(f"Experiment {r['experiment']}: {r['name']}")
        lines.append("─" * 50)

        if r["experiment"] == 1:
            lines.append(f"  Injected tampered hashes : {r['injected']}")
            lines.append(f"  SQL detected             : {r['sql']['detected']}  ({r['sql']['latency_s']}s)")
            lines.append(f"  MongoDB detected         : {r['mongodb']['detected']}  ({r['mongodb']['latency_s']}s)")
            neo = r.get("neo4j", {})
            lines.append(f"  Neo4j detected           : {neo.get('detected', 'N/A')}  ({neo.get('latency_s', '—')}s)")
            lines.append(f"  Recall                   : {r['recall_pct']}%")

        elif r["experiment"] == 2:
            lines.append(f"  Injected chain gaps      : {r['injected_broken']}")
            lines.append(f"  Injected cycles          : {r['injected_cycles']}")
            sg = r.get("sql_gaps", {})
            ng = r.get("neo4j_gaps", {})
            sc = r.get("sql_cycles", {})
            nc = r.get("neo4j_cycles", {})
            lines.append(f"  SQL gap detection        : {sg.get('evidence_with_gaps','N/A')} items  ({sg.get('latency_s','—')}s)")
            lines.append(f"  Neo4j gap detection      : {ng.get('evidence_with_gaps','N/A')} items  ({ng.get('latency_s','—')}s)")
            lines.append(f"  SQL cycle detection      : {sc.get('evidence_with_cycles','N/A')} items  ({sc.get('latency_s','—')}s)")
            lines.append(f"  Neo4j cycle detection    : {nc.get('evidence_with_cycles','N/A')} items  ({nc.get('latency_s','—')}s)")
            recall = r.get("recall", {})
            lines.append(f"  Gap recall  SQL/Neo4j    : {recall.get('gaps_sql_pct','—')}% / {recall.get('gaps_neo4j_pct','—')}%")
            lines.append(f"  Cycle recall SQL/Neo4j   : {recall.get('cycles_sql_pct','—')}% / {recall.get('cycles_neo4j_pct','—')}%")

        elif r["experiment"] == 3:
            lines.append(f"  Injected insider users   : {r['injected_insiders']}")
            for db_key in ("sql", "mongodb", "neo4j"):
                d = r.get(db_key, {})
                lines.append(f"  {db_key.upper():<8} flagged / TP       : {d.get('flagged','N/A')} / {d.get('true_positives','N/A')}  ({d.get('latency_s','—')}s)")
            recall = r.get("recall", {})
            lines.append(f"  Recall SQL/Mongo/Neo4j   : {recall.get('sql_pct','—')}% / {recall.get('mongodb_pct','—')}% / {recall.get('neo4j_pct','—')}%")

        elif r["experiment"] == 4:
            qs = r.get("queries", {})
            baseline = qs.get("Q2_SQL_custody_chain_join", {}).get("avg_s", 1) or 1
            lines.append(f"  {'Query':<42}  Avg(s)   Ratio")
            lines.append(f"  {'─'*42}  ─────── ──────")
            for qname, qdata in qs.items():
                avg = qdata.get("avg_s")
                if avg is None:
                    lines.append(f"  {qname:<42}  ERROR")
                    continue
                ratio = f"{avg/baseline:.2f}x"
                lines.append(f"  {qname:<42}  {avg:.4f}   {ratio}")

    lines.append("")
    lines.append("=" * 62)
    report_text = "\n".join(lines)

    txt_path  = os.path.join(RESULTS_DIR, "experiment_results.txt")
    json_path = os.path.join(RESULTS_DIR, "experiment_results.json")

    with open(txt_path, "w") as f:
        f.write(report_text)

    with open(json_path, "w") as f:
        json.dump({
            "generated_at": datetime.now().isoformat(),
            "total_runtime_s": round(elapsed_total, 2),
            "results": all_results
        }, f, indent=2, default=str)

    print(f"\n  Report saved → {txt_path}")
    print(f"  JSON saved   → {json_path}")
    return report_text


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ECMS Experiment Runner")
    parser.add_argument("--exp", type=int, choices=[1, 2, 3, 4],
                        help="Run only one experiment (1-4)")
    parser.add_argument("--summary", action="store_true",
                        help="Print saved results without re-running")
    args = parser.parse_args()

    if args.summary:
        path = os.path.join(RESULTS_DIR, "experiment_results.txt")
        if os.path.exists(path):
            print(open(path).read())
        else:
            print("No saved results found. Run without --summary first.")
        return

    print()
    print("=" * 62)
    print("  ECMS Multi-Model Database Experiment Runner")
    print("  PostgreSQL  ·  Neo4j  ·  MongoDB")
    print("=" * 62)

    exp_map = {1: experiment_1, 2: experiment_2,
               3: experiment_3, 4: experiment_4}

    if args.exp:
        to_run = [args.exp]
    else:
        to_run = [1, 2, 3, 4]

    all_results = []
    t_start = time.perf_counter()

    for exp_num in to_run:
        try:
            result = exp_map[exp_num]()
            all_results.append(result)
        except Exception as e:
            print(f"\n  [ERROR] Experiment {exp_num} failed: {e}")
            import traceback; traceback.print_exc()

    elapsed = time.perf_counter() - t_start
    _hr()

    if all_results:
        write_report(all_results, elapsed)

    print(f"\n  Done in {elapsed:.1f}s")
    print()


if __name__ == "__main__":
    main()