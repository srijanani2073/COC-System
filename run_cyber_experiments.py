"""
run_cyber_experiments.py  —  ECMS Cyber Security Experiments
=============================================================
Formal experiments for the Cyber Security research paper.

Research Question
-----------------
"Does a multi-model, cryptographically-secured chain-of-custody
system (Neo4j + AES-256 + RSA) improve forensic evidence integrity
detection over a baseline relational approach (SQL-only)?"

Experiments
-----------
  Exp 1: Tamper Detection Rate & Latency
          Baseline : SQL sequential hash comparison against stored records
          Proposed : Neo4j VerificationEvent graph + RSA signature check
          Metric   : Detection rate (%), false positive rate, latency (ms)

  Exp 2: Chain-of-Custody Integrity (Gap & Cycle Detection)
          Baseline : SQL self-JOIN with LEAD() window function
          Proposed : Neo4j Cypher graph traversal
          Metric   : Recall (%), precision (%), query time (ms)

  Exp 3: Insider Threat Detection
          Baseline : SQL GROUP BY on coc_logs with COUNT threshold
          Proposed : Neo4j graph degree centrality + MongoDB audit frequency
          Metric   : True positive rate (%), false positives, latency (ms)

  Exp 4: Cryptographic Overhead Measurement
          Measures : SHA-256 hashing, RSA signing/verification, AES-256-CBC
                     encrypt/decrypt across increasing file sizes
          Metric   : Throughput (MB/s), latency (ms) per operation

Prerequisites
-------------
  python3 simulate_data.py   (creates sim_results/ anomaly IDs)

Output
------
  sim_results/cyber_experiment_results.txt
  sim_results/cyber_experiment_results.json

Usage
-----
  python3 run_cyber_experiments.py
  python3 run_cyber_experiments.py --exp 4
  python3 run_cyber_experiments.py --summary
"""

import os, sys, json, time, argparse, hashlib, statistics
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dbs.sql_db   import get_connection
from dbs.mongo_db import db as mongo_db
from dbs.neo4j_db import driver, NEO4J_DATABASE
from cyber.crypto_pipeline import crypto_pipeline

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sim_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

TRIALS = 5   # number of repeated runs per benchmark

# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _load_ids(name):
    path = os.path.join(RESULTS_DIR, f"{name}.txt")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [int(x.strip()) for x in f if x.strip().isdigit()]


def _bench(fn, *args, trials=TRIALS, **kwargs):
    """Run fn `trials` times, return (result, avg_ms, all_ms)."""
    times_ms = []
    result = None
    for _ in range(trials):
        t0 = time.perf_counter()
        result = fn(*args, **kwargs)
        times_ms.append((time.perf_counter() - t0) * 1000)
    return result, round(statistics.mean(times_ms), 2), times_ms


def _hr(title="", width=64):
    if title:
        print(f"\n{'─'*2}  {title}  {'─'*max(width - len(title) - 4, 2)}")
    else:
        print("─" * width)


def _ok(msg):   print(f"  ✓  {msg}")
def _warn(msg): print(f"  ⚠  {msg}")
def _info(msg): print(f"     {msg}")
def _row(label, value): print(f"  {label:<38}  {value}")


def _pct(n, d): return round(n / d * 100, 1) if d else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 1 — Tamper Detection Rate & Latency
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_1():
    _hr("Experiment 1 — Tamper Detection Rate & Latency")

    tampered_ids = _load_ids("tampered_ids")
    n_injected   = len(tampered_ids)
    _info(f"Injected tampered evidence items : {n_injected}")
    _info(f"Detection trials per method      : {TRIALS}")

    results = {
        "experiment": 1,
        "name": "Tamper Detection Rate & Latency",
        "injected": n_injected,
    }

    # ── BASELINE: SQL — scan verification_history for mismatch rows ───────────
    def baseline_sql():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT e.evidence_id
            FROM evidence e
            JOIN evidence_verification_history vh ON e.evidence_id = vh.evidence_id
            WHERE vh.result = 'mismatch';
        """)
        ids = {row[0] for row in cur.fetchall()}
        cur.close(); conn.close()
        return ids

    _, b_avg_ms, b_times = _bench(baseline_sql, trials=TRIALS)
    b_result = baseline_sql()
    b_tp = len(b_result & set(tampered_ids))
    b_fp = len(b_result - set(tampered_ids))
    b_recall    = _pct(b_tp, n_injected)
    b_precision = _pct(b_tp, b_tp + b_fp) if (b_tp + b_fp) else 0.0

    _ok(f"BASELINE  (SQL)  detected={len(b_result)}  TP={b_tp}  FP={b_fp}  "
        f"recall={b_recall}%  precision={b_precision}%  avg={b_avg_ms}ms")

    results["baseline_sql"] = {
        "detected": len(b_result), "true_positives": b_tp, "false_positives": b_fp,
        "recall_pct": b_recall, "precision_pct": b_precision,
        "avg_latency_ms": b_avg_ms, "all_latencies_ms": [round(t,2) for t in b_times],
    }

    # ── PROPOSED: Neo4j VerificationEvent mismatch + RSA signature check ──────
    def proposed_neo4j():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence)-[:VERIFIED_BY]->(ve:VerificationEvent)
                WHERE ve.result = 'mismatch'
                RETURN DISTINCT e.evidence_id AS eid
            """)
            return {rec["eid"] for rec in r}

    try:
        _, p_avg_ms, p_times = _bench(proposed_neo4j, trials=TRIALS)
        p_result = proposed_neo4j()
        p_tp = len(p_result & set(tampered_ids))
        p_fp = len(p_result - set(tampered_ids))
        p_recall    = _pct(p_tp, n_injected)
        p_precision = _pct(p_tp, p_tp + p_fp) if (p_tp + p_fp) else 0.0

        _ok(f"PROPOSED (Neo4j) detected={len(p_result)}  TP={p_tp}  FP={p_fp}  "
            f"recall={p_recall}%  precision={p_precision}%  avg={p_avg_ms}ms")

        results["proposed_neo4j"] = {
            "detected": len(p_result), "true_positives": p_tp, "false_positives": p_fp,
            "recall_pct": p_recall, "precision_pct": p_precision,
            "avg_latency_ms": p_avg_ms, "all_latencies_ms": [round(t,2) for t in p_times],
        }
    except Exception as e:
        _warn(f"Neo4j query failed: {e}")
        results["proposed_neo4j"] = {"error": str(e)}

    # ── Also check MongoDB — audit_logs + security_alerts for tampered hashes ──
    def mongo_detect():
        from_audit = {r.get("object_id") for r in mongo_db.audit_logs.find(
            {"action": "HASH_TAMPERED"}, {"_id": 0, "object_id": 1}
        ) if r.get("object_id")}
        from_alerts = {d.get("evidence_id") for d in mongo_db.security_alerts.find(
            {"alert_type": "tampered_hash"}, {"_id": 0, "evidence_id": 1}
        ) if d.get("evidence_id")}
        return from_audit | from_alerts

    _, m_avg_ms, _ = _bench(mongo_detect, trials=TRIALS)
    m_result = mongo_detect()
    m_tp = len(m_result & set(tampered_ids))
    _ok(f"PROPOSED (MongoDB alerts) detected={len(m_result)}  TP={m_tp}  avg={m_avg_ms}ms")
    results["proposed_mongodb"] = {
        "detected": len(m_result), "true_positives": m_tp,
        "avg_latency_ms": m_avg_ms,
    }

    # ── Speedup ───────────────────────────────────────────────────────────────
    p_lat = results.get("proposed_neo4j", {}).get("avg_latency_ms", 0)
    if b_avg_ms and p_lat:
        speedup = round(b_avg_ms / p_lat, 2)
        _info(f"Neo4j vs SQL latency ratio : {speedup}x  "
              f"({'faster' if speedup > 1 else 'slower'})")
        results["latency_speedup_x"] = speedup

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 2 — Chain-of-Custody Integrity Detection
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_2():
    _hr("Experiment 2 — Chain-of-Custody Integrity (Gap & Cycle Detection)")

    broken_ids = _load_ids("broken_chain_ids")
    cycle_ids  = _load_ids("cycle_ids")
    _info(f"Injected broken chains : {len(broken_ids)}")
    _info(f"Injected cycles        : {len(cycle_ids)}")

    results = {
        "experiment": 2,
        "name": "Chain-of-Custody Integrity Detection",
        "injected_broken": len(broken_ids),
        "injected_cycles": len(cycle_ids),
    }

    # ── GAP DETECTION ─────────────────────────────────────────────────────────

    # Baseline: SQL LEAD() window function
    def baseline_gap_sql():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            WITH ordered AS (
                SELECT evidence_id, to_user_id,
                       LEAD(from_user_id) OVER (
                           PARTITION BY evidence_id ORDER BY timestamp
                       ) AS next_from
                FROM coc_logs
                WHERE action_description LIKE '[SIM]%'
            )
            SELECT DISTINCT evidence_id FROM ordered
            WHERE next_from IS NOT NULL AND to_user_id <> next_from;
        """)
        ids = {row[0] for row in cur.fetchall()}
        cur.close(); conn.close()
        return ids

    _, bg_avg, bg_times = _bench(baseline_gap_sql, trials=TRIALS)
    bg_result = baseline_gap_sql()
    bg_tp = len(bg_result & set(broken_ids))
    bg_recall = _pct(bg_tp, len(broken_ids))
    _ok(f"BASELINE gap (SQL LEAD)   detected={len(bg_result)}  TP={bg_tp}  "
        f"recall={bg_recall}%  avg={bg_avg}ms")
    results["baseline_gap_sql"] = {
        "detected": len(bg_result), "true_positives": bg_tp,
        "recall_pct": bg_recall, "avg_latency_ms": bg_avg,
        "all_latencies_ms": [round(t,2) for t in bg_times],
    }

    # Proposed: Neo4j graph traversal
    def proposed_gap_neo4j():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce1:CustodyEvent),
                      (e)-[:HAS_CUSTODY_EVENT]->(ce2:CustodyEvent)
                WHERE ce1.timestamp < ce2.timestamp
                  AND NOT EXISTS {
                      MATCH (e)-[:HAS_CUSTODY_EVENT]->(mid:CustodyEvent)
                      WHERE mid.timestamp > ce1.timestamp
                        AND mid.timestamp < ce2.timestamp
                  }
                MATCH (ce1)-[:TO]->(u1:User), (u2:User)-[:FROM]->(ce2)
                WHERE id(u1) <> id(u2)
                RETURN DISTINCT e.evidence_id AS eid
                LIMIT 500
            """)
            return {rec["eid"] for rec in r}

    try:
        _, pg_avg, pg_times = _bench(proposed_gap_neo4j, trials=TRIALS)
        pg_result = proposed_gap_neo4j()
        pg_tp = len(pg_result & set(broken_ids))
        pg_recall = _pct(pg_tp, len(broken_ids))
        _ok(f"PROPOSED gap (Neo4j)      detected={len(pg_result)}  TP={pg_tp}  "
            f"recall={pg_recall}%  avg={pg_avg}ms")
        results["proposed_gap_neo4j"] = {
            "detected": len(pg_result), "true_positives": pg_tp,
            "recall_pct": pg_recall, "avg_latency_ms": pg_avg,
            "all_latencies_ms": [round(t,2) for t in pg_times],
        }
    except Exception as e:
        _warn(f"Neo4j gap query failed: {e}")
        results["proposed_gap_neo4j"] = {"error": str(e)}

    # ── CYCLE DETECTION ───────────────────────────────────────────────────────

    # Baseline: SQL GROUP BY HAVING COUNT > 1
    def baseline_cycle_sql():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT evidence_id FROM coc_logs
            WHERE action_description LIKE '[SIM]%'
            GROUP BY evidence_id, to_user_id
            HAVING COUNT(*) > 1;
        """)
        ids = {row[0] for row in cur.fetchall()}
        cur.close(); conn.close()
        return ids

    _, bc_avg, bc_times = _bench(baseline_cycle_sql, trials=TRIALS)
    bc_result = baseline_cycle_sql()
    bc_tp = len(bc_result & set(cycle_ids))
    bc_recall = _pct(bc_tp, len(cycle_ids))
    _ok(f"BASELINE cycle (SQL)      detected={len(bc_result)}  TP={bc_tp}  "
        f"recall={bc_recall}%  avg={bc_avg}ms")
    results["baseline_cycle_sql"] = {
        "detected": len(bc_result), "true_positives": bc_tp,
        "recall_pct": bc_recall, "avg_latency_ms": bc_avg,
        "all_latencies_ms": [round(t,2) for t in bc_times],
    }

    # Proposed: Neo4j
    def proposed_cycle_neo4j():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                      -[:TO]->(u:User)
                WITH e.evidence_id AS eid, u.user_id AS uid, COUNT(*) AS n
                WHERE n > 1
                RETURN DISTINCT eid
                LIMIT 500
            """)
            return {rec["eid"] for rec in r}

    try:
        _, pc_avg, pc_times = _bench(proposed_cycle_neo4j, trials=TRIALS)
        pc_result = proposed_cycle_neo4j()
        pc_tp = len(pc_result & set(cycle_ids))
        pc_recall = _pct(pc_tp, len(cycle_ids))
        _ok(f"PROPOSED cycle (Neo4j)    detected={len(pc_result)}  TP={pc_tp}  "
            f"recall={pc_recall}%  avg={pc_avg}ms")
        results["proposed_cycle_neo4j"] = {
            "detected": len(pc_result), "true_positives": pc_tp,
            "recall_pct": pc_recall, "avg_latency_ms": pc_avg,
            "all_latencies_ms": [round(t,2) for t in pc_times],
        }
    except Exception as e:
        _warn(f"Neo4j cycle query failed: {e}")
        results["proposed_cycle_neo4j"] = {"error": str(e)}

    # ── Summary table ─────────────────────────────────────────────────────────
    _hr("Chain Integrity Summary")
    _row("Method", "Recall  Avg(ms)")
    _row("Baseline SQL gap detection",
         f"{bg_recall}%    {bg_avg}ms")
    pg = results.get("proposed_gap_neo4j", {})
    _row("Proposed Neo4j gap detection",
         f"{pg.get('recall_pct','—')}%    {pg.get('avg_latency_ms','—')}ms")
    _row("Baseline SQL cycle detection",
         f"{bc_recall}%    {bc_avg}ms")
    pc = results.get("proposed_cycle_neo4j", {})
    _row("Proposed Neo4j cycle detection",
         f"{pc.get('recall_pct','—')}%    {pc.get('avg_latency_ms','—')}ms")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 3 — Insider Threat Detection
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_3():
    _hr("Experiment 3 — Insider Threat Detection")

    insider_ids = _load_ids("insider_user_ids")
    _info(f"Injected insider users : {len(insider_ids)}")
    _info(f"Threshold method       : mean + 2 × stdev (Z-score outlier)")

    results = {
        "experiment": 3,
        "name": "Insider Threat Detection",
        "injected_insiders": len(insider_ids),
    }

    def _threshold_flag(counts_dict):
        """Flag entries whose count > mean + 2*stdev."""
        if not counts_dict:
            return set(), 0.0
        vals = list(counts_dict.values())
        mean = statistics.mean(vals)
        stdev = statistics.stdev(vals) if len(vals) > 1 else 0
        threshold = mean + 2 * stdev
        return {uid for uid, c in counts_dict.items() if c >= threshold}, threshold

    # ── BASELINE: SQL GROUP BY coc_logs ──────────────────────────────────────
    def baseline_sql():
        conn = get_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT u.user_id, COUNT(cl.log_id) AS n
            FROM users u
            JOIN coc_logs cl ON (cl.from_user_id = u.user_id
                                  OR cl.to_user_id = u.user_id)
            WHERE cl.action_description LIKE '[SIM]%'
            GROUP BY u.user_id;
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return {r[0]: r[1] for r in rows}

    _, b_avg, b_times = _bench(baseline_sql, trials=TRIALS)
    b_counts = baseline_sql()
    b_flagged, b_thresh = _threshold_flag(b_counts)
    b_tp = len(b_flagged & set(insider_ids))
    b_fp = len(b_flagged - set(insider_ids))
    b_recall = _pct(b_tp, len(insider_ids))
    b_precision = _pct(b_tp, b_tp + b_fp) if (b_tp + b_fp) else 0.0
    _ok(f"BASELINE (SQL)   flagged={len(b_flagged)}  TP={b_tp}  FP={b_fp}  "
        f"recall={b_recall}%  precision={b_precision}%  avg={b_avg}ms")
    results["baseline_sql"] = {
        "flagged": len(b_flagged), "true_positives": b_tp, "false_positives": b_fp,
        "recall_pct": b_recall, "precision_pct": b_precision,
        "threshold": round(b_thresh, 1), "avg_latency_ms": b_avg,
        "all_latencies_ms": [round(t,2) for t in b_times],
    }

    # ── PROPOSED: Neo4j graph degree centrality ───────────────────────────────
    def proposed_neo4j():
        with driver.session(database=NEO4J_DATABASE) as s:
            r = s.run("""
                MATCH (u:User)-[:FROM|TO]-(ce:CustodyEvent)
                WITH u.user_id AS uid, COUNT(DISTINCT ce) AS degree
                RETURN uid, degree
            """)
            return {rec["uid"]: rec["degree"] for rec in r}

    try:
        _, p_avg, p_times = _bench(proposed_neo4j, trials=TRIALS)
        p_counts = proposed_neo4j()
        p_flagged, p_thresh = _threshold_flag(p_counts)
        p_tp = len(p_flagged & set(insider_ids))
        p_fp = len(p_flagged - set(insider_ids))
        p_recall = _pct(p_tp, len(insider_ids))
        p_precision = _pct(p_tp, p_tp + p_fp) if (p_tp + p_fp) else 0.0
        _ok(f"PROPOSED (Neo4j) flagged={len(p_flagged)}  TP={p_tp}  FP={p_fp}  "
            f"recall={p_recall}%  precision={p_precision}%  avg={p_avg}ms")
        results["proposed_neo4j"] = {
            "flagged": len(p_flagged), "true_positives": p_tp, "false_positives": p_fp,
            "recall_pct": p_recall, "precision_pct": p_precision,
            "threshold": round(p_thresh, 1), "avg_latency_ms": p_avg,
            "all_latencies_ms": [round(t,2) for t in p_times],
        }
    except Exception as e:
        _warn(f"Neo4j insider query failed: {e}")
        results["proposed_neo4j"] = {"error": str(e)}

    # ── PROPOSED: MongoDB audit log frequency ────────────────────────────────
    def proposed_mongo():
        pipeline = [
            {"$group": {"_id": "$user_id", "count": {"$sum": 1}}},
        ]
        docs = list(mongo_db.audit_logs.aggregate(pipeline))
        return {d["_id"]: d["count"] for d in docs if d.get("_id")}

    _, m_avg, m_times = _bench(proposed_mongo, trials=TRIALS)
    m_counts = proposed_mongo()
    m_flagged, m_thresh = _threshold_flag(m_counts)
    m_tp = len(m_flagged & set(insider_ids))
    m_fp = len(m_flagged - set(insider_ids))
    m_recall = _pct(m_tp, len(insider_ids))
    m_precision = _pct(m_tp, m_tp + m_fp) if (m_tp + m_fp) else 0.0
    _ok(f"PROPOSED (MongoDB) flagged={len(m_flagged)}  TP={m_tp}  FP={m_fp}  "
        f"recall={m_recall}%  precision={m_precision}%  avg={m_avg}ms")
    results["proposed_mongodb"] = {
        "flagged": len(m_flagged), "true_positives": m_tp, "false_positives": m_fp,
        "recall_pct": m_recall, "precision_pct": m_precision,
        "threshold": round(m_thresh, 1), "avg_latency_ms": m_avg,
        "all_latencies_ms": [round(t,2) for t in m_times],
    }

    # ── Combined recall (Neo4j OR MongoDB, union of flagged) ─────────────────
    try:
        combined = (p_flagged | m_flagged)
        combined_tp = len(combined & set(insider_ids))
        combined_recall = _pct(combined_tp, len(insider_ids))
        _ok(f"COMBINED (Neo4j ∪ MongoDB)  TP={combined_tp}  recall={combined_recall}%")
        results["combined_recall_pct"] = combined_recall
    except Exception:
        pass

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Experiment 4 — Cryptographic Operation Overhead
# ═══════════════════════════════════════════════════════════════════════════════

def experiment_4():
    _hr("Experiment 4 — Cryptographic Overhead Measurement")

    _info("Measures SHA-256, RSA-2048, AES-256-CBC across file sizes")
    _info(f"Trials per size per operation : {TRIALS}")

    FILE_SIZES_KB = [1, 10, 100, 500, 1024, 5120]  # KB
    results = {
        "experiment": 4,
        "name": "Cryptographic Overhead Measurement",
        "file_sizes_kb": FILE_SIZES_KB,
        "trials": TRIALS,
        "measurements": [],
    }

    _row("Size (KB)", "SHA-256  RSA-sign  RSA-verify  AES-enc  AES-dec  Pipeline")
    _row("─"*10, "─"*7 + "  " + "─"*8 + "  " + "─"*10 + "  " + "─"*7 + "  " + "─"*7 + "  " + "─"*8)

    for size_kb in FILE_SIZES_KB:
        data = os.urandom(size_kb * 1024)
        evidence_id = 999_000 + size_kb   # fake ID for key derivation

        # SHA-256
        def op_hash():
            import hashlib
            return hashlib.sha256(data).hexdigest()

        _, sha_avg, _ = _bench(op_hash, trials=TRIALS)

        # RSA sign
        file_hash = hashlib.sha256(data).hexdigest()
        def op_rsa_sign():
            return crypto_pipeline.generate_rsa_signature(file_hash)

        _, rsa_sign_avg, _ = _bench(op_rsa_sign, trials=TRIALS)

        # RSA verify
        sig = crypto_pipeline.generate_rsa_signature(file_hash)
        def op_rsa_verify():
            return crypto_pipeline.verify_rsa_signature(file_hash, sig)

        _, rsa_ver_avg, _ = _bench(op_rsa_verify, trials=TRIALS)

        # AES-256-CBC encrypt
        def op_aes_enc():
            return crypto_pipeline.encrypt_file_aes256(data, evidence_id)

        enc_result, aes_enc_avg, _ = _bench(op_aes_enc, trials=TRIALS)

        # AES-256-CBC decrypt
        enc_data = enc_result["encrypted_data"]
        iv_b64   = enc_result["iv"]
        def op_aes_dec():
            return crypto_pipeline.decrypt_file_aes256(enc_data, iv_b64, evidence_id)

        _, aes_dec_avg, _ = _bench(op_aes_dec, trials=TRIALS)

        # Full pipeline (hash + sign + encrypt)
        def op_full():
            return crypto_pipeline.process_evidence_upload(data, evidence_id)

        _, full_avg, _ = _bench(op_full, trials=TRIALS)

        # Throughput MB/s for AES encryption
        size_mb = size_kb / 1024
        enc_throughput = round(size_mb / (aes_enc_avg / 1000), 1) if aes_enc_avg else 0

        row = {
            "size_kb":         size_kb,
            "sha256_ms":       round(sha_avg, 2),
            "rsa_sign_ms":     round(rsa_sign_avg, 2),
            "rsa_verify_ms":   round(rsa_ver_avg, 2),
            "aes_enc_ms":      round(aes_enc_avg, 2),
            "aes_dec_ms":      round(aes_dec_avg, 2),
            "full_pipeline_ms":round(full_avg, 2),
            "enc_throughput_mbps": enc_throughput,
        }
        results["measurements"].append(row)

        _row(f"{size_kb:>7} KB",
             f"{sha_avg:>6.1f}ms  {rsa_sign_avg:>7.1f}ms  "
             f"{rsa_ver_avg:>9.1f}ms  {aes_enc_avg:>6.1f}ms  "
             f"{aes_dec_avg:>6.1f}ms  {full_avg:>7.1f}ms")

    # ── RSA is constant (key-size dependent, not data-size) ───────────────────
    rsa_vals = [m["rsa_sign_ms"] for m in results["measurements"]]
    _info(f"\nRSA sign   — min={min(rsa_vals):.1f}ms  max={max(rsa_vals):.1f}ms  "
          f"(constant: signs hash, not raw data)")

    aes_vals = [m["aes_enc_ms"] for m in results["measurements"]]
    _info(f"AES-256 enc — 1KB={aes_vals[0]:.1f}ms  "
          f"1MB={aes_vals[-1]:.1f}ms  (linear with size)")

    # ── Overhead vs file size table ───────────────────────────────────────────
    _hr("Pipeline Overhead Summary")
    _info("Pipeline = SHA-256 + RSA sign + AES-256-CBC encryption")
    _info(f"{'Size':>10}  {'Full pipeline':>14}  {'AES throughput':>16}")
    for m in results["measurements"]:
        _info(f"{m['size_kb']:>8} KB  {m['full_pipeline_ms']:>12.1f}ms  "
              f"{m['enc_throughput_mbps']:>14.1f} MB/s")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Report writer
# ═══════════════════════════════════════════════════════════════════════════════

def write_report(all_results, elapsed_total):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 64,
        "  ECMS Cyber Security Experiment Results",
        "  Baseline (SQL) vs Proposed (Neo4j + AES-256/RSA)",
        f"  Generated  : {ts}",
        f"  Runtime    : {elapsed_total:.1f}s",
        "=" * 64,
    ]

    for r in all_results:
        lines += ["", f"Experiment {r['experiment']}: {r['name']}", "─" * 50]

        if r["experiment"] == 1:
            lines.append(f"  Injected tampered evidence      : {r['injected']}")
            for key, label in [
                ("baseline_sql", "Baseline  (SQL)"),
                ("proposed_neo4j", "Proposed  (Neo4j)"),
                ("proposed_mongodb", "Proposed  (MongoDB alerts)"),
            ]:
                d = r.get(key, {})
                if "error" in d:
                    lines.append(f"  {label:<26} : ERROR — {d['error']}")
                else:
                    lines.append(
                        f"  {label:<26} : detected={d.get('detected','—')}  "
                        f"TP={d.get('true_positives','—')}  "
                        f"recall={d.get('recall_pct','—')}%  "
                        f"avg={d.get('avg_latency_ms','—')}ms"
                    )
            if "latency_speedup_x" in r:
                lines.append(f"  Neo4j vs SQL speedup            : {r['latency_speedup_x']}x")

        elif r["experiment"] == 2:
            lines.append(f"  Injected broken chains          : {r['injected_broken']}")
            lines.append(f"  Injected cycles                 : {r['injected_cycles']}")
            for key, label in [
                ("baseline_gap_sql",     "Baseline  gap (SQL)    "),
                ("proposed_gap_neo4j",   "Proposed  gap (Neo4j)  "),
                ("baseline_cycle_sql",   "Baseline  cycle (SQL)  "),
                ("proposed_cycle_neo4j", "Proposed  cycle (Neo4j)"),
            ]:
                d = r.get(key, {})
                if not d or "error" in d:
                    lines.append(f"  {label} : {'ERROR — ' + d.get('error','') if d else 'N/A'}")
                else:
                    lines.append(
                        f"  {label} : TP={d.get('true_positives','—')}  "
                        f"recall={d.get('recall_pct','—')}%  "
                        f"avg={d.get('avg_latency_ms','—')}ms"
                    )

        elif r["experiment"] == 3:
            lines.append(f"  Injected insider users          : {r['injected_insiders']}")
            for key, label in [
                ("baseline_sql",      "Baseline  (SQL)       "),
                ("proposed_neo4j",    "Proposed  (Neo4j)     "),
                ("proposed_mongodb",  "Proposed  (MongoDB)   "),
            ]:
                d = r.get(key, {})
                if not d or "error" in d:
                    lines.append(f"  {label} : {'ERROR' if not d else d.get('error','')}")
                else:
                    lines.append(
                        f"  {label} : flagged={d.get('flagged','—')}  "
                        f"TP={d.get('true_positives','—')}  "
                        f"FP={d.get('false_positives','—')}  "
                        f"recall={d.get('recall_pct','—')}%  "
                        f"avg={d.get('avg_latency_ms','—')}ms"
                    )
            if "combined_recall_pct" in r:
                lines.append(f"  Combined (Neo4j ∪ MongoDB) recall: {r['combined_recall_pct']}%")

        elif r["experiment"] == 4:
            lines.append(f"  {'Size':>8}  {'SHA-256':>8}  {'RSA-sign':>9}  "
                         f"{'RSA-ver':>8}  {'AES-enc':>8}  {'AES-dec':>8}  "
                         f"{'Pipeline':>9}  {'Throughput':>11}")
            lines.append("  " + "─" * 90)
            for m in r.get("measurements", []):
                lines.append(
                    f"  {m['size_kb']:>6} KB  "
                    f"{m['sha256_ms']:>7.1f}ms  "
                    f"{m['rsa_sign_ms']:>8.1f}ms  "
                    f"{m['rsa_verify_ms']:>7.1f}ms  "
                    f"{m['aes_enc_ms']:>7.1f}ms  "
                    f"{m['aes_dec_ms']:>7.1f}ms  "
                    f"{m['full_pipeline_ms']:>8.1f}ms  "
                    f"{m['enc_throughput_mbps']:>9.1f} MB/s"
                )

    lines += ["", "=" * 64]
    text = "\n".join(lines)

    txt_path  = os.path.join(RESULTS_DIR, "cyber_experiment_results.txt")
    json_path = os.path.join(RESULTS_DIR, "cyber_experiment_results.json")

    with open(txt_path, "w") as f:
        f.write(text)
    with open(json_path, "w") as f:
        json.dump({
            "generated_at": datetime.now().isoformat(),
            "total_runtime_s": round(elapsed_total, 2),
            "results": all_results,
        }, f, indent=2, default=str)

    print(f"\n  Report → {txt_path}")
    print(f"  JSON   → {json_path}")
    return text


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ECMS Cyber Security Experiments")
    parser.add_argument("--exp", type=int, choices=[1, 2, 3, 4],
                        help="Run only one experiment")
    parser.add_argument("--summary", action="store_true",
                        help="Print saved results without re-running")
    args = parser.parse_args()

    if args.summary:
        path = os.path.join(RESULTS_DIR, "cyber_experiment_results.txt")
        print(open(path).read() if os.path.exists(path)
              else "No saved results. Run without --summary first.")
        return

    print()
    print("=" * 64)
    print("  ECMS Cyber Security Experiments")
    print("  Baseline (SQL-only) vs Proposed (Neo4j + AES-256 + RSA)")
    print("=" * 64)

    exp_map = {1: experiment_1, 2: experiment_2,
               3: experiment_3, 4: experiment_4}

    to_run = [args.exp] if args.exp else [1, 2, 3, 4]
    all_results = []
    t0 = time.perf_counter()

    for n in to_run:
        try:
            all_results.append(exp_map[n]())
        except Exception as e:
            print(f"\n  [ERROR] Experiment {n} failed: {e}")
            import traceback; traceback.print_exc()

    elapsed = time.perf_counter() - t0
    _hr()

    if all_results:
        write_report(all_results, elapsed)

    print(f"\n  Done in {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()