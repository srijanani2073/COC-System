from flask import render_template, request, session
from datetime import datetime, timezone
from dbs.sql_db import get_connection
from dbs.mongo_db import get_case_timeline, get_alerts
from dbs.neo4j_db import neo_get_custody_chain

def register_other_routes(app, login_required, role_required):
    @app.route("/dashboard")
    @login_required
    def dashboard():
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM cases;")
        total_cases = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cases WHERE status = 'open';")
        open_cases = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM evidence;")
        total_evidence = cur.fetchone()[0]

        cur.close()
        conn.close()
        
        alerts_count = len(get_alerts())

        from dbs.mongo_db import get_recent_activity_for_user, get_recent_activity_all
        role = session.get('role','Unknown')
        user_id = session.get('user_id',1)
        if role in ['Admin','Investigator']:
            recent_activity = get_recent_activity_all(limit=8)
        else:
            recent_activity = get_recent_activity_for_user(user_id, limit=8)
        return render_template(
            "dashboard.html",
            user=session.get('full_name', 'User'),
            role=role,
            total_cases=total_cases,
            open_cases=open_cases,
            total_evidence=total_evidence,
            alerts_count=alerts_count,
            recent_activity=recent_activity
        )

    @app.route("/timeline")
    @login_required
    def timeline():
        case_id = request.args.get("case_id", type=int)
        timeline_events = get_case_timeline(case_id) if case_id else []
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT case_id, case_number, title
            FROM cases
            ORDER BY created_at DESC;
        """)
        cases = [{"id": r[0], "case_number": r[1], "title": r[2]} for r in cur.fetchall()]
        cur.close()
        conn.close()
        
        return render_template(
            "timeline.html",
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown'),
            timeline=timeline_events,
            cases=cases,
            selected_case_id=case_id
        )

    @app.route("/reports")
    @login_required
    def reports():
        case_id = request.args.get("case_id", type=int)
        report_data = None

        if case_id:
            conn = get_connection()
            cur  = conn.cursor()

            # ── Case info ──────────────────────────────────────────────────
            cur.execute("""
                SELECT c.case_id, c.case_number, c.title, c.description,
                       c.status, c.created_at, u.full_name as created_by
                FROM cases c JOIN users u ON c.created_by = u.user_id
                WHERE c.case_id = %s;
            """, (case_id,))
            case_row = cur.fetchone()

            if case_row:
                # ── Evidence list (SQL) ────────────────────────────────────
                cur.execute("""
                    SELECT e.evidence_id, e.evidence_code, e.evidence_type,
                           e.evidence_tag, e.upload_time, e.file_hash_sha256,
                           e.size_bytes, e.last_verified_at
                    FROM evidence e
                    WHERE e.case_id = %s AND e.is_active = TRUE
                    ORDER BY e.created_at;
                """, (case_id,))
                evidence_list = []
                for ev in cur.fetchall():
                    size_kb = f"{(ev[6]/1024):.1f} KB" if ev[6] else "—"
                    evidence_list.append({
                        "id": ev[0], "code": ev[1], "type": ev[2],
                        "tag": ev[3] or ev[1], "uploaded": ev[4],
                        "hash": ev[5][:12] if ev[5] else "N/A",
                        "size_kb": size_kb, "last_verified": ev[7]
                    })

                # ── Custody summary per evidence (SQL) ─────────────────────
                custody_summary = []
                for ev in evidence_list:
                    cur.execute(
                        "SELECT COUNT(*) FROM coc_logs WHERE evidence_id = %s;",
                        (ev['id'],)
                    )
                    custody_summary.append({
                        "evidence_code": ev['code'],
                        "custody_events": cur.fetchone()[0]
                    })

                # ── Full custody chains per evidence (SQL) ─────────────────
                custody_chains = []
                for ev in evidence_list:
                    cur.execute("""
                        SELECT cl.log_id, cl.action, cl.action_description,
                               cl.location, cl.timestamp,
                               uf.full_name, ut.full_name
                        FROM coc_logs cl
                        LEFT JOIN users uf ON cl.from_user_id = uf.user_id
                        LEFT JOIN users ut ON cl.to_user_id   = ut.user_id
                        WHERE cl.evidence_id = %s
                        ORDER BY cl.timestamp ASC;
                    """, (ev['id'],))
                    events = [
                        {"log_id": r[0], "action": r[1], "description": r[2],
                         "location": r[3], "timestamp": r[4],
                         "from_user": r[5] or "—", "to_user": r[6] or "—"}
                        for r in cur.fetchall()
                    ]
                    custody_chains.append({
                        "evidence_code": ev['code'],
                        "evidence_id": ev['id'],
                        "events": events,
                        "anomaly_count": 0  # will fill from neo4j below
                    })

                cur.close(); conn.close()

                # ── Neo4j stats ────────────────────────────────────────────
                neo_stats = {
                    "total_chain_events": 0,
                    "total_anomalies": 0,
                    "max_chain": 0,
                    "anomalies": []
                }
                try:
                    from dbs.neo4j_db import driver, NEO4J_DATABASE
                    with driver.session(database=NEO4J_DATABASE) as s:
                        # Count all CustodyEvent nodes for this case's evidence
                        ev_ids = [ev['id'] for ev in evidence_list]
                        if ev_ids:
                            result = s.run("""
                                MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                                WHERE e.evidence_id IN $ids
                                RETURN count(ce) AS total, max(size([(e2)-[:HAS_CUSTODY_EVENT]->(ce2)
                                    WHERE e2.evidence_id IN $ids | ce2])) AS max_depth
                            """, {"ids": ev_ids})
                            row = result.single()
                            if row:
                                neo_stats["total_chain_events"] = row["total"] or 0
                                neo_stats["max_chain"] = row["max_depth"] or 0

                    # Anomaly check per evidence
                    from cyber.query_interface import detect_anomalies
                    all_anomalies = []
                    for chain in custody_chains:
                        try:
                            res = detect_anomalies(chain["evidence_id"])
                            a_list = res.get("anomalies", [])
                            chain["anomaly_count"] = len(a_list)
                            all_anomalies.extend(a_list[:2])
                        except Exception:
                            pass
                    neo_stats["anomalies"] = all_anomalies[:8]
                    neo_stats["total_anomalies"] = sum(c["anomaly_count"] for c in custody_chains)
                except Exception:
                    pass

                # ── MongoDB stats ──────────────────────────────────────────
                mongo_stats = {"total_logs": 0}
                timeline = []
                try:
                    timeline = get_case_timeline(case_id)
                    from dbs.mongo_db import db as mongo_db
                    mongo_stats["total_logs"] = mongo_db.case_activity_logs.count_documents(
                        {"case_id": case_id}
                    )
                except Exception:
                    pass

                report_data = {
                    "case": {
                        "id": case_row[0], "number": case_row[1],
                        "title": case_row[2], "description": case_row[3],
                        "status": case_row[4], "created_at": case_row[5],
                        "created_by": case_row[6]
                    },
                    "evidence": evidence_list,
                    "custody_summary": custody_summary,
                    "custody_chains": custody_chains,
                    "timeline": timeline[:20],
                    "neo_stats": neo_stats,
                    "mongo_stats": mongo_stats,
                }
            else:
                cur.close(); conn.close()

        conn2 = get_connection()
        cur2  = conn2.cursor()
        cur2.execute("SELECT case_id, case_number, title FROM cases ORDER BY created_at DESC;")
        cases = [{"id": r[0], "case_number": r[1], "title": r[2]} for r in cur2.fetchall()]
        cur2.close(); conn2.close()

        return render_template(
            "reports.html",
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown'),
            cases=cases,
            report=report_data,
            generated_at=datetime.now(timezone.utc)
        )

    @app.route("/alerts")
    @login_required
    @role_required('Admin', 'Investigator')
    def alerts():
        from dbs.mongo_db import get_alerts, get_failed_login_attempts, get_security_alerts
        all_alerts = get_alerts()
        failed_logins = get_failed_login_attempts(limit=20)
        security_alerts = get_security_alerts()
        
        return render_template(
            "alerts.html",
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown'),
            alerts=all_alerts,
            failed_logins=failed_logins,
            security_alerts=security_alerts
        )

    @app.route("/users")
    @login_required
    @role_required('Admin')
    def users():
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                u.user_id,
                u.full_name,
                r.role_name,
                COUNT(c.case_id) AS case_count
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN cases c ON u.user_id = c.created_by
            GROUP BY u.user_id, u.full_name, r.role_name
            ORDER BY u.full_name;
        """)

        user_rows = cur.fetchall()
        role_stats = cur.fetchall()
        cur.close()
        conn.close()

        users_list = []
        for r in user_rows:
            users_list.append({
                "name": r[1],
                "role": r[2],
                "case_count": r[3]
            })

        role_stats_list = []
        for r in role_stats:
            role_stats_list.append({
                "role": r[0],
                "case_count": r[1]
            })

        return render_template(
            "users.html",
            users=users_list,
            role_stats=role_stats_list,
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )
# Patch dashboard to include recent_activity
# (replace in register_other_routes)
