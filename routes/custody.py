from flask import render_template, request, redirect, session, flash, url_for, jsonify
from datetime import datetime, timedelta, timezone

_IST = timezone(timedelta(hours=5, minutes=30))
def _now_ist(): return datetime.now(_IST)
from dbs.sql_db import get_connection
from dbs.mongo_db import log_custody_activity, log_case_activity
from dbs.neo4j_db import (neo_add_custody_event, neo_get_custody_chain,
                           neo_detect_custody_gaps, neo_detect_cycles,
                           neo_get_graph_data, neo_merge_user)


def _build_graph_from_sql(evidence_info, custody_chain, case_info=None, uploader_info=None):
    """SQL fallback graph — mirrors the full Neo4j schema."""
    nodes, edges, node_ids = [], [], set()

    def add_node(nid, label, group, extra=None):
        if nid not in node_ids:
            n = {"id": nid, "label": label, "group": group}
            if extra:
                n.update(extra)
            nodes.append(n)
            node_ids.add(nid)

    def add_edge(frm, to, label):
        edges.append({"from": frm, "to": to, "label": label, "arrows": "to"})

    if evidence_info:
        ev_node = f"ev_{evidence_info['id']}"
        add_node(ev_node, evidence_info["code"], "evidence",
                 {"title": evidence_info.get("tag", "")})

        # Case node
        if case_info:
            c_node = f"case_{case_info['id']}"
            add_node(c_node,
                     case_info.get("case_number", f"Case {case_info['id']}"),
                     "case", {"status": case_info.get("status")})
            add_edge(c_node, ev_node, "HAS_EVIDENCE")

            # Case creator
            if case_info.get("creator_id"):
                cu_node = f"user_{case_info['creator_id']}"
                add_node(cu_node,
                         case_info.get("creator_name", f"User {case_info['creator_id']}"),
                         "user", {"subtitle": "case creator"})
                add_edge(cu_node, c_node, "CREATED")

        # Uploader node
        if uploader_info:
            up_node = f"user_{uploader_info['id']}"
            add_node(up_node,
                     uploader_info.get("name", f"User {uploader_info['id']}"),
                     "user", {"subtitle": "uploader"})
            add_edge(up_node, ev_node, "UPLOADED")

    for i, ev in enumerate(custody_chain):
        fu_node = f"user_{ev['from_user_id']}"
        tu_node = f"user_{ev['to_user_id']}"
        ce_node = f"ce_{ev['custody_id']}"

        add_node(fu_node, ev["from_user"], "user")
        add_node(tu_node, ev["to_user"],   "user")

        short = (ev.get("reason") or "Transfer")[:20]
        add_node(ce_node, short, "custody",
                 {"action": "transfer", "ts": str(ev.get("timestamp", ""))})

        if evidence_info:
            add_edge(f"ev_{evidence_info['id']}", ce_node, "transfer")
        add_edge(fu_node, ce_node, "FROM")
        add_edge(ce_node, tu_node, "TO")

    return {"nodes": nodes, "edges": edges}


def register_custody_routes(app, login_required, role_required):

    @app.route("/custody")
    @login_required
    def custody_view():
        evidence_id = request.args.get("evidence_id", type=int)
        custody_chain, evidence_info = [], None
        gaps_detected, cycles_detected = [], []
        graph_data = {"nodes": [], "edges": []}

        if evidence_id:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT e.evidence_id, e.evidence_code, e.evidence_tag,
                       c.case_id, c.case_number, c.title, c.status,
                       e.is_sealed, e.seal_reason,
                       e.uploader_id, u_up.full_name  AS uploader_name,
                       c.created_by, u_cr.full_name   AS creator_name
                FROM evidence e
                JOIN cases c    ON e.case_id      = c.case_id
                JOIN users u_up ON e.uploader_id  = u_up.user_id
                JOIN users u_cr ON c.created_by   = u_cr.user_id
                WHERE e.evidence_id = %s;
            """, (evidence_id,))
            row = cur.fetchone()
            if row:
                evidence_info = {
                    "id": row[0], "code": row[1], "tag": row[2],
                    "case_number": row[4], "case_title": row[5],
                    "case_status": (row[6] or '').lower(),
                    "is_sealed": row[7] or False, "seal_reason": row[8]
                }
                case_info = {
                    "id": row[3], "case_number": row[4], "status": row[6],
                    "creator_id": row[11], "creator_name": row[12]
                }
                uploader_info = {"id": row[9], "name": row[10]}
            else:
                case_info = uploader_info = None

            # SQL is ground truth for the custody log
            cur.execute("""
                SELECT cl.log_id, cl.from_user_id, cl.to_user_id,
                       cl.action_description, cl.location, cl.timestamp,
                       fu.full_name, tu.full_name
                FROM coc_logs cl
                LEFT JOIN users fu ON cl.from_user_id = fu.user_id
                LEFT JOIN users tu ON cl.to_user_id = tu.user_id
                WHERE cl.evidence_id = %s ORDER BY cl.timestamp ASC;
            """, (evidence_id,))
            for row in cur.fetchall():
                custody_chain.append({
                    "custody_id": row[0], "from_user_id": row[1], "to_user_id": row[2],
                    "from_user": row[6] or f"User {row[1]}", "to_user": row[7] or f"User {row[2]}",
                    "reason": row[3], "location": row[4], "timestamp": row[5]
                })
            cur.close(); conn.close()

            user_names_map = {}
            for ev in custody_chain:
                if ev["from_user_id"]: user_names_map[ev["from_user_id"]] = ev["from_user"]
                if ev["to_user_id"]:   user_names_map[ev["to_user_id"]]   = ev["to_user"]

            # Bulk-fetch all users' full names so the graph labels are always real names
            try:
                conn2 = get_connection(); cur2 = conn2.cursor()
                cur2.execute("SELECT user_id, full_name, username FROM users WHERE is_active = TRUE;")
                for uid, fname, uname in cur2.fetchall():
                    if uid not in user_names_map:
                        user_names_map[uid] = fname or uname or f"User {uid}"
                cur2.close(); conn2.close()
            except Exception:
                pass

            try:
                graph_data = neo_get_graph_data(evidence_id, user_names_map)
                if not graph_data.get("nodes"):
                    graph_data = _build_graph_from_sql(
                        evidence_info, custody_chain, case_info, uploader_info)
            except Exception:
                graph_data = _build_graph_from_sql(
                    evidence_info, custody_chain, case_info, uploader_info)

            try:
                cycles_detected = neo_detect_cycles(evidence_id)
            except Exception:
                cycles_detected = []

            try:
                gaps_detected = neo_detect_custody_gaps(evidence_id)
            except Exception:
                for i in range(len(custody_chain) - 1):
                    if custody_chain[i]["to_user_id"] != custody_chain[i+1]["from_user_id"]:
                        gaps_detected.append({
                            "gap_index": i,
                            "expected_from_user": custody_chain[i]["to_user"],
                            "actual_from_user": custody_chain[i+1]["from_user"],
                            "timestamp": custody_chain[i+1]["timestamp"]
                        })

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT e.evidence_id, e.evidence_code, e.evidence_tag, c.case_number, e.is_sealed
            FROM evidence e JOIN cases c ON e.case_id = c.case_id
            WHERE e.is_active = TRUE ORDER BY e.created_at DESC LIMIT 100;
        """)
        evidence_list = [{"id": r[0], "code": r[1], "tag": r[2],
                          "case_number": r[3], "is_sealed": r[4] or False} for r in cur.fetchall()]
        cur.execute("SELECT user_id, full_name, role_id FROM users WHERE is_active = TRUE ORDER BY full_name;")
        users = [{"id": r[0], "name": r[1], "role_id": r[2]} for r in cur.fetchall()]
        cur.close(); conn.close()

        return render_template("custody.html", user=session.get('full_name', 'User'),
                               role=session.get('role', 'Unknown'), evidence_list=evidence_list,
                               selected_evidence=evidence_info, custody_chain=custody_chain,
                               gaps=gaps_detected, cycles=cycles_detected,
                               graph_data=graph_data, users=users)

    @app.route("/custody/transfer", methods=["POST"])
    @login_required
    @role_required('Admin', 'Investigator')
    def transfer_custody():
        evidence_id = int(request.form.get("evidence_id"))
        to_user_id = int(request.form.get("to_user"))
        reason = request.form.get("reason", "")
        location = request.form.get("location", "Unknown")

        conn = get_connection()
        cur = conn.cursor()
        try:
            # Block transfer if case is closed
            cur.execute("""
                SELECT c.status FROM evidence e
                JOIN cases c ON e.case_id = c.case_id
                WHERE e.evidence_id = %s;
            """, (evidence_id,))
            case_status_row = cur.fetchone()
            if case_status_row and (case_status_row[0] or '').lower() == 'closed':
                cur.close(); conn.close()
                flash('Transfer blocked — this case is closed. Evidence cannot be transferred.', 'error')
                return redirect(f"/custody?evidence_id={evidence_id}")

            cur.execute("SELECT is_sealed, seal_reason, evidence_code FROM evidence WHERE evidence_id = %s;", (evidence_id,))
            seal_row = cur.fetchone()
            if seal_row and seal_row[0]:
                cur.close(); conn.close()
                # Log the blocked attempt to MongoDB
                try:
                    from dbs.mongo_db import log_audit_event as mongo_audit
                    mongo_audit(
                        user_id=session.get('user_id'),
                        action="TRANSFER_BLOCKED_SEALED",
                        object_type="evidence",
                        object_id=evidence_id,
                        description=f"Custody transfer blocked — evidence {seal_row[2]} is sealed: {seal_row[1]}",
                        ip_address=request.remote_addr
                    )
                except Exception:
                    pass
                flash(f'Transfer blocked — evidence is sealed: {seal_row[1]}', 'error')
                return redirect(f"/custody?evidence_id={evidence_id}")

            cur.execute("""
                SELECT to_user_id FROM coc_logs WHERE evidence_id = %s ORDER BY timestamp DESC LIMIT 1;
            """, (evidence_id,))
            result = cur.fetchone()
            from_user_id = result[0] if result else None
            if not from_user_id:
                cur.execute("SELECT uploader_id FROM evidence WHERE evidence_id = %s;", (evidence_id,))
                from_user_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO coc_logs (evidence_id, from_user_id, to_user_id, action,
                    action_description, location, timestamp, created_at)
                VALUES (%s,%s,%s,'transfer',%s,%s,NOW(),NOW()) RETURNING log_id;
            """, (evidence_id, from_user_id, to_user_id, reason, location))
            custody_id = cur.fetchone()[0]

            cur.execute("SELECT case_id FROM evidence WHERE evidence_id = %s;", (evidence_id,))
            case_id = cur.fetchone()[0]
            conn.commit()
            cur.close(); conn.close()
        except Exception as e:
            conn.rollback(); cur.close(); conn.close()
            flash(f'Transfer failed: {str(e)}', 'error')
            return redirect(f"/custody?evidence_id={evidence_id}")

        # Fetch names for logging
        try:
            conn2 = get_connection(); cur2 = conn2.cursor()
            cur2.execute(
                "SELECT user_id, username, full_name FROM users WHERE user_id IN %s;",
                (tuple({from_user_id, to_user_id}),)
            )
            name_map = {r[0]: (r[1], r[2]) for r in cur2.fetchall()}
            cur2.close(); conn2.close()
        except Exception:
            name_map = {}

        # Use full_name for display (never the username placeholder like 'user_9')
        from_uname = name_map.get(from_user_id, (None, None))[1] or name_map.get(from_user_id, (None, None))[0] or f"User {from_user_id}"
        from_fname = from_uname
        to_uname   = name_map.get(to_user_id,   (None, None))[1] or name_map.get(to_user_id,   (None, None))[0] or f"User {to_user_id}"
        to_fname   = to_uname

        for fn, args, kwargs in [
            (log_custody_activity, [], {"evidence_id": evidence_id, "from_user": from_user_id,
                                        "to_user": to_user_id, "location": location, "reason": reason}),
            (neo_add_custody_event, [], {
                "custody_id": custody_id, "evidence_id": evidence_id,
                "from_user": from_user_id, "to_user": to_user_id,
                "from_username": from_uname, "to_username": to_uname,
                "reason": reason, "timestamp": _now_ist().isoformat(),
                "action": "transfer", "location": location,
            }),
            (log_case_activity, [], {"case_id": case_id, "event_type": "custody_transferred",
                                      "entity": "evidence", "entity_id": evidence_id,
                                      "description": f"Custody transferred: {from_fname} → {to_fname}",
                                      "actor_id": session.get('user_id')}),
        ]:
            try:
                fn(*args, **kwargs)
            except Exception:
                pass

        flash('Custody transferred successfully', 'success')
        return redirect(f"/custody?evidence_id={evidence_id}")

    @app.route("/api/custody/graph/<int:evidence_id>")
    @login_required
    def custody_graph_api(evidence_id):
        conn = get_connection()
        cur = conn.cursor()

        # Full evidence + case + uploader info
        cur.execute("""
            SELECT e.evidence_id, e.evidence_code, e.evidence_tag,
                   c.case_id, c.case_number, c.status,
                   c.created_by, u_cr.full_name AS creator_name,
                   e.uploader_id, u_up.full_name AS uploader_name
            FROM evidence e
            JOIN cases c    ON e.case_id     = c.case_id
            JOIN users u_up ON e.uploader_id = u_up.user_id
            JOIN users u_cr ON c.created_by  = u_cr.user_id
            WHERE e.evidence_id = %s;
        """, (evidence_id,))
        ev_row = cur.fetchone()

        cur.execute("""
            SELECT cl.log_id, cl.from_user_id, cl.to_user_id,
                   fu.full_name, tu.full_name, cl.action_description
            FROM coc_logs cl
            LEFT JOIN users fu ON cl.from_user_id = fu.user_id
            LEFT JOIN users tu ON cl.to_user_id   = tu.user_id
            WHERE cl.evidence_id = %s ORDER BY cl.timestamp ASC;
        """, (evidence_id,))
        sql_rows = cur.fetchall()
        cur.close(); conn.close()

        user_names, chain = {}, []
        for row in sql_rows:
            user_names[row[1]] = row[3] or f"User {row[1]}"
            user_names[row[2]] = row[4] or f"User {row[2]}"
            chain.append({"custody_id": row[0], "from_user_id": row[1], "to_user_id": row[2],
                          "from_user": user_names[row[1]], "to_user": user_names[row[2]],
                          "reason": row[5]})

        evidence_info = None
        case_info     = None
        uploader_info = None
        if ev_row:
            evidence_info = {"id": ev_row[0], "code": ev_row[1], "tag": ev_row[2]}
            case_info     = {"id": ev_row[3], "case_number": ev_row[4], "status": ev_row[5],
                             "creator_id": ev_row[6], "creator_name": ev_row[7]}
            uploader_info = {"id": ev_row[8], "name": ev_row[9]}
            user_names[ev_row[8]] = ev_row[9]

        try:
            graph = neo_get_graph_data(evidence_id, user_names)
            if not graph.get("nodes"):
                graph = _build_graph_from_sql(
                    evidence_info, chain, case_info, uploader_info)
        except Exception:
            graph = _build_graph_from_sql(
                evidence_info, chain, case_info, uploader_info)

        try:
            cycles = neo_detect_cycles(evidence_id)
        except Exception:
            cycles = []

        cycle_user_ids = {f"user_{c['user_id']}" for c in cycles}
        for node in graph.get("nodes", []):
            if node["id"] in cycle_user_ids:
                node["cycle"] = True

        return jsonify({**graph, "cycles": cycles}), 200
