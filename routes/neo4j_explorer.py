from flask import render_template, session, request, jsonify
from dbs.neo4j_db import (
    neo_get_custody_chain_with_case,
    neo_get_case_evidence_handlers,
    neo_get_user_case_involvement,
    neo_get_verifications_by_case,
    neo_detect_custody_gaps,
    neo_detect_cycles,
)
from dbs.sql_db import get_connection


def _get_all_evidence():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT e.evidence_id, e.evidence_code, e.evidence_tag,
               c.case_id, c.case_number
        FROM evidence e
        JOIN cases c ON e.case_id = c.case_id
        ORDER BY c.case_number, e.evidence_code
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return [{"id": r[0], "code": r[1], "tag": r[2],
             "case_id": r[3], "case_number": r[4]} for r in rows]


def _get_all_cases():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT case_id, case_number, title FROM cases ORDER BY case_number")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return [{"id": r[0], "number": r[1], "title": r[2]} for r in rows]


def _get_all_users():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.user_id, u.full_name, u.username, r.role_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.role_id
        ORDER BY u.full_name
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return [{"id": r[0], "name": r[1] or r[2] or f"User {r[0]}", "role": r[3]} for r in rows]


# ── Graph builders for each function ──────────────────────────────────────────

def _build_custody_chain_graph(data):
    """neo_get_custody_chain_with_case → nodes + edges"""
    nodes, edges, node_ids = [], [], set()

    def add_node(nid, label, group, extra=None):
        if nid not in node_ids:
            n = {"id": nid, "label": label, "group": group}
            if extra: n.update(extra)
            nodes.append(n)
            node_ids.add(nid)

    for i, row in enumerate(data):
        # Case node
        c_id = f"case_{row['case_number']}"
        add_node(c_id, row["case_number"], "case", {"status": row["case_status"]})

        # Evidence node
        ev_id = f"ev_{row['evidence_code']}"
        add_node(ev_id, row["evidence_code"], "evidence", {"etype": row["evidence_type"]})
        if (c_id, ev_id) not in {(e["from"], e["to"]) for e in edges}:
            edges.append({"from": c_id, "to": ev_id, "label": "HAS_EVIDENCE"})

        # Custody event node
        ce_id = f"ce_{row['custody_id']}"
        add_node(ce_id, (row["action"] or "event").capitalize(), "custody", {
            "action": row["action"], "reason": (row["reason"] or "")[:40],
            "ts": str(row["timestamp"]) if row["timestamp"] else "",
            "location": row["location"]
        })
        edges.append({"from": ev_id, "to": ce_id, "label": row["action"] or "EVENT"})

        # From user
        fu_id = f"user_from_{row['from_username']}"
        add_node(fu_id, row["from_username"] or "Unknown", "user", {"role": row["from_role"]})
        edges.append({"from": fu_id, "to": ce_id, "label": "FROM"})

        # To user
        tu_id = f"user_to_{row['to_username']}_{i}"
        add_node(tu_id, row["to_username"] or "Unknown", "user", {"role": row["to_role"]})
        edges.append({"from": ce_id, "to": tu_id, "label": "TO"})

    return {"nodes": nodes, "edges": edges}


def _build_handlers_graph(data):
    """neo_get_case_evidence_handlers → nodes + edges"""
    nodes, edges, node_ids = [], [], set()

    def add_node(nid, label, group, extra=None):
        if nid not in node_ids:
            n = {"id": nid, "label": label, "group": group}
            if extra: n.update(extra)
            nodes.append(n)
            node_ids.add(nid)

    for row in data:
        c_id = f"case_{row['case_number']}"
        add_node(c_id, row["case_number"], "case")

        ev_id = f"ev_{row['evidence_code']}"
        add_node(ev_id, row["evidence_code"], "evidence", {"etype": row["evidence_type"]})
        if (c_id, ev_id) not in {(e["from"], e["to"]) for e in edges}:
            edges.append({"from": c_id, "to": ev_id, "label": "HAS_EVIDENCE"})

        u_id = f"user_{row['handler']}"
        add_node(u_id, row["handler"] or "Unknown", "user", {
            "role": row["role"],
            "subtitle": f"×{row['times_handled']} actions"
        })
        edges.append({"from": u_id, "to": ev_id, "label": f"HANDLED×{row['times_handled']}"})

    return {"nodes": nodes, "edges": edges}


def _build_user_involvement_graph(data):
    """neo_get_user_case_involvement → nodes + edges"""
    nodes, edges, node_ids = [], [], set()

    def add_node(nid, label, group, extra=None):
        if nid not in node_ids:
            n = {"id": nid, "label": label, "group": group}
            if extra: n.update(extra)
            nodes.append(n)
            node_ids.add(nid)

    for row in data:
        u_id = f"user_{row['username']}"
        add_node(u_id, row["username"] or "Unknown", "user", {"role": row["role"]})

        c_id = f"case_{row['case_number']}"
        add_node(c_id, row["case_number"], "case", {"status": row["case_status"]})

        ev_id = f"ev_{row['evidence_code']}"
        add_node(ev_id, row["evidence_code"], "evidence")
        if (c_id, ev_id) not in {(e["from"], e["to"]) for e in edges}:
            edges.append({"from": c_id, "to": ev_id, "label": "HAS_EVIDENCE"})
        edges.append({"from": u_id, "to": ev_id, "label": f"ACTED×{row['custody_actions']}"})

    return {"nodes": nodes, "edges": edges}


def _build_verifications_graph(data):
    """neo_get_verifications_by_case → nodes + edges"""
    nodes, edges, node_ids = [], [], set()

    def add_node(nid, label, group, extra=None):
        if nid not in node_ids:
            n = {"id": nid, "label": label, "group": group}
            if extra: n.update(extra)
            nodes.append(n)
            node_ids.add(nid)

    for i, row in enumerate(data):
        c_id = f"case_{row['case_number']}"
        add_node(c_id, row["case_number"], "case")

        ev_id = f"ev_{row['evidence_code']}"
        add_node(ev_id, row["evidence_code"], "evidence")
        if (c_id, ev_id) not in {(e["from"], e["to"]) for e in edges}:
            edges.append({"from": c_id, "to": ev_id, "label": "HAS_EVIDENCE"})

        ve_id = f"ve_{i}_{row['evidence_code']}"
        add_node(ve_id, f"Verify: {row['result']}", "verification", {
            "result": row["result"], "ts": str(row["verified_at"]) if row["verified_at"] else "",
            "method": row["method"]
        })
        edges.append({"from": ev_id, "to": ve_id, "label": "VERIFIED_BY"})

        u_id = f"user_{row['verifier']}"
        add_node(u_id, row["verifier"] or "Unknown", "user", {"role": row["verifier_role"]})
        edges.append({"from": u_id, "to": ve_id, "label": "PERFORMED"})

    return {"nodes": nodes, "edges": edges}


def _build_gaps_graph(gaps, evidence_id):
    nodes, edges = [], []
    nodes.append({"id": "ev", "label": f"Evidence {evidence_id}", "group": "evidence"})
    for i, g in enumerate(gaps):
        g_id = f"gap_{i}"
        nodes.append({"id": g_id, "label": "GAP", "group": "gap",
                      "subtitle": g["timestamp"]})
        edges.append({"from": "ev", "to": g_id, "label": "BREAK"})
        nodes.append({"id": f"expected_{i}", "label": g["expected_from_user"], "group": "user",
                      "subtitle": "expected"})
        nodes.append({"id": f"actual_{i}", "label": g["actual_from_user"], "group": "cycle",
                      "subtitle": "actual"})
        edges.append({"from": g_id, "to": f"expected_{i}", "label": "EXPECTED"})
        edges.append({"from": g_id, "to": f"actual_{i}", "label": "ACTUAL"})
    return {"nodes": nodes, "edges": edges}


def _build_cycles_graph(cycles, evidence_id):
    nodes, edges = [], []
    nodes.append({"id": "ev", "label": f"Evidence {evidence_id}", "group": "evidence"})
    for c in cycles:
        u_id = f"user_{c['user_id']}"
        nodes.append({"id": u_id, "label": c["username"] or f"User {c['user_id']}",
                      "group": "cycle", "subtitle": f"×{c['appearances']} times"})
        edges.append({"from": "ev", "to": u_id, "label": f"CYCLE×{c['appearances']}"})
        for ce_id in c["custody_event_ids"]:
            ce_node = f"ce_{ce_id}"
            nodes.append({"id": ce_node, "label": "Event", "group": "custody"})
            edges.append({"from": u_id, "to": ce_node, "label": "APPEARED"})
    return {"nodes": nodes, "edges": edges}


# ── Route registration ─────────────────────────────────────────────────────────

def register_neo4j_explorer(app, login_required):

    @app.route("/neo4j-explorer")
    @login_required
    def neo4j_explorer():
        return render_template(
            "neo4j_explorer.html",
            user=session.get("full_name", "User"),
            role=session.get("role", "Unknown"),
            evidence_list=_get_all_evidence(),
            case_list=_get_all_cases(),
            user_list=_get_all_users(),
        )

    @app.route("/api/neo4j/query", methods=["POST"])
    @login_required
    def neo4j_query_api():
        body = request.get_json(force=True)
        fn   = body.get("fn")
        arg  = body.get("arg")   # int: evidence_id / case_id / user_id
        try:
            arg = int(arg)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid argument"}), 400

        try:
            if fn == "custody_chain":
                raw = neo_get_custody_chain_with_case(arg)
                graph = _build_custody_chain_graph(raw)
                table = raw

            elif fn == "case_handlers":
                raw = neo_get_case_evidence_handlers(arg)
                graph = _build_handlers_graph(raw)
                table = raw

            elif fn == "user_involvement":
                raw = neo_get_user_case_involvement(arg)
                graph = _build_user_involvement_graph(raw)
                table = raw

            elif fn == "verifications_by_case":
                raw = neo_get_verifications_by_case(arg)
                graph = _build_verifications_graph(raw)
                table = raw

            elif fn == "custody_gaps":
                raw = neo_detect_custody_gaps(arg)
                graph = _build_gaps_graph(raw, arg)
                table = raw

            elif fn == "detect_cycles":
                raw = neo_detect_cycles(arg)
                graph = _build_cycles_graph(raw, arg)
                table = raw

            else:
                return jsonify({"error": f"Unknown function: {fn}"}), 400

            return jsonify({"graph": graph, "table": table}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500