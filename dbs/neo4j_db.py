from neo4j import GraphDatabase
import os

NEO4J_URI = os.environ.get("NEO4J_URI")
NEO4J_USER = os.environ.get("NEO4J_USER")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


# ── Smart username SET snippet ────────────────────────────────────────────────
_SET_NAME = """
    CASE
        WHEN $name IS NOT NULL AND NOT $name STARTS WITH 'user_'
        THEN $name
        WHEN u.username IS NOT NULL AND NOT u.username STARTS WITH 'user_'
        THEN u.username
        ELSE COALESCE($name, 'user_' + toString($uid))
    END
"""


# ── Node creation / upsert ────────────────────────────────────────────────────

def neo_merge_user(user_id, username=None, role_name=None, is_active=True):
    """Upsert a User node. Promotes real names; never downgrades to placeholder."""
    with driver.session(database=NEO4J_DATABASE) as s:
        s.run(
            f"MERGE (u:User {{user_id: $uid}}) "
            f"SET u.username = {_SET_NAME}, "
            f"    u.role_name = COALESCE($role_name, u.role_name, 'Unknown'), "
            f"    u.is_active = $is_active",
            {"uid": user_id, "name": username,
             "role_name": role_name, "is_active": is_active}
        )


def neo_create_case(case_id, case_number, status=None, created_at=None,
                    created_by_user_id=None, created_by_username=None,
                    created_by_role=None):
    with driver.session(database=NEO4J_DATABASE) as s:
        s.run("""
            MERGE (c:Case {case_id: $case_id})
            SET c.case_number = $case_number,
                c.status      = COALESCE($status, c.status, 'open'),
                c.created_at  = COALESCE($created_at, c.created_at)
        """, {"case_id": case_id, "case_number": case_number,
              "status": status, "created_at": created_at})

        if created_by_user_id:
            s.run(
                f"MERGE (u:User {{user_id: $uid}}) "
                f"SET u.username = {_SET_NAME}, "
                f"    u.role_name = COALESCE($role_name, u.role_name, 'Unknown'), "
                f"    u.is_active = true "
                f"WITH u MATCH (c:Case {{case_id: $case_id}}) MERGE (u)-[:CREATED]->(c)",
                {"uid": created_by_user_id, "case_id": case_id,
                 "name": created_by_username, "role_name": created_by_role}
            )


def neo_add_evidence(case_id, evidence_id, evidence_code, evidence_type,
                     evidence_tag=None, is_active=True, created_at=None,
                     uploader_id=None, uploader_username=None, uploader_role=None):
    with driver.session(database=NEO4J_DATABASE) as s:
        s.run("""
            MERGE (e:Evidence {evidence_id: $eid})
            SET e.evidence_code = $ecode,
                e.evidence_type = $etype,
                e.evidence_tag  = COALESCE($etag, e.evidence_tag),
                e.is_active     = $is_active,
                e.created_at    = COALESCE($created_at, e.created_at)
            WITH e
            MERGE (c:Case {case_id: $cid})
            MERGE (c)-[:HAS_EVIDENCE]->(e)
        """, {"eid": evidence_id, "ecode": evidence_code, "etype": evidence_type,
              "etag": evidence_tag, "is_active": is_active,
              "created_at": created_at, "cid": case_id})

        if uploader_id:
            s.run(
                f"MERGE (u:User {{user_id: $uid}}) "
                f"SET u.username = {_SET_NAME}, "
                f"    u.role_name = COALESCE($role_name, u.role_name, 'Unknown'), "
                f"    u.is_active = true "
                f"WITH u MATCH (e:Evidence {{evidence_id: $eid}}) MERGE (u)-[:UPLOADED]->(e)",
                {"uid": uploader_id, "eid": evidence_id,
                 "name": uploader_username, "role_name": uploader_role}
            )


def neo_add_custody_event(custody_id, evidence_id, from_user, to_user,
                          reason, timestamp, action="transfer", location=None,
                          from_username=None, to_username=None,
                          from_role=None, to_role=None,
                          signature_verified=None):
    with driver.session(database=NEO4J_DATABASE) as s:
        s.run(
            f"MERGE (u:User {{user_id: $uid}}) "
            f"SET u.username = {_SET_NAME}, "
            f"    u.role_name = COALESCE($role_name, u.role_name, 'Unknown'), "
            f"    u.is_active = true",
            {"uid": from_user, "name": from_username, "role_name": from_role}
        )
        s.run(
            f"MERGE (u:User {{user_id: $uid}}) "
            f"SET u.username = {_SET_NAME}, "
            f"    u.role_name = COALESCE($role_name, u.role_name, 'Unknown'), "
            f"    u.is_active = true",
            {"uid": to_user, "name": to_username, "role_name": to_role}
        )
        # 4-node pattern: Case → Evidence → CustodyEvent, User1 → CustodyEvent → User2
        s.run("""
            MATCH (u1:User {user_id: $fu})
            MATCH (u2:User {user_id: $tu})
            MATCH (e:Evidence {evidence_id: $eid})
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e)
            CREATE (ce:CustodyEvent {
                custody_id:         $cid,
                action:             $action,
                reason:             $reason,
                timestamp:          $ts,
                location:           COALESCE($location, 'Unknown'),
                signature_verified: $sig_verified
            })
            MERGE (e)-[:HAS_CUSTODY_EVENT]->(ce)
            MERGE (u1)-[:FROM]->(ce)
            MERGE (ce)-[:TO]->(u2)
        """, {"fu": from_user, "tu": to_user, "eid": evidence_id,
              "cid": custody_id, "action": action, "reason": reason,
              "ts": timestamp, "location": location,
              "sig_verified": signature_verified})


def neo_add_verification_event(verify_id, evidence_id, verified_by_user_id,
                                verified_at, result, verification_method,
                                expected_hash, found_hash,
                                verifier_username=None, verifier_role=None):
    with driver.session(database=NEO4J_DATABASE) as s:
        # 3-node pattern: User → VerificationEvent ← Evidence, Evidence belongs to Case
        s.run(
            f"MERGE (u:User {{user_id: $uid}}) "
            f"SET u.username = {_SET_NAME}, "
            f"    u.role_name = COALESCE($urole, u.role_name, 'Unknown'), "
            f"    u.is_active = true "
            f"WITH u MATCH (e:Evidence {{evidence_id: $eid}}) "
            f"MATCH (c:Case)-[:HAS_EVIDENCE]->(e) "
            f"MERGE (ve:VerificationEvent {{verify_id: $vid}}) "
            f"SET ve.verified_at = $verified_at, ve.result = $result, "
            f"    ve.verification_method = $method, "
            f"    ve.expected_hash = $exp_hash, ve.found_hash = $found_hash, "
            f"    ve.case_id = c.case_id "
            f"MERGE (e)-[:VERIFIED_BY]->(ve) "
            f"MERGE (u)-[:PERFORMED]->(ve)",
            {"uid": verified_by_user_id, "eid": evidence_id, "vid": verify_id,
             "verified_at": verified_at, "result": result, "method": verification_method,
             "exp_hash": expected_hash, "found_hash": found_hash,
             "name": verifier_username, "urole": verifier_role}
        )


def neo_seal_evidence(evidence_id, sealed_by_user_id, sealed_at,
                       reason, action="seal",
                       user_username=None, user_role=None):
    synthetic_id = abs(hash(f"seal_{evidence_id}_{sealed_at}_{action}")) % (10**9)
    with driver.session(database=NEO4J_DATABASE) as s:
        # 3-node pattern: User seals Evidence which belongs to Case
        s.run(
            f"MERGE (u:User {{user_id: $uid}}) "
            f"SET u.username = {_SET_NAME}, "
            f"    u.role_name = COALESCE($urole, u.role_name, 'Unknown'), "
            f"    u.is_active = true "
            f"WITH u MATCH (e:Evidence {{evidence_id: $eid}}) "
            f"MATCH (c:Case)-[:HAS_EVIDENCE]->(e) "
            f"CREATE (ce:CustodyEvent {{ "
            f"    custody_id: $cid, action: $action, "
            f"    reason: COALESCE($reason, ''), timestamp: $ts, "
            f"    location: 'System', signature_verified: false }}) "
            f"MERGE (e)-[:HAS_CUSTODY_EVENT]->(ce) "
            f"MERGE (u)-[:FROM]->(ce)",
            {"uid": sealed_by_user_id, "eid": evidence_id,
             "cid": synthetic_id, "action": action,
             "reason": reason, "ts": sealed_at,
             "name": user_username, "urole": user_role}
        )


def neo_get_custody_chain(evidence_id):
    """
    3-node pattern: Evidence → CustodyEvent → User (from/to),
    also pulls Case the evidence belongs to.
    """
    with driver.session(database=NEO4J_DATABASE) as session:
        result = session.run("""
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e:Evidence {evidence_id: $evidence_id})
            MATCH (e)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
            MATCH (from_user:User)-[:FROM]->(ce)
            MATCH (ce)-[:TO]->(to_user:User)
            RETURN
                c.case_number      AS case_number,
                ce.custody_id      AS custody_id,
                ce.reason          AS reason,
                ce.timestamp       AS timestamp,
                from_user.user_id  AS from_user_id,
                from_user.username AS from_username,
                to_user.user_id    AS to_user_id,
                to_user.username   AS to_username
            ORDER BY ce.timestamp ASC
        """, {"evidence_id": evidence_id})
        return [{"custody_id":    r["custody_id"],
                 "case_number":   r["case_number"],
                 "from_user_id":  r["from_user_id"],
                 "from_username": r["from_username"],
                 "to_user_id":    r["to_user_id"],
                 "to_username":   r["to_username"],
                 "reason":        r["reason"],
                 "timestamp":     r["timestamp"]} for r in result]


def neo_detect_custody_gaps(evidence_id):
    chain = neo_get_custody_chain(evidence_id)
    try:
        from dbs.sql_db import get_connection
        all_ids = {c["from_user_id"] for c in chain if c.get("from_user_id")} | \
                  {c["to_user_id"]   for c in chain if c.get("to_user_id")}
        name_map = {}
        if all_ids:
            conn = get_connection(); cur = conn.cursor()
            cur.execute("SELECT user_id, full_name, username FROM users WHERE user_id = ANY(%s);",
                        (list(all_ids),))
            for uid, fname, uname in cur.fetchall():
                name_map[uid] = fname or uname or f"User {uid}"
            cur.close(); conn.close()
    except Exception:
        name_map = {}

    def _name(uid, neo_uname):
        n = name_map.get(uid)
        if n: return n
        if neo_uname and not neo_uname.startswith('user_'): return neo_uname
        return f"User {uid}"

    gaps = []
    for i in range(len(chain) - 1):
        if chain[i]["to_user_id"] != chain[i+1]["from_user_id"]:
            gaps.append({
                "gap_index":          i,
                "expected_from_user": _name(chain[i]["to_user_id"],     chain[i].get("to_username")),
                "actual_from_user":   _name(chain[i+1]["from_user_id"], chain[i+1].get("from_username")),
                "timestamp":          chain[i+1]["timestamp"]
            })
    return gaps


def neo_detect_cycles(evidence_id):
    """
    3-node pattern: Evidence → CustodyEvent → User, filtered to users
    who appear more than once as recipient — indicates illegal custody loop.
    Case is also pulled to provide context.
    """
    with driver.session(database=NEO4J_DATABASE) as session:
        result = session.run("""
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e:Evidence {evidence_id: $evidence_id})
            MATCH (e)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
            MATCH (ce)-[:TO]->(u:User)
            WITH c.case_number AS case_number,
                 u.user_id AS user_id,
                 u.username AS username,
                 collect(ce.custody_id) AS events,
                 count(*) AS appearances
            WHERE appearances > 1
            RETURN case_number, user_id, username, events, appearances
            ORDER BY appearances DESC
        """, {"evidence_id": evidence_id})
        return [{"case_number":       r["case_number"],
                 "user_id":           r["user_id"],
                 "username":          r["username"],
                 "custody_event_ids": list(r["events"]),
                 "appearances":       r["appearances"]} for r in result]


def neo_get_case_evidence_handlers(case_id):
    """
    3-node traversal: Case → Evidence → CustodyEvent → User
    Answers: which users handled which evidence in this case?
    Equivalent to: student (User) studying under professor (Case)
    participating in project (Evidence).
    """
    with driver.session(database=NEO4J_DATABASE) as session:
        result = session.run("""
            MATCH (c:Case {case_id: $case_id})-[:HAS_EVIDENCE]->(e:Evidence)
            MATCH (e)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
            MATCH (u:User)-[:FROM]->(ce)
            RETURN
                c.case_number        AS case_number,
                e.evidence_code      AS evidence_code,
                e.evidence_type      AS evidence_type,
                u.username           AS handler,
                u.role_name          AS role,
                COUNT(ce)            AS times_handled,
                COLLECT(ce.action)   AS actions_taken
            ORDER BY times_handled DESC
        """, {"case_id": case_id})
        return [{
            "case_number":   r["case_number"],
            "evidence_code": r["evidence_code"],
            "evidence_type": r["evidence_type"],
            "handler":       r["handler"],
            "role":          r["role"],
            "times_handled": r["times_handled"],
            "actions_taken": r["actions_taken"]
        } for r in result]


def neo_get_user_case_involvement(user_id):
    """
    3-node traversal: User → CustodyEvent ← Evidence ← Case
    Answers: which cases is this user involved in, through which evidence?
    """
    with driver.session(database=NEO4J_DATABASE) as session:
        result = session.run("""
            MATCH (u:User {user_id: $user_id})-[:FROM]->(ce:CustodyEvent)
            MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce)
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e)
            RETURN
                u.username           AS username,
                u.role_name          AS role,
                c.case_number        AS case_number,
                c.status             AS case_status,
                e.evidence_code      AS evidence_code,
                COUNT(ce)            AS custody_actions,
                COLLECT(DISTINCT ce.action) AS action_types
            ORDER BY custody_actions DESC
        """, {"user_id": user_id})
        return [{
            "username":       r["username"],
            "role":           r["role"],
            "case_number":    r["case_number"],
            "case_status":    r["case_status"],
            "evidence_code":  r["evidence_code"],
            "custody_actions": r["custody_actions"],
            "action_types":   r["action_types"]
        } for r in result]


def neo_get_custody_chain_with_case(evidence_id):
    """
    4-node pattern: Case → Evidence → CustodyEvent, User1 → CustodyEvent → User2
    Full chain with case context — who transferred what evidence in which case.
    """
    with driver.session(database=NEO4J_DATABASE) as session:
        result = session.run("""
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e:Evidence {evidence_id: $evidence_id})
            MATCH (e)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
            MATCH (fu:User)-[:FROM]->(ce)
            MATCH (ce)-[:TO]->(tu:User)
            RETURN
                c.case_number      AS case_number,
                c.status           AS case_status,
                e.evidence_code    AS evidence_code,
                e.evidence_type    AS evidence_type,
                ce.custody_id      AS custody_id,
                ce.action          AS action,
                ce.reason          AS reason,
                ce.timestamp       AS timestamp,
                ce.location        AS location,
                fu.username        AS from_username,
                fu.role_name       AS from_role,
                tu.username        AS to_username,
                tu.role_name       AS to_role
            ORDER BY ce.timestamp ASC
        """, {"evidence_id": evidence_id})
        return [{
            "case_number":    r["case_number"],
            "case_status":    r["case_status"],
            "evidence_code":  r["evidence_code"],
            "evidence_type":  r["evidence_type"],
            "custody_id":     r["custody_id"],
            "action":         r["action"],
            "reason":         r["reason"],
            "timestamp":      r["timestamp"],
            "location":       r["location"],
            "from_username":  r["from_username"],
            "from_role":      r["from_role"],
            "to_username":    r["to_username"],
            "to_role":        r["to_role"]
        } for r in result]


def neo_get_verifications_by_case(case_id):
    """
    3-node pattern: Case → Evidence → VerificationEvent ← User
    Answers: who verified what evidence in this case, and what was the result?
    """
    with driver.session(database=NEO4J_DATABASE) as session:
        result = session.run("""
            MATCH (c:Case {case_id: $case_id})-[:HAS_EVIDENCE]->(e:Evidence)
            MATCH (e)-[:VERIFIED_BY]->(ve:VerificationEvent)
            MATCH (u:User)-[:PERFORMED]->(ve)
            RETURN
                c.case_number            AS case_number,
                e.evidence_code          AS evidence_code,
                ve.result                AS result,
                ve.verification_method   AS method,
                ve.verified_at           AS verified_at,
                u.username               AS verifier,
                u.role_name              AS verifier_role
            ORDER BY ve.verified_at DESC
        """, {"case_id": case_id})
        return [{
            "case_number":   r["case_number"],
            "evidence_code": r["evidence_code"],
            "result":        r["result"],
            "method":        r["method"],
            "verified_at":   r["verified_at"],
            "verifier":      r["verifier"],
            "verifier_role": r["verifier_role"]
        } for r in result]


def neo_get_graph_data(evidence_id, user_names=None):
    """
    Return nodes + edges for canvas rendering.
    user_names: {user_id -> full_name} from SQL — always overrides Neo4j stored values.
    """
    raw = user_names or {}
    umap = {}
    for k, v in raw.items():
        if v:
            try:
                umap[int(k)] = v
            except (ValueError, TypeError):
                pass

    def _resolve(uid, neo_uname):
        if uid is None:
            return neo_uname or 'Unknown'
        sql = umap.get(int(uid) if not isinstance(uid, int) else uid)
        if sql:
            return sql
        if neo_uname and not neo_uname.startswith('user_'):
            return neo_uname
        return f"User {uid}"

    with driver.session(database=NEO4J_DATABASE) as s:
        for uid_int, real_name in umap.items():
            if real_name and not real_name.startswith('user_'):
                s.run("""
                    MATCH (u:User {user_id: $uid})
                    WHERE u.username IS NULL OR u.username STARTS WITH 'user_'
                    SET u.username = $name
                """, {"uid": uid_int, "name": real_name})

        nodes, edges = [], []
        node_ids = set()

        def add_node(nid, label, group, extra=None):
            if nid not in node_ids:
                n = {"id": nid, "label": label, "group": group}
                if extra:
                    n.update(extra)
                nodes.append(n)
                node_ids.add(nid)

        def add_edge(frm, to, label):
            edges.append({"from": frm, "to": to, "label": label, "arrows": "to"})

        ev_node = f"ev_{evidence_id}"

        # ── 1. 4-node: Case → Evidence, User → Case, User → Evidence ──────────
        r = s.run("""
            MATCH (e:Evidence {evidence_id: $eid})
            OPTIONAL MATCH (c:Case)-[:HAS_EVIDENCE]->(e)
            OPTIONAL MATCH (creator:User)-[:CREATED]->(c)
            OPTIONAL MATCH (uploader:User)-[:UPLOADED]->(e)
            RETURN
                e.evidence_id   AS eid,  e.evidence_code AS ecode,
                e.evidence_type AS etype, e.evidence_tag  AS etag,
                c.case_id       AS cid,  c.case_number   AS cnum, c.status AS cstatus,
                creator.user_id   AS creator_uid,  creator.username  AS creator_uname,
                creator.role_name AS creator_role,
                uploader.user_id   AS up_uid, uploader.username  AS up_uname,
                uploader.role_name AS up_role
        """, {"eid": evidence_id})

        for rec in r:
            etag = rec["etag"] or rec["ecode"] or f"Evidence {evidence_id}"
            add_node(ev_node, label=rec["ecode"] or f"EV{evidence_id}",
                     group="evidence", extra={"title": etag, "etype": rec["etype"]})

            if rec["cid"] is not None:
                cnode = f"case_{rec['cid']}"
                add_node(cnode, label=rec["cnum"] or f"Case {rec['cid']}",
                         group="case", extra={"status": rec["cstatus"]})
                add_edge(cnode, ev_node, "HAS_EVIDENCE")

                if rec["creator_uid"] is not None:
                    uid = rec["creator_uid"]
                    add_node(f"user_{uid}", label=_resolve(uid, rec["creator_uname"]),
                             group="user", extra={"role": rec["creator_role"], "subtitle": "case creator"})
                    add_edge(f"user_{uid}", cnode, "CREATED")

            if rec["up_uid"] is not None:
                uid = rec["up_uid"]
                add_node(f"user_{uid}", label=_resolve(uid, rec["up_uname"]),
                         group="user", extra={"role": rec["up_role"], "subtitle": "uploader"})
                add_edge(f"user_{uid}", ev_node, "UPLOADED")

        # ── 2. 4-node: Case → Evidence → CustodyEvent, User → CustodyEvent → User ──
        chain = s.run("""
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e:Evidence {evidence_id: $eid})
            MATCH (e)-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
            OPTIONAL MATCH (fu:User)-[:FROM]->(ce)
            OPTIONAL MATCH (ce)-[:TO]->(tu:User)
            RETURN
                c.case_number AS case_number,
                ce.custody_id AS cid, ce.action AS action, ce.reason AS reason,
                ce.timestamp  AS ts,  ce.location AS location,
                fu.user_id AS fuid, fu.username AS funame, fu.role_name AS furole,
                tu.user_id AS tuid, tu.username AS tuname, tu.role_name AS turole
            ORDER BY ce.timestamp ASC
        """, {"eid": evidence_id})

        for rec in chain:
            ce_node = f"ce_{rec['cid']}"
            _action = (rec["action"] or "event").capitalize()
            _reason = (rec["reason"] or "")
            for _pfx in ("[SIM] ", "[BROKEN_CHAIN] ", "[CYCLE] ", "[INSIDER:rapid_access] ",
                         "[INSIDER:off_hours] ", "[INSIDER:cross_case] "):
                _reason = _reason.replace(_pfx, "")
            _reason = _reason.strip()[:40]
            add_node(ce_node, label=_action,
                     group="custody",
                     extra={"action": rec["action"], "reason": _reason,
                            "ts": rec["ts"], "location": rec["location"],
                            "case_number": rec["case_number"]})
            add_edge(ev_node, ce_node, rec["action"] or "EVENT")

            if rec["fuid"] is not None:
                add_node(f"user_{rec['fuid']}", label=_resolve(rec["fuid"], rec["funame"]),
                         group="user", extra={"role": rec["furole"]})
                add_edge(f"user_{rec['fuid']}", ce_node, "FROM")

            if rec["tuid"] is not None:
                add_node(f"user_{rec['tuid']}", label=_resolve(rec["tuid"], rec["tuname"]),
                         group="user", extra={"role": rec["turole"]})
                add_edge(ce_node, f"user_{rec['tuid']}", "TO")

        # ── 3. 3-node: Evidence → VerificationEvent ← User, with Case context ──
        verifs = s.run("""
            MATCH (c:Case)-[:HAS_EVIDENCE]->(e:Evidence {evidence_id: $eid})
            MATCH (e)-[:VERIFIED_BY]->(ve:VerificationEvent)
            MATCH (u:User)-[:PERFORMED]->(ve)
            RETURN
                c.case_number            AS case_number,
                ve.verify_id             AS vid,
                ve.result                AS result,
                ve.verified_at           AS verified_at,
                ve.verification_method   AS method,
                u.user_id AS uid, u.username AS uname, u.role_name AS urole
            ORDER BY ve.verified_at ASC
        """, {"eid": evidence_id})

        for rec in verifs:
            ve_node = f"ve_{rec['vid']}"
            result  = rec["result"] or "verify"
            add_node(ve_node, label=f"Verify: {result}", group="verification",
                     extra={"result": result, "ts": rec["verified_at"],
                            "method": rec["method"], "case_number": rec["case_number"]})
            add_edge(ev_node, ve_node, "VERIFIED_BY")

            if rec["uid"] is not None:
                add_node(f"user_{rec['uid']}", label=_resolve(rec["uid"], rec["uname"]),
                         group="user", extra={"role": rec["urole"]})
                add_edge(f"user_{rec['uid']}", ve_node, "PERFORMED")

        return {"nodes": nodes, "edges": edges}
