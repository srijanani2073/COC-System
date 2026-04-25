from dbs.sql_db import get_connection
from dbs.neo4j_db import driver, NEO4J_DATABASE
from datetime import datetime

class QueryInterface:
    """
    Multi-model query interface supporting relational and graph queries
    """
    
    def __init__(self):
        pass
    
    # ==================== RELATIONAL QUERIES ====================
    
    def query_evidence_by_case(self, case_id):
        """
        Query all evidence for a specific case
        
        Input: Case ID
        Output: List of evidence with metadata
        """
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT 
                e.evidence_id,
                e.evidence_code,
                e.evidence_type,
                e.evidence_tag,
                e.version,
                e.original_filename,
                e.file_hash_sha256,
                e.size_bytes,
                e.upload_time,
                e.last_verified_at,
                u.full_name as uploader_name,
                c.case_number,
                c.title as case_title
            FROM evidence e
            JOIN users u ON e.uploader_id = u.user_id
            JOIN cases c ON e.case_id = c.case_id
            WHERE e.case_id = %s AND e.is_active = TRUE
            ORDER BY e.upload_time DESC;
        """, (case_id,))
        
        evidence_list = []
        for row in cur.fetchall():
            evidence_list.append({
                'evidence_id': row[0],
                'evidence_code': row[1],
                'evidence_type': row[2],
                'evidence_tag': row[3],
                'version': row[4],
                'filename': row[5],
                'hash': row[6][:16] + '...' if row[6] else None,
                'size_bytes': row[7],
                'uploaded_at': row[8],
                'last_verified': row[9],
                'uploader': row[10],
                'case_number': row[11],
                'case_title': row[12]
            })
        
        cur.close()
        conn.close()
        
        return evidence_list
    
    def query_custody_events_by_evidence(self, evidence_id):
        """
        Query all custody events for specific evidence
        
        Input: Evidence ID
        Output: List of custody events as structured records
        """
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT 
                cl.log_id,
                cl.evidence_id,
                cl.action,
                cl.action_description,
                cl.location,
                cl.timestamp,
                u_from.full_name as from_user_name,
                u_to.full_name as to_user_name,
                cl.signature_verified
            FROM coc_logs cl
            LEFT JOIN users u_from ON cl.from_user_id = u_from.user_id
            LEFT JOIN users u_to ON cl.to_user_id = u_to.user_id
            WHERE cl.evidence_id = %s
            ORDER BY cl.timestamp ASC;
        """, (evidence_id,))
        
        custody_events = []
        for row in cur.fetchall():
            custody_events.append({
                'log_id': row[0],
                'evidence_id': row[1],
                'action': row[2],
                'description': row[3],
                'location': row[4],
                'timestamp': row[5],
                'from_user': row[6],
                'to_user': row[7],
                'signature_verified': row[8]
            })
        
        cur.close()
        conn.close()
        
        return custody_events
    
    def query_custody_events_by_user(self, user_id):
        """
        Query all custody events involving a specific user
        
        Input: User ID
        Output: List of custody events
        """
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT 
                cl.log_id,
                cl.evidence_id,
                e.evidence_code,
                cl.action,
                cl.action_description,
                cl.timestamp,
                u_from.full_name as from_user_name,
                u_to.full_name as to_user_name,
                c.case_number
            FROM coc_logs cl
            JOIN evidence e ON cl.evidence_id = e.evidence_id
            JOIN cases c ON e.case_id = c.case_id
            LEFT JOIN users u_from ON cl.from_user_id = u_from.user_id
            LEFT JOIN users u_to ON cl.to_user_id = u_to.user_id
            WHERE cl.from_user_id = %s OR cl.to_user_id = %s
            ORDER BY cl.timestamp DESC
            LIMIT 100;
        """, (user_id, user_id))
        
        events = []
        for row in cur.fetchall():
            events.append({
                'log_id': row[0],
                'evidence_id': row[1],
                'evidence_code': row[2],
                'action': row[3],
                'description': row[4],
                'timestamp': row[5],
                'from_user': row[6],
                'to_user': row[7],
                'case_number': row[8]
            })
        
        cur.close()
        conn.close()
        
        return events
    
    def query_case_summary(self, case_id):
        """
        Get comprehensive case summary
        
        Input: Case ID
        Output: Case summary with statistics
        """
        conn = get_connection()
        cur = conn.cursor()
        
        # Basic case info
        cur.execute("""
            SELECT 
                c.case_id,
                c.case_number,
                c.title,
                c.description,
                c.status,
                c.created_at,
                c.updated_at,
                u.full_name as created_by_name
            FROM cases c
            JOIN users u ON c.created_by = u.user_id
            WHERE c.case_id = %s;
        """, (case_id,))
        
        case_row = cur.fetchone()
        if not case_row:
            cur.close()
            conn.close()
            return None
        
        # Evidence count
        cur.execute("""
            SELECT COUNT(DISTINCT original_filename)
            FROM evidence
            WHERE case_id = %s AND is_active = TRUE;
        """, (case_id,))
        evidence_count = cur.fetchone()[0]
        
        # Total versions
        cur.execute("""
            SELECT COUNT(*)
            FROM evidence
            WHERE case_id = %s AND is_active = TRUE;
        """, (case_id,))
        total_versions = cur.fetchone()[0]
        
        # Custody events count
        cur.execute("""
            SELECT COUNT(*)
            FROM coc_logs cl
            JOIN evidence e ON cl.evidence_id = e.evidence_id
            WHERE e.case_id = %s;
        """, (case_id,))
        custody_events = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return {
            'case_id': case_row[0],
            'case_number': case_row[1],
            'title': case_row[2],
            'description': case_row[3],
            'status': case_row[4],
            'created_at': case_row[5],
            'updated_at': case_row[6],
            'created_by': case_row[7],
            'evidence_count': evidence_count,
            'total_versions': total_versions,
            'custody_events': custody_events
        }
    
    # ==================== GRAPH QUERIES ====================
    
    def query_full_custody_chain(self, evidence_id):
        """
        Query full chain-of-custody from Neo4j.
        Schema: (:User)-[:FROM]->(:CustodyEvent)  (sender)
                (:CustodyEvent)-[:TO]->(:User)     (receiver)
                (:Evidence)-[:HAS_CUSTODY_EVENT]->(:CustodyEvent)
        Falls back to SQL if Neo4j is empty for this evidence.
        """
        chain = []
        try:
            with driver.session(database=NEO4J_DATABASE) as s:
                result = s.run("""
                    MATCH (e:Evidence {evidence_id: $eid})-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                    OPTIONAL MATCH (fu:User)-[:FROM]->(ce)
                    OPTIONAL MATCH (ce)-[:TO]->(tu:User)
                    RETURN
                        ce.custody_id   AS custody_id,
                        ce.action       AS action,
                        ce.reason       AS reason,
                        ce.timestamp    AS ts,
                        fu.user_id      AS from_uid,
                        fu.username     AS from_uname,
                        tu.user_id      AS to_uid,
                        tu.username     AS to_uname
                    ORDER BY ce.timestamp ASC
                """, {"eid": evidence_id})
                for rec in result:
                    chain.append({
                        'custody_id':   rec['custody_id'],
                        'action':       rec['action'] or 'transfer',
                        'reason':       rec['reason'] or '',
                        'timestamp':    str(rec['ts']) if rec['ts'] else '',
                        'from_user_id': rec['from_uid'],
                        'from_user':    rec['from_uname'] or (f"User {rec['from_uid']}" if rec['from_uid'] else '—'),
                        'to_user_id':   rec['to_uid'],
                        'to_user':      rec['to_uname'] or (f"User {rec['to_uid']}" if rec['to_uid'] else '—'),
                    })
        except Exception:
            pass

        # Enrich: replace username fallbacks with full_name from SQL
        if chain:
            all_uids = set()
            for ev in chain:
                if ev.get('from_user_id'): all_uids.add(ev['from_user_id'])
                if ev.get('to_user_id'):   all_uids.add(ev['to_user_id'])
            if all_uids:
                try:
                    conn_e = get_connection(); cur_e = conn_e.cursor()
                    cur_e.execute(
                        "SELECT user_id, full_name FROM users WHERE user_id = ANY(%s);",
                        (list(all_uids),)
                    )
                    fname_map = {r[0]: r[1] for r in cur_e.fetchall() if r[1]}
                    cur_e.close(); conn_e.close()
                    for ev in chain:
                        if ev.get('from_user_id') and ev['from_user_id'] in fname_map:
                            ev['from_user'] = fname_map[ev['from_user_id']]
                        if ev.get('to_user_id') and ev['to_user_id'] in fname_map:
                            ev['to_user'] = fname_map[ev['to_user_id']]
                except Exception:
                    pass
        if not chain:
            conn = get_connection(); cur = conn.cursor()
            cur.execute("""
                SELECT cl.log_id, cl.action, cl.action_description, cl.timestamp,
                       cl.from_user_id, fu.username, fu.full_name,
                       cl.to_user_id,   tu.username, tu.full_name
                FROM coc_logs cl
                LEFT JOIN users fu ON cl.from_user_id = fu.user_id
                LEFT JOIN users tu ON cl.to_user_id   = tu.user_id
                WHERE cl.evidence_id = %s
                ORDER BY cl.timestamp ASC;
            """, (evidence_id,))
            for row in cur.fetchall():
                chain.append({
                    'custody_id':   row[0],
                    'action':       row[1] or 'transfer',
                    'reason':       row[2] or '',
                    'timestamp':    str(row[3]) if row[3] else '',
                    'from_user_id': row[4],
                    'from_user':    row[6] or row[5] or (f"User {row[4]}" if row[4] else '—'),
                    'to_user_id':   row[7],
                    'to_user':      row[9] or row[8] or (f"User {row[7]}" if row[7] else '—'),
                })
            cur.close(); conn.close()

        return {
            'evidence_id':    evidence_id,
            'chain':          chain,
            'total_transfers': len(chain),
            'max_path_length': len(chain),
            'source':         'neo4j+sql_fallback'
        }

    def query_custody_relationships(self, evidence_id):
        """Relationship statistics for evidence."""
        try:
            with driver.session(database=NEO4J_DATABASE) as s:
                rec = s.run("""
                    MATCH (e:Evidence {evidence_id: $eid})-[:HAS_CUSTODY_EVENT]->(ce:CustodyEvent)
                    OPTIONAL MATCH (fu:User)-[:FROM]->(ce)
                    OPTIONAL MATCH (ce)-[:TO]->(tu:User)
                    RETURN COUNT(DISTINCT fu) + COUNT(DISTINCT tu) AS unique_users,
                           COUNT(ce) AS total_events
                """, {"eid": evidence_id}).single()
                return {
                    'evidence_id':  evidence_id,
                    'unique_users': rec['unique_users'] if rec else 0,
                    'total_events': rec['total_events'] if rec else 0,
                }
        except Exception:
            conn = get_connection(); cur = conn.cursor()
            cur.execute("""
                SELECT COUNT(DISTINCT from_user_id) + COUNT(DISTINCT to_user_id),
                       COUNT(*) FROM coc_logs WHERE evidence_id = %s;
            """, (evidence_id,))
            row = cur.fetchone(); cur.close(); conn.close()
            return {'evidence_id': evidence_id,
                    'unique_users': row[0] if row else 0,
                    'total_events': row[1] if row else 0}

    def query_detect_suspicious_transitions(self, evidence_id):
        """
        Detect chain anomalies:
          - Custody gaps (to_user ≠ next from_user)
          - Cycles (a user appears as both sender and receiver)
          - Rapid transfers (< 5 minutes apart)
        """
        chain_data = self.query_full_custody_chain(evidence_id)
        chain = chain_data['chain']
        anomalies = []

        # 1. Custody gaps
        for i in range(len(chain) - 1):
            cur_ev  = chain[i]
            next_ev = chain[i + 1]
            cto  = cur_ev.get('to_user_id')
            nfrom = next_ev.get('from_user_id')
            if cto and nfrom and cto != nfrom:
                anomalies.append({
                    'type': 'Custody Gap',
                    'severity': 'high',
                    'description': (
                        f"Transfer {i+1}→{i+2}: custody left with "
                        f"'{cur_ev['to_user']}' but next transfer came from "
                        f"'{next_ev['from_user']}'"
                    ),
                    'timestamp': next_ev['timestamp']
                })

        # 2. Cycle detection — user appears as receiver then later as sender
        #    and the chain eventually returns to someone who already held it
        seen_as_receiver = {}  # uid → step index
        for i, ev in enumerate(chain):
            to_uid   = ev.get('to_user_id')
            from_uid = ev.get('from_user_id')
            if to_uid is not None:
                seen_as_receiver[to_uid] = i
            # If this sender was already a receiver at an earlier step,
            # AND there's a later step where custody returns to an earlier holder → cycle
            if from_uid is not None and from_uid in seen_as_receiver:
                prev_idx = seen_as_receiver[from_uid]
                if prev_idx < i - 1:   # not the immediately adjacent step
                    anomalies.append({
                        'type': 'Custody Cycle',
                        'severity': 'high',
                        'description': (
                            f"Cycle detected: '{ev['from_user']}' received custody "
                            f"at step {prev_idx+1} and is now sending again at step {i+1}"
                        ),
                        'timestamp': ev['timestamp']
                    })

        # Also do a full-scan cycle check via set of (from,to) pairs
        transfer_pairs = [(ev.get('from_user_id'), ev.get('to_user_id')) for ev in chain]
        seen_uids = set()
        for i, (f, t) in enumerate(transfer_pairs):
            if t in seen_uids and (t, f) in set(transfer_pairs):
                # t was already involved and the reverse transfer exists
                already_flagged = any(
                    a['type'] == 'Custody Cycle' for a in anomalies
                    if str(t) in a['description'] or str(f) in a['description']
                )
                if not already_flagged:
                    idx = next((j for j, ev in enumerate(chain) if ev.get('to_user_id') == t), i)
                    anomalies.append({
                        'type': 'Custody Cycle',
                        'severity': 'high',
                        'description': (
                            f"Bidirectional cycle: user {f} and user {t} "
                            f"exchanged custody back and forth"
                        ),
                        'timestamp': chain[i]['timestamp']
                    })
            seen_uids.add(f)

        # 3. Rapid transfers
        for i in range(len(chain) - 1):
            t1 = chain[i]['timestamp']
            t2 = chain[i+1]['timestamp']
            try:
                from datetime import datetime as _dt
                d1 = _dt.fromisoformat(t1.replace('Z','')) if t1 else None
                d2 = _dt.fromisoformat(t2.replace('Z','')) if t2 else None
                if d1 and d2:
                    diff = abs((d2 - d1).total_seconds())
                    if diff < 300:
                        anomalies.append({
                            'type': 'Rapid Transfer',
                            'severity': 'medium',
                            'description': (
                                f"Steps {i+1}→{i+2}: only {int(diff)}s between transfers "
                                f"({chain[i]['from_user']} → {chain[i]['to_user']} → {chain[i+1]['to_user']})"
                            ),
                            'timestamp': t2
                        })
            except Exception:
                pass

        return {
            'evidence_id':    evidence_id,
            'anomalies':      anomalies,
            'total_anomalies': len(anomalies)
        }

    def query_user_custody_network(self, user_id):
        """
        Return all custody relationships involving this user.
        Schema: (:User)-[:FROM]->(:CustodyEvent)  (user sent)
                (:CustodyEvent)-[:TO]->(:User)     (user received)
                (:Evidence)-[:HAS_CUSTODY_EVENT]->(:CustodyEvent)
        Falls back to SQL if Neo4j empty.
        Partner names are resolved via SQL full_name lookup.
        """
        network = []
        partner_uid_sets = {}   # rel_type -> set of user_ids

        try:
            with driver.session(database=NEO4J_DATABASE) as s:
                # Sent (FROM) — collect partner user_ids not usernames
                r1 = s.run("""
                    MATCH (u:User {user_id: $uid})-[:FROM]->(ce:CustodyEvent)
                    MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce)
                    OPTIONAL MATCH (ce)-[:TO]->(tu:User)
                    RETURN 'SENT' AS rel,
                           COUNT(DISTINCT ce) AS event_count,
                           COLLECT(DISTINCT e.evidence_id) AS evidence_ids,
                           COLLECT(DISTINCT tu.user_id) AS partner_ids
                """, {"uid": user_id}).single()
                if r1 and r1['event_count']:
                    pids = [p for p in (r1['partner_ids'] or []) if p is not None]
                    network.append({
                        'relationship_type': 'SENT',
                        'event_count':  r1['event_count'],
                        'evidence_ids': list(r1['evidence_ids'] or []),
                        'partner_ids':  pids,
                        'partners':     [],   # filled below
                    })
                    partner_uid_sets['SENT'] = set(pids)

                # Received (TO)
                r2 = s.run("""
                    MATCH (ce:CustodyEvent)-[:TO]->(u:User {user_id: $uid})
                    MATCH (e:Evidence)-[:HAS_CUSTODY_EVENT]->(ce)
                    OPTIONAL MATCH (fu:User)-[:FROM]->(ce)
                    RETURN 'RECEIVED' AS rel,
                           COUNT(DISTINCT ce) AS event_count,
                           COLLECT(DISTINCT e.evidence_id) AS evidence_ids,
                           COLLECT(DISTINCT fu.user_id) AS partner_ids
                """, {"uid": user_id}).single()
                if r2 and r2['event_count']:
                    pids = [p for p in (r2['partner_ids'] or []) if p is not None]
                    network.append({
                        'relationship_type': 'RECEIVED',
                        'event_count':  r2['event_count'],
                        'evidence_ids': list(r2['evidence_ids'] or []),
                        'partner_ids':  pids,
                        'partners':     [],
                    })
                    partner_uid_sets['RECEIVED'] = set(pids)
        except Exception:
            pass

        # SQL fallback — also get partner names directly
        if not network:
            conn = get_connection(); cur = conn.cursor()
            cur.execute("""
                SELECT 'SENT'::text,
                       COUNT(*),
                       ARRAY_AGG(DISTINCT cl.evidence_id),
                       ARRAY_AGG(DISTINCT cl.to_user_id)
                FROM coc_logs cl WHERE cl.from_user_id = %s
                UNION ALL
                SELECT 'RECEIVED',
                       COUNT(*),
                       ARRAY_AGG(DISTINCT cl.evidence_id),
                       ARRAY_AGG(DISTINCT cl.from_user_id)
                FROM coc_logs cl WHERE cl.to_user_id = %s;
            """, (user_id, user_id))
            for row in cur.fetchall():
                if row[1]:
                    pids = [p for p in (row[3] or []) if p is not None]
                    network.append({
                        'relationship_type': row[0],
                        'event_count':  row[1],
                        'evidence_ids': [e for e in (row[2] or []) if e][:20],
                        'partner_ids':  pids,
                        'partners':     [],
                    })
                    partner_uid_sets[row[0]] = set(pids)
            cur.close(); conn.close()

        # Enrich all partner_ids → full_name via SQL
        all_pids = set()
        for s in partner_uid_sets.values():
            all_pids |= s
        if all_pids:
            try:
                conn2 = get_connection(); cur2 = conn2.cursor()
                cur2.execute(
                    "SELECT user_id, full_name, username FROM users WHERE user_id = ANY(%s);",
                    (list(all_pids),)
                )
                fname_map = {r[0]: r[1] or r[2] or f"User {r[0]}" for r in cur2.fetchall()}
                cur2.close(); conn2.close()
                for entry in network:
                    entry['partners'] = [
                        fname_map.get(pid, f"User {pid}")
                        for pid in entry.get('partner_ids', [])
                        if pid is not None
                    ]
            except Exception:
                pass

        return {'user_id': user_id, 'network': network}
    
    def query_case_custody_graph(self, case_id):
        """
        Get entire custody graph for a case
        
        Input: Case ID
        Output: Graph structure for visualization
        """
        # First get all evidence IDs for the case
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT evidence_id FROM evidence WHERE case_id = %s AND is_active = TRUE;", (case_id,))
        evidence_ids = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
        
        # Get custody chains for all evidence
        all_chains = []
        for eid in evidence_ids:
            chain = self.query_full_custody_chain(eid)
            all_chains.append(chain)
        
        return {
            'case_id': case_id,
            'evidence_count': len(evidence_ids),
            'custody_chains': all_chains
        }


# Global instance
query_interface = QueryInterface()


# ==================== CONVENIENCE FUNCTIONS ====================

# Relational queries
def get_evidence_by_case(case_id):
    """Get all evidence for a case"""
    return query_interface.query_evidence_by_case(case_id)


def get_custody_events(evidence_id):
    """Get custody events for evidence"""
    return query_interface.query_custody_events_by_evidence(evidence_id)


def get_user_custody_history(user_id):
    """Get custody history for user"""
    return query_interface.query_custody_events_by_user(user_id)


def get_case_summary(case_id):
    """Get case summary"""
    return query_interface.query_case_summary(case_id)


# Graph queries
def get_custody_chain(evidence_id):
    """Get full custody chain"""
    return query_interface.query_full_custody_chain(evidence_id)


def get_custody_statistics(evidence_id):
    """Get custody relationship statistics"""
    return query_interface.query_custody_relationships(evidence_id)


def detect_anomalies(evidence_id):
    """Detect suspicious transitions"""
    return query_interface.query_detect_suspicious_transitions(evidence_id)


def get_user_network(user_id):
    """Get user custody network"""
    return query_interface.query_user_custody_network(user_id)


def get_case_graph(case_id):
    """Get case custody graph"""
    return query_interface.query_case_custody_graph(case_id)