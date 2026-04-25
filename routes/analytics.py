from flask import jsonify, request, render_template, session
from cyber.analytics import (
    get_evidence_stats, get_custody_stats, get_all_case_summaries,
    get_path_analytics, get_transfer_analytics, get_suspicious_patterns,
    get_activity_heatmap, get_user_profile, get_device_patterns,
    get_cross_db_analysis, get_risk_profiles
)
from cyber.query_interface import (
    get_evidence_by_case, get_custody_events, get_user_custody_history,
    get_case_summary, get_custody_chain, get_custody_statistics,
    detect_anomalies, get_user_network, get_case_graph
)
from cyber.integrity_engine import (
    verify_evidence, verify_case_evidence, verify_pending_evidence,
    get_verification_stats, integrity_engine
)

def register_analytics_routes(app, login_required, role_required):
    @app.route("/api/analytics/evidence-stats")
    @login_required
    def api_evidence_statistics():
        """Get evidence statistics"""
        stats = get_evidence_stats()
        return jsonify(stats), 200
    
    @app.route("/api/analytics/custody-stats")
    @login_required
    def api_custody_statistics():
        """Get custody statistics"""
        stats = get_custody_stats()
        return jsonify(stats), 200
    
    @app.route("/api/analytics/case-summaries")
    @login_required
    def api_case_summaries():
        """Get all case summaries"""
        summaries = get_all_case_summaries()
        return jsonify({
            'total_cases': len(summaries),
            'cases': summaries
        }), 200
    
    # ==================== GRAPH ANALYTICS ====================
    
    @app.route("/api/analytics/path-analysis")
    @login_required
    def api_path_analysis():
        """Get custody path analytics"""
        analytics = get_path_analytics()
        return jsonify(analytics), 200
    
    @app.route("/api/analytics/transfer-frequency")
    @login_required
    def api_transfer_frequency():
        """Get transfer frequency analytics"""
        analytics = get_transfer_analytics()
        return jsonify(analytics), 200
    
    @app.route("/api/analytics/suspicious-patterns")
    @login_required
    def api_suspicious_patterns():
        """Detect suspicious transitions"""
        patterns = get_suspicious_patterns()
        return jsonify(patterns), 200
    
    # ==================== LOG ANALYTICS ====================
    
    @app.route("/api/analytics/activity-heatmap")
    @login_required
    def api_activity_heatmap():
        """Get activity heat map"""
        heatmap = get_activity_heatmap()
        return jsonify(heatmap), 200
    
    @app.route("/api/analytics/user-profile")
    @login_required
    def api_user_profile():
        """Get user behavior profile"""
        user_id = request.args.get('user_id', type=int)
        profile = get_user_profile(user_id)
        return jsonify(profile), 200
    
    @app.route("/api/analytics/device-patterns")
    @login_required
    def api_device_patterns():
        """Get device access patterns"""
        patterns = get_device_patterns()
        return jsonify(patterns), 200
    
    # ==================== COMBINED MULTI-MODEL ANALYSIS ====================
    
    @app.route("/api/analytics/cross-database")
    @login_required
    @role_required('Admin', 'Investigator')
    def api_cross_database_analysis():
        """Get cross-database correlations"""
        analysis = get_cross_db_analysis()
        return jsonify(analysis), 200
    
    @app.route("/api/analytics/risk-profiles")
    @login_required
    @role_required('Admin')
    def api_risk_profiles():
        """Get high-risk user profiles"""
        profiles = get_risk_profiles()
        return jsonify(profiles), 200
    
    # ==================== QUERY INTERFACE ====================
    
    @app.route("/api/query/evidence")
    @login_required
    def api_query_evidence():
        """Query evidence by case ID"""
        case_id = request.args.get('case_id', type=int)
        if not case_id:
            return jsonify({'error': 'case_id required'}), 400
        
        evidence = get_evidence_by_case(case_id)
        return jsonify({
            'case_id': case_id,
            'evidence_count': len(evidence),
            'evidence': evidence
        }), 200
    
    @app.route("/api/query/custody-events")
    @login_required
    def api_query_custody_events():
        """Query custody events by evidence ID"""
        evidence_id = request.args.get('evidence_id', type=int)
        if not evidence_id:
            return jsonify({'error': 'evidence_id required'}), 400
        
        events = get_custody_events(evidence_id)
        return jsonify({
            'evidence_id': evidence_id,
            'event_count': len(events),
            'events': events
        }), 200
    
    @app.route("/api/query/user-custody-history")
    @login_required
    def api_user_custody_history():
        """Query custody history for a user"""
        user_id = request.args.get('user_id', type=int)
        if not user_id:
            return jsonify({'error': 'user_id required'}), 400
        
        history = get_user_custody_history(user_id)
        return jsonify({
            'user_id': user_id,
            'event_count': len(history),
            'history': history
        }), 200
    
    @app.route("/api/query/case-summary")
    @login_required
    def api_case_summary():
        """Query case summary"""
        case_id = request.args.get('case_id', type=int)
        if not case_id:
            return jsonify({'error': 'case_id required'}), 400
        
        summary = get_case_summary(case_id)
        if not summary:
            return jsonify({'error': 'Case not found'}), 404
        
        return jsonify(summary), 200
    
    # ==================== GRAPH QUERIES ====================
    
    @app.route("/api/query/custody-chain")
    @login_required
    def api_custody_chain():
        """Query full custody chain from Neo4j"""
        evidence_id = request.args.get('evidence_id', type=int)
        if not evidence_id:
            return jsonify({'error': 'evidence_id required'}), 400
        
        chain = get_custody_chain(evidence_id)
        return jsonify(chain), 200
    
    @app.route("/api/query/custody-statistics")
    @login_required
    def api_custody_relationship_stats():
        """Query custody relationship statistics"""
        evidence_id = request.args.get('evidence_id', type=int)
        if not evidence_id:
            return jsonify({'error': 'evidence_id required'}), 400
        
        stats = get_custody_statistics(evidence_id)
        return jsonify(stats), 200
    
    @app.route("/api/query/detect-anomalies")
    @login_required
    def api_detect_anomalies():
        """Detect suspicious transitions in custody chain"""
        evidence_id = request.args.get('evidence_id', type=int)
        if not evidence_id:
            return jsonify({'error': 'evidence_id required'}), 400
        
        anomalies = detect_anomalies(evidence_id)
        return jsonify(anomalies), 200
    
    @app.route("/api/query/user-network")
    @login_required
    def api_user_network():
        """Query user custody network"""
        user_id = request.args.get('user_id', type=int)
        if not user_id:
            return jsonify({'error': 'user_id required'}), 400
        
        network = get_user_network(user_id)
        return jsonify(network), 200
    
    @app.route("/api/query/case-graph")
    @login_required
    def api_case_graph():
        """Get entire custody graph for a case"""
        case_id = request.args.get('case_id', type=int)
        if not case_id:
            return jsonify({'error': 'case_id required'}), 400
        
        graph = get_case_graph(case_id)
        return jsonify(graph), 200
    
    # ==================== INTEGRITY VERIFICATION ====================
    
    @app.route("/api/integrity/verify/<int:evidence_id>", methods=['POST'])
    @login_required
    def api_verify_evidence(evidence_id):
        """Verify integrity of single evidence"""
        user_id = session.get('user_id')
        result = verify_evidence(evidence_id, user_id)
        return jsonify(result), 200
    
    @app.route("/api/integrity/verify-case/<int:case_id>", methods=['POST'])
    @login_required
    @role_required('Admin', 'Investigator')
    def api_verify_case(case_id):
        """Verify all evidence in a case"""
        user_id = session.get('user_id')
        result = verify_case_evidence(case_id, user_id)
        return jsonify(result), 200
    
    @app.route("/api/integrity/verify-pending", methods=['POST'])
    @login_required
    @role_required('Admin')
    def api_verify_pending():
        """Verify evidence due for periodic check"""
        days = request.args.get('days', default=30, type=int)
        user_id = session.get('user_id')
        results = verify_pending_evidence(days, user_id)
        return jsonify({
            'verified_count': len(results),
            'results': results
        }), 200
    
    @app.route("/api/integrity/statistics")
    @login_required
    def api_integrity_statistics():
        """Get integrity verification statistics — keys matched to dashboard."""
        from dbs.sql_db import get_connection as _gc
        try:
            conn = _gc()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM evidence WHERE is_active = TRUE;")
            total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM evidence WHERE is_active = TRUE AND last_verified_at IS NOT NULL;")
            verified = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM evidence WHERE is_active = TRUE AND last_verified_at IS NULL;")
            pending = cur.fetchone()[0]
            # failed verifications — try history table, fall back to 0
            failed = 0
            try:
                cur.execute("SELECT COUNT(*) FROM evidence_verification_history WHERE result = 'mismatch';")
                failed = cur.fetchone()[0]
            except Exception:
                conn.rollback()
            # recent verifications
            recent = []
            cur.execute("""
                SELECT evidence_id, evidence_code, last_verified_at
                FROM evidence WHERE is_active = TRUE AND last_verified_at IS NOT NULL
                ORDER BY last_verified_at DESC LIMIT 20;
            """)
            for row in cur.fetchall():
                recent.append({
                    'evidence_id': row[0], 'evidence_code': row[1],
                    'verified_at': row[2].isoformat() if row[2] else None,
                    'integrity_verified': True
                })
            cur.close(); conn.close()
            return jsonify({
                'total': total, 'verified': verified,
                'pending': pending, 'failed': failed,
                'recent_verifications': recent,
            }), 200
        except Exception as e:
            return jsonify({'total': 0, 'verified': 0, 'pending': 0,
                            'failed': 0, 'recent_verifications': [],
                            'error': str(e)}), 200
    
    @app.route("/api/integrity/verification-history/<int:evidence_id>")
    @login_required
    def api_verification_history(evidence_id):
        """Get verification history for evidence"""
        limit = request.args.get('limit', default=10, type=int)
        history = integrity_engine.get_verification_history(evidence_id, limit)
        return jsonify({
            'evidence_id': evidence_id,
            'history': history
        }), 200
    
    # ==================== DASHBOARD ====================
    
    # ==================== MISSING QUERY ENDPOINTS ====================

    @app.route("/api/query/activity-logs")
    @login_required
    def api_activity_logs():
        """MongoDB activity logs for a case"""
        from dbs.mongo_db import db as mongo_db
        case_id = request.args.get('case_id', type=int)
        try:
            query = {"case_id": case_id} if case_id else {}
            docs = list(mongo_db.case_activity_logs.find(
                query, {"_id": 0}
            ).sort("timestamp", -1).limit(50))
            for d in docs:
                if hasattr(d.get("timestamp"), "isoformat"):
                    d["timestamp"] = d["timestamp"].isoformat()
            return jsonify({"logs": docs, "count": len(docs)}), 200
        except Exception as e:
            return jsonify({"logs": [], "count": 0, "error": str(e)}), 200

    @app.route("/api/query/access-patterns")
    @login_required
    def api_access_patterns():
        """MongoDB access pattern aggregation"""
        from dbs.mongo_db import db as mongo_db
        try:
            pipeline_action = [
                {"$group": {"_id": "$action", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 15}
            ]
            by_action = [{"action": r["_id"] or "unknown", "count": r["count"]}
                         for r in mongo_db.audit_logs.aggregate(pipeline_action)]
            pipeline_ip = [
                {"$group": {"_id": "$ip_address", "access_count": {"$sum": 1}}},
                {"$sort": {"access_count": -1}},
                {"$limit": 10}
            ]
            by_ip = [{"ip": r["_id"] or "unknown", "access_count": r["access_count"]}
                     for r in mongo_db.audit_logs.aggregate(pipeline_ip)]
            return jsonify({"by_action": by_action, "top_ip_addresses": by_ip}), 200
        except Exception as e:
            return jsonify({"by_action": [], "top_ip_addresses": [], "error": str(e)}), 200

    @app.route("/api/query/evidence-profile")
    @login_required
    def api_evidence_profile():
        """Full evidence profile: SQL + Neo4j + MongoDB combined"""
        from dbs.sql_db import get_connection
        from dbs.mongo_db import db as mongo_db
        from dbs.neo4j_db import driver, NEO4J_DATABASE
        from cyber.query_interface import detect_anomalies, get_custody_chain

        evidence_id = request.args.get('evidence_id', type=int)
        if not evidence_id:
            return jsonify({"error": "evidence_id required"}), 400

        # SQL
        sql_data = {}
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute("""
                SELECT e.evidence_id, e.evidence_code, e.evidence_type, e.evidence_tag,
                       e.file_hash_sha256, e.size_bytes, e.upload_time, e.is_sealed,
                       e.seal_reason, e.last_verified_at, e.version,
                       u.full_name AS uploader,
                       c.case_number, c.title AS case_title,
                       COUNT(cl.log_id) AS custody_count
                FROM evidence e
                JOIN users u ON e.uploader_id = u.user_id
                JOIN cases c ON e.case_id = c.case_id
                LEFT JOIN coc_logs cl ON e.evidence_id = cl.evidence_id
                WHERE e.evidence_id = %s
                GROUP BY e.evidence_id, u.full_name, c.case_number, c.title;
            """, (evidence_id,))
            row = cur.fetchone()
            cur.close(); conn.close()
            if row:
                sql_data = {
                    "evidence_id": row[0], "evidence_code": row[1],
                    "evidence_type": row[2], "evidence_tag": row[3],
                    "file_hash": row[4], "size_bytes": row[5],
                    "upload_time": str(row[6]) if row[6] else None,
                    "is_sealed": row[7], "seal_reason": row[8],
                    "last_verified_at": str(row[9]) if row[9] else None,
                    "version": row[10], "uploader": row[11],
                    "case_number": row[12], "case_title": row[13],
                    "custody_count": row[14]
                }
        except Exception as e:
            sql_data = {"error": str(e)}

        # Neo4j
        neo_data = {}
        try:
            chain     = get_custody_chain(evidence_id)
            anomalies = detect_anomalies(evidence_id)
            neo_data  = {
                "total_transfers": chain.get("total_transfers", 0),
                "chain":           chain.get("chain", []),
                "anomaly_count":   anomalies.get("total_anomalies", 0),
                "anomalies":       anomalies.get("anomalies", [])[:10]
            }
        except Exception as e:
            neo_data = {"total_transfers": 0, "chain": [],
                        "anomaly_count": 0, "anomalies": [], "error": str(e)}

        # MongoDB
        mongo_data = {}
        try:
            logs = list(mongo_db.case_activity_logs.find(
                {"entity_id": evidence_id}, {"_id": 0}
            ).sort("timestamp", -1).limit(10))
            for d in logs:
                if hasattr(d.get("timestamp"), "isoformat"):
                    d["timestamp"] = d["timestamp"].isoformat()
            mongo_data = {"log_count": len(logs), "recent": logs}
        except Exception as e:
            mongo_data = {"log_count": 0, "recent": [], "error": str(e)}

        return jsonify({"sql": sql_data, "neo": neo_data, "mongo": mongo_data}), 200

    # ==================== PAGE ROUTES ====================

    @app.route("/query")
    @login_required
    def query_page():
        """Multi-model query browser page"""
        from dbs.sql_db import get_connection
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute("SELECT case_id, case_number, title FROM cases ORDER BY created_at DESC;")
        cases = [{"id": r[0], "case_number": r[1], "title": r[2]} for r in cur.fetchall()]
        cur.close(); conn.close()
        return render_template(
            "query.html",
            cases=cases,
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )

    @app.route("/analytics-dashboard")
    @login_required
    def analytics_dashboard():
        """Analytics dashboard page"""
        return render_template(
            "analytics_dashboard.html",
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )
    
    @app.route("/integrity-dashboard")
    @login_required
    def integrity_dashboard():
        """Integrity verification dashboard page"""
        stats = get_verification_stats()
        return render_template(
            "integrity_dashboard.html",
            stats=stats,
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )