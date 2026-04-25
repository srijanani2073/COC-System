from dbs.sql_db import get_connection
from dbs.neo4j_db import driver, NEO4J_DATABASE
from dbs.mongo_db import db
from datetime import datetime, timedelta
from collections import defaultdict

class AnalyticsEngine:
    """
    Comprehensive analytics engine for evidence management system
    """
    
    def __init__(self):
        pass
    
    # ==================== ADMINISTRATIVE OUTPUTS ====================
    
    def get_evidence_statistics(self):
        """
        Get comprehensive evidence statistics
        
        Output:
        - Total evidence count
        - Evidence by type
        - Evidence by case
        - Evidence by status
        """
        conn = get_connection()
        cur = conn.cursor()
        
        # Total evidence
        cur.execute("SELECT COUNT(*) FROM evidence WHERE is_active = TRUE;")
        total_evidence = cur.fetchone()[0]
        
        # Evidence by type
        cur.execute("""
            SELECT evidence_type, COUNT(*) as count
            FROM evidence
            WHERE is_active = TRUE
            GROUP BY evidence_type;
        """)
        by_type = {row[0]: row[1] for row in cur.fetchall()}
        
        # Evidence by case
        cur.execute("""
            SELECT c.case_number, COUNT(e.evidence_id) as count
            FROM cases c
            LEFT JOIN evidence e ON c.case_id = e.case_id AND e.is_active = TRUE
            GROUP BY c.case_id, c.case_number
            ORDER BY count DESC
            LIMIT 10;
        """)
        by_case = [{'case_number': row[0], 'count': row[1]} for row in cur.fetchall()]
        
        # Total file size — exclude NULLs (physical evidence has no size)
        cur.execute("""
            SELECT
                COALESCE(SUM(size_bytes), 0) AS total_bytes,
                COUNT(*) FILTER (WHERE size_bytes IS NOT NULL) AS with_size,
                COUNT(*) FILTER (WHERE size_bytes IS NULL)     AS no_size
            FROM evidence
            WHERE is_active = TRUE;
        """)
        sr = cur.fetchone()
        raw_bytes   = int(sr[0]) if sr[0] else 0
        with_size   = int(sr[1]) if sr[1] else 0
        no_size     = int(sr[2]) if sr[2] else 0
        total_size  = raw_bytes

        # Evidence uploaded in last 30 days — DB-side interval avoids tz mismatch
        cur.execute("""
            SELECT COUNT(*)
            FROM evidence
            WHERE is_active = TRUE
              AND upload_time >= NOW() - INTERVAL '30 days';
        """)
        recent_uploads = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return {
            'total_evidence': total_evidence,
            'by_type': by_type,
            'top_cases': by_case,
            'total_size_bytes': total_size,
            'total_size_mb':  round(total_size / (1024 * 1024), 2),
            'total_size_gb':  round(total_size / (1024 * 1024 * 1024), 3),
            'evidence_with_size': with_size,
            'evidence_no_size':   no_size,
            'recent_uploads_30d': recent_uploads
        }
    
    def get_custody_statistics(self):
        """
        Get custody transfer statistics
        
        Output:
        - Total custody events
        - Events by action type
        - Events by user
        - Recent activity
        """
        conn = get_connection()
        cur = conn.cursor()
        
        # Total custody events
        cur.execute("SELECT COUNT(*) FROM coc_logs;")
        total_events = cur.fetchone()[0]
        
        # Events by action
        cur.execute("""
            SELECT action, COUNT(*) as count
            FROM coc_logs
            GROUP BY action
            ORDER BY count DESC;
        """)
        by_action = [{'action': row[0], 'count': row[1]} for row in cur.fetchall()]
        
        # Most active users (involved in custody)
        cur.execute("""
            SELECT u.full_name, COUNT(cl.log_id) as event_count
            FROM users u
            JOIN (
                SELECT from_user_id as user_id, log_id FROM coc_logs WHERE from_user_id IS NOT NULL
                UNION ALL
                SELECT to_user_id as user_id, log_id FROM coc_logs WHERE to_user_id IS NOT NULL
            ) cl ON u.user_id = cl.user_id
            GROUP BY u.user_id, u.full_name
            ORDER BY event_count DESC
            LIMIT 10;
        """)
        active_users = [{'name': row[0], 'events': row[1]} for row in cur.fetchall()]
        
        # Recent custody events
        cur.execute("""
            SELECT COUNT(*)
            FROM coc_logs
            WHERE timestamp >= NOW() - INTERVAL '7 days';
        """)
        recent_events = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return {
            'total_events': total_events,
            'by_action': by_action,
            'active_users': active_users,
            'recent_events_7d': recent_events
        }
    
    def get_case_summaries(self, limit=20):
        """
        Get summaries of all cases
        
        Output:
        - Case list with statistics
        """
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT 
                c.case_id,
                c.case_number,
                c.title,
                c.status,
                c.created_at,
                u.full_name as created_by,
                COUNT(DISTINCT e.evidence_id) as evidence_count,
                COUNT(DISTINCT cl.log_id) as custody_events
            FROM cases c
            JOIN users u ON c.created_by = u.user_id
            LEFT JOIN evidence e ON c.case_id = e.case_id AND e.is_active = TRUE
            LEFT JOIN coc_logs cl ON e.evidence_id = cl.evidence_id
            GROUP BY c.case_id, c.case_number, c.title, c.status, c.created_at, u.full_name
            ORDER BY c.created_at DESC
            LIMIT %s;
        """, (limit,))
        
        summaries = []
        for row in cur.fetchall():
            summaries.append({
                'case_id': row[0],
                'case_number': row[1],
                'title': row[2],
                'status': row[3],
                'created_at': row[4],
                'created_by': row[5],
                'evidence_count': row[6],
                'custody_events': row[7]
            })
        
        cur.close()
        conn.close()
        
        return summaries
    
    # ==================== GRAPH ANALYTICS ====================
    
    def analyze_custody_path_lengths(self):
        """
        Analyze path lengths in custody chains
        
        Output:
        - Average path length
        - Maximum path length
        - Evidence with longest chains
        """
        with driver.session(database=NEO4J_DATABASE) as session:
            result = session.run("""
                MATCH path = (e:Evidence)-[:HAS_CUSTODY_EVENT*]->(ce:CustodyEvent)
                WITH e.evidence_id as evidence_id, 
                     COUNT(DISTINCT ce) as chain_length
                RETURN 
                    evidence_id,
                    chain_length
                ORDER BY chain_length DESC
                LIMIT 20
            """)
            
            chains = []
            total_length = 0
            max_length = 0
            
            for record in result:
                eid = record['evidence_id']
                length = record['chain_length']
                chains.append({'evidence_id': eid, 'chain_length': length})
                total_length += length
                max_length = max(max_length, length)
            
            avg_length = total_length / len(chains) if chains else 0
            
            return {
                'average_chain_length': round(avg_length, 2),
                'max_chain_length': max_length,
                'longest_chains': chains[:10]
            }
    
    def analyze_transfer_frequency(self):
        """
        Analyze transfer frequency patterns
        
        Output:
        - Total transfers
        - Transfers by time period
        - Most frequently transferred evidence
        """
        conn = get_connection()
        cur = conn.cursor()
        
        # Total transfers
        cur.execute("SELECT COUNT(*) FROM coc_logs WHERE action = 'transfer';")
        total_transfers = cur.fetchone()[0]
        
        # Transfers by day of week
        cur.execute("""
            SELECT 
                EXTRACT(DOW FROM timestamp) as day_of_week,
                COUNT(*) as count
            FROM coc_logs
            WHERE action = 'transfer'
            GROUP BY day_of_week
            ORDER BY day_of_week;
        """)
        by_day = [{'day': int(row[0]), 'count': row[1]} for row in cur.fetchall()]
        
        # Most transferred evidence
        cur.execute("""
            SELECT 
                e.evidence_id,
                e.evidence_code,
                COUNT(cl.log_id) as transfer_count
            FROM evidence e
            JOIN coc_logs cl ON e.evidence_id = cl.evidence_id
            WHERE cl.action = 'transfer'
            GROUP BY e.evidence_id, e.evidence_code
            ORDER BY transfer_count DESC
            LIMIT 10;
        """)
        most_transferred = [
            {'evidence_id': row[0], 'evidence_code': row[1], 'transfers': row[2]}
            for row in cur.fetchall()
        ]
        
        cur.close()
        conn.close()
        
        return {
            'total_transfers': total_transfers,
            'by_day_of_week': by_day,
            'most_transferred': most_transferred
        }
    
    def detect_all_suspicious_transitions(self):
        """
        Detect suspicious transitions across all evidence
        
        Output:
        - List of suspicious patterns
        """
        suspicious = []
        
        # Get all evidence with custody events
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT evidence_id FROM coc_logs;")
        evidence_ids = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
        
        for eid in evidence_ids[:50]:  # Limit to first 50 for performance
            # Check for rapid transfers
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT log_id, timestamp, action
                FROM coc_logs
                WHERE evidence_id = %s
                ORDER BY timestamp ASC;
            """, (eid,))
            
            events = cur.fetchall()
            cur.close()
            conn.close()
            
            for i in range(len(events) - 1):
                current = events[i]
                next_event = events[i + 1]
                
                time_diff = (next_event[1] - current[1]).total_seconds()
                
                if time_diff < 300:  # Less than 5 minutes
                    suspicious.append({
                        'evidence_id': eid,
                        'type': 'rapid_transfer',
                        'severity': 'medium',
                        'time_difference_seconds': time_diff,
                        'timestamp': next_event[1]
                    })
        
        return {
            'total_suspicious': len(suspicious),
            'patterns': suspicious[:20]  # Return top 20
        }
    
    # ==================== LOG ANALYTICS ====================
    
    def generate_activity_heatmap(self):
        """
        Generate heat map of activity by hour and day
        
        Output:
        - Activity counts by hour of day
        - Activity counts by day of week
        """
        # Query MongoDB for activity logs
        pipeline = [
            {
                '$group': {
                    '_id': {
                        'hour': {'$hour': '$timestamp'},
                        'dayOfWeek': {'$dayOfWeek': '$timestamp'}
                    },
                    'count': {'$sum': 1}
                }
            },
            {
                '$sort': {'_id.dayOfWeek': 1, '_id.hour': 1}
            }
        ]
        
        activity_data = list(db.audit_logs.aggregate(pipeline))
        
        heatmap = defaultdict(lambda: defaultdict(int))
        
        for item in activity_data:
            day = item['_id']['dayOfWeek']
            hour = item['_id']['hour']
            count = item['count']
            heatmap[day][hour] = count
        
        return {
            'heatmap': dict(heatmap),
            'total_activities': sum(item['count'] for item in activity_data)
        }
    
    def profile_user_behavior(self, user_id=None):
        """
        Profile user behavior patterns
        
        Output:
        - Action frequency
        - Most common actions
        - Activity timeline
        """
        query = {'user_id': user_id} if user_id else {}
        
        # Action frequency
        pipeline = [
            {'$match': query},
            {
                '$group': {
                    '_id': '$action',
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'count': -1}}
        ]
        
        action_freq = list(db.audit_logs.aggregate(pipeline))
        
        # Recent activity
        recent = list(
            db.audit_logs.find(query)
            .sort('timestamp', -1)
            .limit(50)
        )
        
        return {
            'user_id': user_id,
            'action_frequency': [
                {'action': item['_id'], 'count': item['count']}
                for item in action_freq
            ],
            'recent_activity': [
                {
                    'action': act['action'],
                    'object_type': act.get('object_type'),
                    'timestamp': act['timestamp']
                }
                for act in recent
            ],
            'total_actions': sum(item['count'] for item in action_freq)
        }
    
    def analyze_device_access_patterns(self):
        """
        Analyze device-based access patterns
        
        Output:
        - Access by IP address
        - Unusual access patterns
        """
        pipeline = [
            {
                '$group': {
                    '_id': '$ip_address',
                    'count': {'$sum': 1},
                    'users': {'$addToSet': '$user_id'}
                }
            },
            {'$sort': {'count': -1}},
            {'$limit': 20}
        ]
        
        ip_stats = list(db.audit_logs.aggregate(pipeline))
        
        # Detect multiple users from same IP
        multi_user_ips = [
            {
                'ip': item['_id'],
                'access_count': item['count'],
                'user_count': len(item['users'])
            }
            for item in ip_stats
            if len(item['users']) > 1
        ]
        
        return {
            'top_ip_addresses': [
                {'ip': item['_id'], 'access_count': item['count']}
                for item in ip_stats[:10]
            ],
            'multi_user_ips': multi_user_ips
        }
    
    # ==================== COMBINED MULTI-MODEL ANALYSIS ====================
    
    def analyze_cross_database_correlations(self):
        """
        Cross-database correlations between SQL, MongoDB, and Neo4j
        
        Output:
        - Evidence with most activity
        - High-risk patterns
        """
        # Get evidence with most versions (SQL)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                original_filename,
                case_id,
                COUNT(*) as version_count
            FROM evidence
            WHERE is_active = TRUE
            GROUP BY original_filename, case_id
            HAVING COUNT(*) > 1
            ORDER BY version_count DESC
            LIMIT 10;
        """)
        most_versioned = cur.fetchall()
        cur.close()
        conn.close()
        
        # Get evidence with most MongoDB activity
        pipeline = [
            {
                '$match': {'entity': 'evidence'}
            },
            {
                '$group': {
                    '_id': '$entity_id',
                    'activity_count': {'$sum': 1}
                }
            },
            {'$sort': {'activity_count': -1}},
            {'$limit': 10}
        ]
        
        most_active_mongo = list(db.case_activity_logs.aggregate(pipeline))
        
        # Get evidence with longest custody chains (Neo4j)
        path_analysis = self.analyze_custody_path_lengths()
        
        return {
            'most_versioned_evidence': [
                {
                    'filename': row[0],
                    'case_id': row[1],
                    'versions': row[2]
                }
                for row in most_versioned
            ],
            'most_active_evidence': [
                {
                    'evidence_id': item['_id'],
                    'activity_count': item['activity_count']
                }
                for item in most_active_mongo
            ],
            'longest_custody_chains': path_analysis['longest_chains']
        }
    
    def identify_high_risk_users(self):
        """
        Identify high-risk user profiles based on multiple factors
        
        Output:
        - Users with unusual patterns
        - Risk scores
        """
        # Users with failed verifications
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                u.user_id,
                u.full_name,
                COUNT(vh.verify_id) as failed_verifications
            FROM users u
            JOIN evidence_verification_history vh ON u.user_id = vh.verified_by
            WHERE vh.result = 'mismatch'
            GROUP BY u.user_id, u.full_name
            HAVING COUNT(vh.verify_id) > 0
            ORDER BY failed_verifications DESC;
        """)
        users_with_failures = cur.fetchall()
        cur.close()
        conn.close()
        
        # Users with rapid custody transfers
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                u.user_id,
                u.full_name,
                COUNT(cl.log_id) as rapid_transfers
            FROM users u
            JOIN coc_logs cl ON u.user_id = cl.from_user_id
            WHERE cl.action = 'transfer'
            GROUP BY u.user_id, u.full_name
            HAVING COUNT(cl.log_id) > 10
            ORDER BY rapid_transfers DESC
            LIMIT 10;
        """)
        frequent_transferrers = cur.fetchall()
        cur.close()
        conn.close()
        
        return {
            'users_with_failed_verifications': [
                {'user_id': row[0], 'name': row[1], 'failed_count': row[2]}
                for row in users_with_failures
            ],
            'frequent_transferrers': [
                {'user_id': row[0], 'name': row[1], 'transfer_count': row[2]}
                for row in frequent_transferrers
            ]
        }


# Global instance
analytics_engine = AnalyticsEngine()


# ==================== CONVENIENCE FUNCTIONS ====================

def get_evidence_stats():
    """Get evidence statistics"""
    return analytics_engine.get_evidence_statistics()


def get_custody_stats():
    """Get custody statistics"""
    return analytics_engine.get_custody_statistics()


def get_all_case_summaries():
    """Get case summaries"""
    return analytics_engine.get_case_summaries()


def get_path_analytics():
    """Get custody path analytics"""
    return analytics_engine.analyze_custody_path_lengths()


def get_transfer_analytics():
    """Get transfer frequency analytics"""
    return analytics_engine.analyze_transfer_frequency()


def get_suspicious_patterns():
    """Detect suspicious transitions"""
    return analytics_engine.detect_all_suspicious_transitions()


def get_activity_heatmap():
    """Get activity heat map"""
    return analytics_engine.generate_activity_heatmap()


def get_user_profile(user_id=None):
    """Get user behavior profile"""
    return analytics_engine.profile_user_behavior(user_id)


def get_device_patterns():
    """Get device access patterns"""
    return analytics_engine.analyze_device_access_patterns()


def get_cross_db_analysis():
    """Get cross-database analysis"""
    return analytics_engine.analyze_cross_database_correlations()


def get_risk_profiles():
    """Get high-risk user profiles"""
    return analytics_engine.identify_high_risk_users()