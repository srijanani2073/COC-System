# Add these two routes to routes/evidence.py inside register_evidence_routes()
# They handle seal/unseal and update the evidence route to include is_sealed

# In view_evidence(), update the evidence_list dict to include is_sealed:
#     "is_sealed": r[7] if len(r) > 7 else False,
# And update the SQL query to also SELECT e.is_sealed

# New routes to add:

"""
    @app.route("/evidence/<int:evidence_id>/seal", methods=["POST"])
    @login_required
    def seal_evidence(evidence_id):
        from flask import jsonify
        action = request.form.get("action")  # "seal" or "unseal"
        reason = request.form.get("reason", "")

        if action == "unseal" and session.get("role") != "Admin":
            return jsonify({"success": False, "message": "Only admins can unseal evidence"}), 403

        conn = get_connection()
        cur = conn.cursor()
        try:
            if action == "seal":
                cur.execute(
                    "UPDATE evidence SET is_sealed=TRUE, sealed_by=%s, sealed_at=NOW(), seal_reason=%s WHERE evidence_id=%s;",
                    (session.get("user_id"), reason, evidence_id)
                )
                event = "evidence_sealed"
                desc = f"Evidence sealed: {reason}"
            else:
                cur.execute(
                    "UPDATE evidence SET is_sealed=FALSE, sealed_by=NULL, sealed_at=NULL, seal_reason=NULL WHERE evidence_id=%s;",
                    (evidence_id,)
                )
                event = "evidence_unsealed"
                desc = f"Evidence unsealed by admin"

            conn.commit()

            cur.execute("SELECT case_id FROM evidence WHERE evidence_id=%s;", (evidence_id,))
            case_id = cur.fetchone()[0]

            log_case_activity(case_id=case_id, event_type=event, description=desc,
                              entity="evidence", entity_id=evidence_id, actor_id=session.get("user_id"))
            log_audit_event(user_id=session.get("user_id"), action=action.upper(), object_type="evidence",
                            object_id=evidence_id, case_id=case_id, description=desc,
                            ip_address=request.remote_addr)

            cur.close(); conn.close()
            return jsonify({"success": True, "action": action})
        except Exception as e:
            conn.rollback(); cur.close(); conn.close()
            return jsonify({"success": False, "message": str(e)}), 500
"""
