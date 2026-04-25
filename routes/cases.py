from flask import render_template, request, redirect, session, flash, url_for
from dbs.sql_db import get_connection
from dbs.mongo_db import log_case_activity, log_audit_event
from dbs.neo4j_db import neo_create_case

def register_case_routes(app, login_required, role_required):
    @app.route("/cases")
    @login_required
    def view_cases():
        query = request.args.get("q", "")

        conn = get_connection()
        cur = conn.cursor()

        if query:
            cur.execute("""
                SELECT
                    c.case_id,
                    c.case_number,
                    c.title,
                    c.status,
                    COUNT(e.evidence_id) AS evidence_count,
                    c.created_at,
                    COALESCE(c.updated_at, c.created_at) AS last_updated
                FROM cases c
                LEFT JOIN evidence e ON e.case_id = c.case_id
                WHERE LOWER(c.title) LIKE %s OR LOWER(c.case_number) LIKE %s
                GROUP BY
                    c.case_id,
                    c.case_number,
                    c.title,
                    c.status,
                    c.created_at,
                    c.updated_at
                ORDER BY last_updated DESC;
            """, (f"%{query.lower()}%", f"%{query.lower()}%"))
        else:
            cur.execute("""
                SELECT
                    c.case_id,
                    c.case_number,
                    c.title,
                    c.status,
                    COUNT(e.evidence_id) AS evidence_count,
                    c.created_at,
                    COALESCE(c.updated_at, c.created_at) AS last_updated
                FROM cases c
                LEFT JOIN evidence e ON e.case_id = c.case_id
                GROUP BY
                    c.case_id,
                    c.case_number,
                    c.title,
                    c.status,
                    c.created_at,
                    c.updated_at
                ORDER BY last_updated DESC;
            """)

        rows = cur.fetchall()
        cur.close()
        conn.close()

        cases = []
        for r in rows:
            cases.append({
                "id": r[0],
                "case_number": r[1],
                "title": r[2],
                "status": r[3],
                "evidence_count": r[4],
                "created_at": r[5],
                "last_updated": r[6]
            })

        return render_template(
            "cases.html",
            cases=cases,
            query=query,
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )

    @app.route("/cases/add", methods=["GET", "POST"])
    @login_required
    @role_required('Admin', 'Investigator')
    def add_case():
        if request.method == "POST":
            title = request.form.get("title")
            description = request.form.get("description")
            status = request.form.get("status").lower()

            conn = get_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO cases (
                    title,
                    description,
                    status,
                    created_by,
                    created_at
                )
                VALUES (
                     %s, %s, %s, %s, NOW()
                )
                RETURNING case_id, case_number;
            """, (
                title,
                description,
                status,
                session.get('user_id', 1)
            ))

            result = cur.fetchone()
            new_case_id = result[0]
            case_number = result[1]

            conn.commit()
            cur.close()
            conn.close()

            neo_create_case(
                case_id=new_case_id,
                case_number=case_number,
                status=status,
                created_by_user_id=session.get('user_id', 1),
                created_by_username=session.get('full_name') or session.get('username'),
                created_by_role=session.get('role')
            )

            log_case_activity(
                case_id=new_case_id,
                event_type="case_created",
                description="Case created",
                entity="case",
                entity_id=new_case_id,
                actor_id=session.get('user_id', 1)
            )

            log_audit_event(
                user_id=session.get('user_id', 1),
                action="CREATE",
                object_type="case",
                object_id=new_case_id,
                case_id=new_case_id,
                description=f"Created case: {title}",
                ip_address=request.remote_addr
            )

            flash('Case created successfully!', 'success')
            return redirect(url_for('view_cases'))

        return render_template(
            "add_case.html",
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )

    @app.route("/cases/edit/<int:case_id>", methods=["GET", "POST"])
    @login_required
    @role_required('Admin', 'Investigator')
    def edit_case(case_id):
        conn = get_connection()
        cur = conn.cursor()

        if request.method == "POST":
            title = request.form.get("title")
            description = request.form.get("description")
            status = request.form.get("status").lower()

            cur.execute("""
                UPDATE cases
                SET title = %s, description = %s, status = %s, updated_at = NOW()
                WHERE case_id = %s;
            """, (title, description, status, case_id))

            conn.commit()

            # If case is being closed, auto-seal all active unsealed evidence
            if status == 'closed':
                try:
                    cur.execute("""
                        UPDATE evidence
                        SET is_sealed = TRUE,
                            sealed_by = %s,
                            sealed_at = NOW(),
                            seal_reason = 'Case closed — evidence automatically sealed'
                        WHERE case_id = %s AND is_active = TRUE AND (is_sealed = FALSE OR is_sealed IS NULL)
                        RETURNING evidence_id, evidence_code;
                    """, (session.get('user_id'), case_id))
                    sealed_rows = cur.fetchall()
                    conn.commit()
                    from dbs.neo4j_db import neo_seal_evidence
                    from datetime import datetime, timedelta, timezone
                    _IST = timezone(timedelta(hours=5, minutes=30))
                    _now_str = datetime.now(_IST).isoformat()
                    for ev_id, ev_code in sealed_rows:
                        try:
                            neo_seal_evidence(
                                evidence_id=ev_id,
                                sealed_by_user_id=session.get('user_id', 1),
                                sealed_at=_now_str,
                                reason='Case closed — evidence automatically sealed',
                                action='seal',
                                user_username=session.get('full_name') or session.get('username'),
                                user_role=session.get('role'),
                            )
                        except Exception:
                            pass
                    if sealed_rows:
                        flash(f'{len(sealed_rows)} evidence item(s) automatically sealed due to case closure.', 'info')
                except Exception:
                    pass

            log_case_activity(
                case_id=case_id,
                event_type="case_updated",
                description="Case details updated",
                entity="case",
                entity_id=case_id,
                actor_id=session.get('user_id', 1)
            )

            log_audit_event(
                user_id=session.get('user_id', 1),
                action="UPDATE",
                object_type="case",
                object_id=case_id,
                case_id=case_id,
                description=f"Updated case: {title}",
                ip_address=request.remote_addr
            )

            cur.close()
            conn.close()

            flash('Case updated successfully!', 'success')
            return redirect(url_for('view_cases'))

        cur.execute("""
            SELECT case_id, case_number, title, description, status
            FROM cases WHERE case_id = %s;
        """, (case_id,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            flash('Case not found', 'error')
            return redirect(url_for('view_cases'))

        case = {"id": row[0], "case_number": row[1], "title": row[2],
                "description": row[3], "status": row[4]}

        # Who currently has access (active grants)
        cur.execute("""
            SELECT ca.access_id, u.user_id, u.full_name, u.username,
                   r.role_name, ca.granted_at, g.full_name
            FROM   case_access ca
            JOIN   users u ON ca.user_id    = u.user_id
            JOIN   roles r ON u.role_id     = r.role_id
            JOIN   users g ON ca.granted_by = g.user_id
            WHERE  ca.case_id = %s AND ca.is_active = TRUE
            ORDER  BY ca.granted_at DESC;
        """, (case_id,))
        access_list = [
            {"access_id": r[0], "user_id": r[1], "full_name": r[2],
             "username": r[3], "role": r[4], "granted_at": r[5], "granted_by": r[6]}
            for r in cur.fetchall()
        ]

        # Restricted-role users not yet granted access
        cur.execute("""
            SELECT u.user_id, u.full_name, u.username, r.role_name
            FROM   users u
            JOIN   roles r ON u.role_id = r.role_id
            WHERE  r.role_name IN ('Lawyer', 'Prosecutor', 'Judge')
              AND  u.is_active = TRUE
              AND  u.user_id NOT IN (
                       SELECT user_id FROM case_access
                       WHERE  case_id = %s AND is_active = TRUE
                   )
            ORDER  BY r.role_name, u.full_name;
        """, (case_id,))
        available_users = [
            {"user_id": r[0], "full_name": r[1], "username": r[2], "role": r[3]}
            for r in cur.fetchall()
        ]
        cur.close(); conn.close()

        return render_template(
            "edit_case.html",
            case=case,
            access_list=access_list,
            available_users=available_users,
            user=session.get('full_name', 'User'),
            role=session.get('role', 'Unknown')
        )

    # ── Grant access ──────────────────────────────────────────────────────────
    @app.route("/cases/<int:case_id>/access/grant", methods=["POST"])
    @login_required
    @role_required('Admin')
    def grant_case_access(case_id):
        user_id_to_grant = request.form.get("user_id", type=int)
        notes = request.form.get("notes", "").strip()
        if not user_id_to_grant:
            flash("No user selected.", "error")
            return redirect(url_for('edit_case', case_id=case_id))

        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO case_access (case_id, user_id, granted_by, granted_at, is_active, notes)
                VALUES (%s, %s, %s, NOW(), TRUE, %s)
                ON CONFLICT (case_id, user_id)
                DO UPDATE SET is_active=TRUE, granted_by=EXCLUDED.granted_by,
                              granted_at=NOW(), revoked_at=NULL, revoked_by=NULL,
                              notes=EXCLUDED.notes;
            """, (case_id, user_id_to_grant, session['user_id'], notes or None))
            conn.commit()
            cur.execute("SELECT full_name FROM users WHERE user_id = %s;", (user_id_to_grant,))
            name = (cur.fetchone() or ["User"])[0]
            flash(f"Access granted to {name}.", "success")
            from dbs.mongo_db import log_audit_event
            log_audit_event(user_id=session['user_id'], action="GRANT_CASE_ACCESS",
                            object_type="case", object_id=case_id, case_id=case_id,
                            description=f"Granted download access to {name} (uid {user_id_to_grant})",
                            ip_address=request.remote_addr)
        except Exception as e:
            conn.rollback()
            flash(f"Failed to grant access: {e}", "error")
        finally:
            cur.close(); conn.close()
        return redirect(url_for('edit_case', case_id=case_id))

    # ── Revoke access ─────────────────────────────────────────────────────────
    @app.route("/cases/<int:case_id>/access/revoke/<int:target_user_id>", methods=["POST"])
    @login_required
    @role_required('Admin')
    def revoke_case_access(case_id, target_user_id):
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                UPDATE case_access SET is_active=FALSE, revoked_at=NOW(), revoked_by=%s
                WHERE case_id=%s AND user_id=%s AND is_active=TRUE;
            """, (session['user_id'], case_id, target_user_id))
            conn.commit()
            cur.execute("SELECT full_name FROM users WHERE user_id = %s;", (target_user_id,))
            name = (cur.fetchone() or ["User"])[0]
            flash(f"Access revoked for {name}.", "success")
            from dbs.mongo_db import log_audit_event
            log_audit_event(user_id=session['user_id'], action="REVOKE_CASE_ACCESS",
                            object_type="case", object_id=case_id, case_id=case_id,
                            description=f"Revoked download access for {name} (uid {target_user_id})",
                            ip_address=request.remote_addr)
        except Exception as e:
            conn.rollback()
            flash(f"Failed to revoke access: {e}", "error")
        finally:
            cur.close(); conn.close()
        return redirect(url_for('edit_case', case_id=case_id))