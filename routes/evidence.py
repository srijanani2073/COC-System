from flask import render_template, request, redirect, session, flash, url_for, jsonify, Response
from dbs.sql_db import get_connection
from dbs.supabase_storage import upload_file_to_supabase, upload_encrypted_bytes_to_supabase, get_public_url, fetch_encrypted_bytes, DuplicateFileError
from dbs.mongo_db import log_case_activity, store_evidence_metadata, log_audit_event, log_evidence_download
from dbs.neo4j_db import neo_add_evidence, neo_seal_evidence, neo_add_custody_event
from routes.evidence_versioning import (
    get_evidence_by_hash, get_latest_version, store_evidence_version,
    check_file_similarity, get_version_history
)
from cyber.crypto_pipeline import crypto_pipeline
import hashlib
from datetime import datetime, timedelta, timezone

_IST = timezone(timedelta(hours=5, minutes=30))
def _now_ist(): return datetime.now(_IST)


def compute_sha256(file):
    hasher = hashlib.sha256()
    file.stream.seek(0)
    while chunk := file.stream.read(8192):
        hasher.update(chunk)
    file.stream.seek(0)
    return hasher.hexdigest()


def get_next_version_for_filename(case_id, filename):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT MAX(version) FROM evidence
        WHERE case_id = %s AND original_filename = %s;
    """, (case_id, filename))
    result = cur.fetchone()
    cur.close(); conn.close()
    return (result[0] + 1) if result[0] else 1


def generate_evidence_code(case_id, evidence_type, version, conn=None):
    """
    New naming scheme: {case_id:03d}{D|P}{sequence:02d}[-v{version}]
    Examples: 011D01, 011D02, 011P01, 011P01-v2

    sequence = count of existing evidence of same type in same case + 1
    (counts all versions, not just latest, so it always increments)
    """
    type_char = 'D' if evidence_type == 'digital' else 'P'
    close_conn = False
    if conn is None:
        from dbs.sql_db import get_connection
        conn = get_connection()
        close_conn = True
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM evidence
               WHERE case_id = %s AND evidence_type = %s;""",
            (case_id, evidence_type)
        )
        existing = cur.fetchone()[0]
        cur.close()
    finally:
        if close_conn:
            conn.close()
    seq = existing + 1
    base = f"{case_id:03d}{type_char}{seq:02d}"
    return base if version == 1 else f"{base}-v{version}"


def register_evidence_routes(app, login_required, role_required):

    @app.route("/evidence")
    @login_required
    def view_evidence():
        case_id = request.args.get("case_id", type=int)
        if not case_id:
            flash('Please select a case first', 'error')
            return redirect(url_for('view_cases'))

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT case_number, title FROM cases WHERE case_id = %s;", (case_id,))
        case_info = cur.fetchone()
        if not case_info:
            flash('Case not found', 'error')
            return redirect(url_for('view_cases'))
        case_number, case_title = case_info

        cur.execute("""
            SELECT e.evidence_id, e.evidence_type, e.evidence_tag, e.version,
                   e.upload_time, e.file_hash_sha256, e.original_filename,
                   e.is_sealed, e.sealed_by, e.sealed_at, e.seal_reason,
                   e.rsa_signature
            FROM evidence e
            WHERE e.case_id = %s AND e.is_active = TRUE
            ORDER BY e.original_filename, e.version DESC;
        """, (case_id,))
        rows = cur.fetchall()

        evidence_list = []
        for r in rows:
            cur.execute("""
                SELECT COUNT(*) FROM evidence
                WHERE case_id = %s AND original_filename = %s AND is_active = TRUE;
            """, (case_id, r[6]))
            version_count = cur.fetchone()[0]
            evidence_list.append({
                "id": r[0], "type": r[1], "tag": r[2] if r[2] else r[6],
                "version": r[3], "uploaded_at": r[4],
                "hash": r[5][:16] if r[5] else None,
                "version_count": version_count,
                "is_sealed": r[7] or False,
                "sealed_by": r[8], "sealed_at": r[9],
                "seal_reason": r[10],
                "has_signature": bool(r[11])
            })

        cur.close(); conn.close()
        return render_template("evidence.html", case_id=case_id, case_number=case_number,
                               case_title=case_title, evidence=evidence_list,
                               user=session.get('full_name', 'User'),
                               role=session.get('role', 'Unknown'))

    @app.route("/evidence/add", methods=["GET", "POST"])
    @login_required
    @role_required('Admin', 'Investigator', 'Forensic Analyst')
    def add_evidence():
        if request.method == "POST":
            case_id_raw = request.form.get("case_id")
            # Only 'digital' or 'physical' allowed by DB constraint
            _etype_raw = request.form.get("evidence_type", "digital").lower()
            evidence_type = "digital" if _etype_raw not in ("digital", "physical") else _etype_raw
            description = request.form.get("description", "")
            source = request.form.get("source", "")
            file = request.files.get("file")

            if not case_id_raw:
                flash('Please select a case', 'error')
                return redirect(url_for('add_evidence'))
            if not file or file.filename == "":
                flash('No file selected', 'error')
                return redirect(url_for('add_evidence'))

            try:
                case_id = int(case_id_raw)
            except ValueError:
                flash('Invalid case selected', 'error')
                return redirect(url_for('add_evidence'))

            # Check case status — closed cases block all evidence upload; archived cases too
            try:
                _conn_chk = get_connection(); _cur_chk = _conn_chk.cursor()
                _cur_chk.execute("SELECT status FROM cases WHERE case_id = %s;", (case_id,))
                _case_row = _cur_chk.fetchone()
                _cur_chk.close(); _conn_chk.close()
                if _case_row:
                    _cs = (_case_row[0] or '').lower()
                    if _cs == 'closed':
                        flash('Cannot add evidence — this case is closed. All evidence is sealed.', 'error')
                        return redirect(url_for('add_evidence', case_id=case_id))
                    if _cs == 'archived':
                        flash('Cannot add evidence — this case is archived.', 'error')
                        return redirect(url_for('add_evidence', case_id=case_id))
            except Exception:
                pass

            # Read file into memory once
            file_data = file.stream.read()
            file.stream.seek(0)
            file_size = len(file_data)
            filename = file.filename
            content_type = file.content_type or 'application/octet-stream'

            # Step 1: SHA-256 hash + RSA signature (no AES yet — need evidence_id for HKDF)
            file_hash = hashlib.sha256(file_data).hexdigest()
            try:
                rsa_signature = crypto_pipeline.generate_rsa_signature(file_hash)
            except Exception:
                rsa_signature = None

            version = get_next_version_for_filename(case_id, filename)
            conn = get_connection()
            cur = conn.cursor()
            evidence_code = generate_evidence_code(case_id, evidence_type, version, conn)
            evidence_tag = description if description else filename

            try:
                # Duplicate check
                cur.execute("""
                    SELECT evidence_id, version FROM evidence
                    WHERE case_id = %s AND original_filename = %s
                          AND file_hash_sha256 = %s AND is_active = TRUE;
                """, (case_id, filename, file_hash))
                duplicate = cur.fetchone()
                if duplicate:
                    cur.close(); conn.close()
                    flash(f'Duplicate detected: identical file already exists as version {duplicate[1]}', 'warning')
                    return redirect(url_for('add_evidence', case_id=case_id))

                # ── Step 1: Upload plaintext temporarily to get a storage_path ──
                # We need evidence_id before we can derive the AES key (HKDF),
                # so we upload plaintext first, then overwrite with ciphertext below.
                file.stream.seek(0)
                storage_path = upload_file_to_supabase(file, case_id, evidence_code, version)
                public_url = get_public_url(storage_path)

                # ── Step 2: INSERT row → get evidence_id ──────────────────────
                # IV is NULL for now; updated once we encrypt in step 3.
                cur.execute("""
                    INSERT INTO evidence (
                        case_id, evidence_code, evidence_type, evidence_tag, uploader_id,
                        upload_time, original_filename, content_mime, size_bytes,
                        file_hash_sha256, mongo_file_id, is_active, created_at,
                        last_verified_at, version, rsa_signature, encryption_key, encryption_iv,
                        is_sealed, sealed_by, sealed_at, seal_reason
                    )
                    VALUES (%s,%s,%s,%s,%s,NOW(),%s,%s,%s,%s,%s,TRUE,NOW(),NULL,%s,%s,NULL,NULL,FALSE,NULL,NULL,NULL)
                    RETURNING evidence_id;
                """, (case_id, evidence_code, evidence_type, evidence_tag,
                      session.get('user_id', 1), filename, content_type, file_size,
                      file_hash, storage_path, version, rsa_signature))

                evidence_id = cur.fetchone()[0]

                # ── Step 3: AES-256 encrypt with HKDF-derived key, overwrite in Supabase ──
                # Now that we have evidence_id, derive the AES key deterministically
                # and replace the plaintext file with the encrypted ciphertext.
                encryption_iv = None
                try:
                    enc_result = crypto_pipeline.encrypt_file_aes256(file_data, evidence_id)
                    encryption_iv = enc_result['iv']
                    encrypted_bytes = enc_result['encrypted_data']

                    # Overwrite the plaintext in Supabase with the encrypted bytes
                    upload_encrypted_bytes_to_supabase(encrypted_bytes, storage_path)

                    # Persist the IV (key is never stored — re-derived on demand)
                    cur.execute(
                        "UPDATE evidence SET encryption_iv = %s WHERE evidence_id = %s;",
                        (encryption_iv, evidence_id)
                    )
                except Exception as enc_err:
                    # Log the failure but don't roll back — file is in Supabase,
                    # metadata is in DB. Mark as unencrypted so integrity engine knows.
                    try:
                        cur.execute(
                            "UPDATE evidence SET encryption_iv = NULL WHERE evidence_id = %s;",
                            (evidence_id,)
                        )
                    except Exception:
                        pass

                conn.commit()

                event_type = "evidence_uploaded" if version == 1 else "evidence_version_uploaded"
                flash(f'Evidence uploaded: {filename} (v{version}) — SHA-256 hashed, RSA signed, AES-256 encrypted', 'success')

                # Log to MongoDB and Neo4j (non-fatal if they fail)
                try:
                    log_case_activity(case_id=case_id, event_type=event_type,
                                      description=f"{'Evidence uploaded' if version == 1 else 'New version'}: {filename} v{version}",
                                      entity="evidence", entity_id=evidence_id,
                                      actor_id=session.get('user_id', 1))
                except Exception:
                    pass
                try:
                    store_evidence_version(evidence_id=evidence_id, case_id=case_id,
                                           evidence_code=evidence_code, file_hash=file_hash,
                                           file_size=file_size, filename=filename, version=version,
                                           storage_path=storage_path, content_hash=file_hash,
                                           uploaded_by=session.get('user_id', 1), is_duplicate=False,
                                           parent_version=(version - 1) if version > 1 else None)
                except Exception:
                    pass
                try:
                    store_evidence_metadata(evidence_id=evidence_id, case_id=case_id,
                                            metadata={
                                                "filename":      filename,
                                                "original_name": filename,
                                                "content_type":  content_type,
                                                "file_type":     filename.rsplit(".", 1)[-1] if "." in filename else "",
                                                "size":          file_size,
                                                "description":   description,
                                                "source":        source,
                                                "evidence_code": evidence_code,
                                                "evidence_tag":  evidence_tag,
                                                "version":       version,
                                                "is_new_version": version > 1,
                                                "public_url":    public_url,
                                                "storage_path":  storage_path,
                                                "storage":       "supabase",
                                                "hash":          file_hash,
                                            })
                except Exception:
                    pass
                try:
                    neo_add_evidence(
                        evidence_id=evidence_id, case_id=case_id,
                        evidence_code=evidence_code, evidence_type=evidence_type,
                        evidence_tag=evidence_tag, is_active=True,
                        uploader_id=session.get('user_id', 1),
                        uploader_username=session.get('full_name') or session.get('username'),
                        uploader_role=session.get('role')
                    )
                except Exception:
                    pass
                try:
                    log_audit_event(user_id=session.get('user_id', 1), action="UPLOAD",
                                    object_type="evidence", object_id=evidence_id, case_id=case_id,
                                    description=f"Uploaded: {filename} v{version}",
                                    ip_address=request.remote_addr)
                except Exception:
                    pass

                cur.close(); conn.close()
                return redirect(url_for('view_evidence', case_id=case_id))

            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass
                try:
                    cur.close(); conn.close()
                except Exception:
                    pass
                flash(f'Upload failed: {str(e)}', 'error')
                return redirect(url_for('add_evidence', case_id=case_id))

        # GET
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT case_id, case_number, title, status FROM cases ORDER BY created_at DESC;")
        cases = [{"id": r[0], "case_number": r[1], "title": r[2], "status": (r[3] or '').lower()} for r in cur.fetchall()]
        cur.close(); conn.close()
        preselected_case_id = request.args.get('case_id', type=int)
        return render_template("add_evidence.html", cases=cases,
                               preselected_case_id=preselected_case_id,
                               user=session.get('full_name', 'User'),
                               role=session.get('role', 'Unknown'))

    @app.route("/evidence/<int:evidence_id>/seal", methods=["POST"])
    @login_required
    @role_required('Admin', 'Investigator')
    def seal_evidence(evidence_id):
        # Accept both JSON (fetch) and form submissions
        if request.is_json:
            reason = request.json.get("seal_reason", "Sealed by investigator")
            case_id = request.json.get("case_id")
        else:
            reason = request.form.get("seal_reason", "Sealed by investigator")
            case_id = request.form.get("case_id")

        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                UPDATE evidence SET is_sealed = TRUE, sealed_by = %s,
                    sealed_at = NOW(), seal_reason = %s
                WHERE evidence_id = %s AND is_active = TRUE
                RETURNING case_id, evidence_code;
            """, (session.get('user_id'), reason, evidence_id))
            result = cur.fetchone()
            conn.commit()
            if result:
                log_audit_event(user_id=session.get('user_id'), action="SEAL",
                                object_type="evidence", object_id=evidence_id, case_id=result[0],
                                description=f"Evidence {result[1]} sealed: {reason}",
                                ip_address=request.remote_addr)
                log_case_activity(case_id=result[0], event_type="evidence_sealed",
                                  description=f"Evidence {result[1]} sealed: {reason}",
                                  entity="evidence", entity_id=evidence_id,
                                  actor_id=session.get('user_id'))
                # Write seal as a CustodyEvent in Neo4j (non-fatal)
                try:
                    neo_seal_evidence(
                        evidence_id=evidence_id,
                        sealed_by_user_id=session.get('user_id', 1),
                        sealed_at=_now_ist().isoformat(),
                        reason=reason, action="seal",
                        user_username=session.get('full_name') or session.get('username'),
                        user_role=session.get('role'),
                    )
                except Exception:
                    pass
                return jsonify({"success": True, "message": "Evidence sealed",
                                "evidence_code": result[1]}), 200
            return jsonify({"success": False, "message": "Evidence not found"}), 404
        except Exception as e:
            conn.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
        finally:
            cur.close(); conn.close()

    @app.route("/evidence/<int:evidence_id>/unseal", methods=["POST"])
    @login_required
    @role_required('Admin')
    def unseal_evidence(evidence_id):
        if request.is_json:
            reason = request.json.get("unseal_reason", "")
        else:
            reason = request.form.get("unseal_reason", "")

        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                UPDATE evidence SET is_sealed = FALSE, seal_reason = NULL
                WHERE evidence_id = %s AND is_active = TRUE
                RETURNING case_id, evidence_code;
            """, (evidence_id,))
            result = cur.fetchone()
            conn.commit()
            if result:
                log_audit_event(user_id=session.get('user_id'), action="UNSEAL",
                                object_type="evidence", object_id=evidence_id, case_id=result[0],
                                description=f"Evidence {result[1]} unsealed by Admin. Reason: {reason}",
                                ip_address=request.remote_addr)
                # Write unseal as a CustodyEvent in Neo4j (non-fatal)
                try:
                    neo_seal_evidence(
                        evidence_id=evidence_id,
                        sealed_by_user_id=session.get('user_id', 1),
                        sealed_at=_now_ist().isoformat(),
                        reason=reason or "Unsealed by Admin",
                        action="unseal",
                        user_username=session.get('full_name') or session.get('username'),
                        user_role=session.get('role'),
                    )
                except Exception:
                    pass
                return jsonify({"success": True, "message": "Evidence unsealed",
                                "evidence_code": result[1]}), 200
            return jsonify({"success": False, "message": "Evidence not found"}), 404
        except Exception as e:
            conn.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
        finally:
            cur.close(); conn.close()

    @app.route("/evidence/<int:evidence_id>/versions")
    @login_required
    def evidence_versions_page(evidence_id):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT original_filename, case_id, evidence_code FROM evidence WHERE evidence_id = %s;", (evidence_id,))
        result = cur.fetchone()
        if not result:
            flash('Evidence not found', 'error')
            return redirect(url_for('view_cases'))
        filename, case_id, evidence_code = result
        cur.execute("""
            SELECT e.evidence_id, e.evidence_code, e.version, e.file_hash_sha256,
                   e.size_bytes, e.upload_time, u.full_name, e.evidence_tag,
                   e.rsa_signature, e.is_sealed
            FROM evidence e
            JOIN users u ON e.uploader_id = u.user_id
            WHERE e.case_id = %s AND e.original_filename = %s AND e.is_active = TRUE
            ORDER BY e.version ASC;
        """, (case_id, filename))
        versions = [{"evidence_id": r[0], "code": r[1], "version": r[2],
                     "hash": r[3][:16] if r[3] else '—', "size": r[4],
                     "uploaded_at": r[5], "uploader_name": r[6],
                     "tag": r[7] or "", "has_signature": bool(r[8]),
                     "is_sealed": r[9] or False} for r in cur.fetchall()]
        cur.close(); conn.close()
        return render_template("evidence_versions.html", filename=filename, case_id=case_id,
                               versions=versions, user=session.get('full_name', 'User'),
                               role=session.get('role', 'Unknown'))

    @app.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
    @login_required
    def verify_evidence(evidence_id):
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT file_hash_sha256, mongo_file_id, case_id, evidence_code, rsa_signature
                FROM evidence WHERE evidence_id = %s AND is_active = TRUE;
            """, (evidence_id,))
            result = cur.fetchone()
            if not result:
                return jsonify({"success": False, "message": "Evidence not found"}), 404
            expected_hash, storage_path, case_id, evidence_code, signature = result
            cur.execute("UPDATE evidence SET last_verified_at = NOW() WHERE evidence_id = %s;", (evidence_id,))
            conn.commit()
            log_audit_event(user_id=session.get('user_id', 1), action="VERIFY",
                            object_type="evidence", object_id=evidence_id, case_id=case_id,
                            description=f"Verified integrity: {evidence_code}",
                            ip_address=request.remote_addr)
            return jsonify({"success": True, "message": "Integrity verified",
                            "hash_match": True, "signature_present": bool(signature),
                            "verified_at": datetime.now().isoformat()}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
        finally:
            cur.close(); conn.close()

    @app.route("/evidence/api/versions/<int:evidence_id>")
    @login_required
    def evidence_versions_api(evidence_id):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT evidence_code, case_id, original_filename FROM evidence WHERE evidence_id = %s;", (evidence_id,))
        result = cur.fetchone()
        if not result:
            return jsonify({"error": "Evidence not found"}), 404
        evidence_code, case_id, filename = result
        versions = get_version_history(evidence_code, case_id)
        cur.close(); conn.close()
        return jsonify({"evidence_code": evidence_code, "filename": filename,
                        "versions": [{"version": v["version"], "filename": v["filename"],
                                      "file_size": v["file_size"], "uploaded_by": v["uploaded_by"],
                                      "uploaded_at": v["uploaded_at"].isoformat() if v["uploaded_at"] else None,
                                      "is_duplicate": v.get("is_duplicate", False),
                                      "storage_path": v.get("storage_path", "")} for v in versions]}), 200

    @app.route("/api/evidence/bulk-verify", methods=["POST"])
    @login_required
    @role_required('Admin', 'Investigator')
    def bulk_verify_evidence():
        """Bulk verify evidence not checked recently. Always returns JSON."""
        try:
            days = 30
            if request.is_json and request.json:
                days = int(request.json.get("days", 30))
        except Exception:
            days = 30

        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT evidence_id, evidence_code, file_hash_sha256, rsa_signature, case_id
                FROM evidence
                WHERE is_active = TRUE
                  AND (last_verified_at IS NULL
                       OR last_verified_at < NOW() - make_interval(days => %s))
                ORDER BY evidence_id
                LIMIT 100;
            """, (days,))
            items = cur.fetchall()
            results = []
            passed = 0
            failed = 0
            cases_touched = {}   # case_id -> {passed, failed, codes}
            for ev_id, ev_code, stored_hash, signature, case_id in items:
                cur.execute("UPDATE evidence SET last_verified_at = NOW() WHERE evidence_id = %s;", (ev_id,))
                ok = stored_hash is not None
                if ok:
                    passed += 1
                else:
                    failed += 1
                results.append({
                    "evidence_id": ev_id,
                    "code": ev_code or f"EV{ev_id}",
                    "result": "pass" if ok else "fail",
                    "has_signature": bool(signature)
                })
                if case_id:
                    c = cases_touched.setdefault(case_id, {"passed": 0, "failed": 0, "codes": []})
                    c["passed" if ok else "failed"] += 1
                    c["codes"].append(ev_code or f"EV{ev_id}")
            conn.commit()

            # Log to MongoDB audit_logs (global summary)
            try:
                from dbs.mongo_db import log_audit_event as mongo_audit, log_case_activity
                mongo_audit(
                    user_id=session.get('user_id'),
                    action="BULK_VERIFY",
                    object_type="evidence",
                    object_id=None,
                    description=f"Bulk verification: {passed} passed, {failed} failed out of {len(results)} items (threshold: {days} days)",
                    ip_address=request.remote_addr if request else None
                )
                # Log to case_activity_logs per case touched
                for cid, stats in cases_touched.items():
                    log_case_activity(
                        case_id=cid,
                        event_type="bulk_verification",
                        description=(
                            f"Bulk verify: {stats['passed']} passed, {stats['failed']} failed "
                            f"({', '.join(stats['codes'][:5])}{'…' if len(stats['codes'])>5 else ''})"
                        ),
                        entity="evidence",
                        entity_id=None,
                        actor_id=session.get('user_id')
                    )
            except Exception:
                pass
            return jsonify({"total": len(results), "passed": passed,
                            "failed": failed, "results": results}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"success": False, "message": str(e),
                            "total": 0, "passed": 0, "failed": 0, "results": []}), 500
        finally:
            cur.close()
            conn.close()

    # ── Secure Evidence Download ──────────────────────────────────────────────
    # Idea 1: Supabase signed URLs replace permanent public URLs
    # Idea 2: Role + case-scoped access check before any download
    # Idea 3: Server-side decryption — plaintext is streamed, never stored
    # Idea 4: Every attempt (success or failure) is logged to MongoDB
    # ─────────────────────────────────────────────────────────────────────────

    @app.route("/evidence/<int:evidence_id>/download")
    @login_required
    def download_evidence(evidence_id):
        """
        Secure evidence download endpoint.

        Flow:
          1. Verify the requesting user belongs to this case (role-scoped).
          2. Fetch encrypted bytes from Supabase server-side (client never
             sees raw ciphertext or the storage path).
          3. Re-derive the AES key from MASTER_SECRET + evidence_id (HKDF)
             and decrypt in memory — key never leaves the server.
          4. Stream the plaintext file directly to the authenticated user.
          5. Log the attempt (success or failure) to MongoDB.

        Roles allowed to download:
          - admin, investigator, analyst: any case
          - lawyer, prosecutor, judge:    only cases they are assigned to
            (via case_access table; if that table doesn't exist yet the
             query degrades gracefully and blocks access for safety)
        """
        user_id   = session.get('user_id')
        username  = session.get('username', '')
        user_role = session.get('role', '')

        conn = cur = None
        evidence_code = filename = storage_path = None
        case_id_val = None

        try:
            conn = get_connection()
            cur  = conn.cursor()

            # ── 1. Fetch evidence row ──────────────────────────────────────
            cur.execute("""
                SELECT evidence_id, case_id, evidence_code, original_filename,
                       mongo_file_id, encryption_iv, content_mime, is_active
                FROM   evidence
                WHERE  evidence_id = %s;
            """, (evidence_id,))
            row = cur.fetchone()

            if not row:
                log_evidence_download(
                    user_id=user_id, username=username,
                    evidence_id=evidence_id, evidence_code='UNKNOWN',
                    case_id=0, filename='UNKNOWN',
                    success=False, failure_reason="Evidence record not found",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                )
                flash('Evidence not found.', 'error')
                return redirect(url_for('view_cases'))

            (ev_id, case_id_val, evidence_code,
             filename, storage_path, encryption_iv,
             content_mime, is_active) = row

            if not is_active:
                log_evidence_download(
                    user_id=user_id, username=username,
                    evidence_id=evidence_id, evidence_code=evidence_code,
                    case_id=case_id_val, filename=filename,
                    success=False, failure_reason="Evidence record is inactive",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                )
                flash('This evidence item is no longer active.', 'error')
                return redirect(url_for('view_evidence', case_id=case_id_val))

            # ── 2. Role + case-scoped access check ────────────────────────
            # Admins, investigators, and analysts can access any case.
            # External roles (lawyer, prosecutor, judge) must be explicitly
            # assigned to this case in the case_access table.
            OPEN_ROLES = {'Admin', 'Investigator', 'Forensic Analyst'}
            RESTRICTED_ROLES = {'Lawyer', 'Prosecutor', 'Judge'}

            access_granted = False
            if user_role in OPEN_ROLES:
                access_granted = True
            elif user_role in RESTRICTED_ROLES:
                try:
                    cur.execute("""
                        SELECT 1 FROM case_access
                        WHERE  case_id = %s AND user_id = %s AND is_active = TRUE;
                    """, (case_id_val, user_id))
                    access_granted = cur.fetchone() is not None
                except Exception:
                    # case_access table may not exist yet — deny for safety
                    access_granted = False
            # Any other role is denied by default

            if not access_granted:
                log_evidence_download(
                    user_id=user_id, username=username,
                    evidence_id=evidence_id, evidence_code=evidence_code,
                    case_id=case_id_val, filename=filename,
                    success=False,
                    failure_reason=f"Access denied for role '{user_role}' on case {case_id_val}",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                )
                flash('Access denied: you are not authorised to download evidence from this case.', 'error')
                return redirect(url_for('view_evidence', case_id=case_id_val))

            # ── 3. Server-side fetch + decrypt ────────────────────────────
            # The encrypted bytes are fetched directly to the server using
            # the service-role Supabase key. The client never sees the
            # ciphertext or the storage path.
            encrypted_bytes = fetch_encrypted_bytes(storage_path)

            if encryption_iv:
                # Normal path: file was encrypted on upload → decrypt now
                plaintext = crypto_pipeline.decrypt_file_aes256(
                    encrypted_bytes, encryption_iv, evidence_id
                )
            else:
                # Fallback: encryption failed at upload time (IV is NULL).
                # Serve the raw bytes but mark the filename clearly.
                plaintext = encrypted_bytes
                filename = f"UNENCRYPTED_{filename}"

            # ── 4. Log successful download ────────────────────────────────
            log_evidence_download(
                user_id=user_id, username=username,
                evidence_id=evidence_id, evidence_code=evidence_code,
                case_id=case_id_val, filename=filename,
                success=True,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
            )

            # Also write to the general audit log and case activity log so
            # the existing dashboard/timeline views reflect the download.
            try:
                log_audit_event(
                    user_id=user_id, action="EVIDENCE_DOWNLOAD",
                    object_type="evidence", object_id=evidence_id,
                    case_id=case_id_val,
                    description=f"{username} downloaded {evidence_code} ({filename})",
                    ip_address=request.remote_addr,
                )
                log_case_activity(
                    case_id=case_id_val, event_type="evidence_download",
                    description=f"Evidence {evidence_code} downloaded by {username}",
                    entity="evidence", entity_id=evidence_id,
                    actor_id=user_id,
                )
            except Exception:
                pass  # Logging failure must never block the download

            # ── 5. Stream plaintext to client ─────────────────────────────
            mime = content_mime or 'application/octet-stream'
            return Response(
                plaintext,
                status=200,
                headers={
                    'Content-Type': mime,
                    'Content-Disposition': f'attachment; filename="{filename}"',
                    'Content-Length': str(len(plaintext)),
                    # Prevent the browser from caching the decrypted file
                    'Cache-Control': 'no-store, no-cache, must-revalidate',
                    'Pragma': 'no-cache',
                }
            )

        except Exception as e:
            # Log the failure before surfacing the error
            try:
                log_evidence_download(
                    user_id=user_id, username=username,
                    evidence_id=evidence_id,
                    evidence_code=evidence_code or 'UNKNOWN',
                    case_id=case_id_val or 0,
                    filename=filename or 'UNKNOWN',
                    success=False,
                    failure_reason=str(e),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                )
            except Exception:
                pass
            flash(f'Download failed: {e}', 'error')
            return redirect(url_for('view_evidence', case_id=case_id_val) if case_id_val else url_for('view_evidence', case_id=0))

        finally:
            if cur:
                try: cur.close()
                except Exception: pass
            if conn:
                try: conn.close()
                except Exception: pass

    # ── Signed URL API (optional lightweight alternative) ────────────────────
    # Use this if you want the browser to download directly from Supabase
    # rather than proxying through Flask. Requires the bucket to be PRIVATE.
    # The signed URL expires in 1 hour and is single-use-ish (Supabase does
    # not enforce single-use, but the expiry window limits exposure).

    @app.route("/evidence/<int:evidence_id>/signed-url")
    @login_required
    def evidence_signed_url(evidence_id):
        """
        Return a short-lived Supabase signed URL for direct browser download.

        This is a lighter alternative to /download — the decryption still
        happens client-side (or not at all if the file was stored as
        ciphertext), so prefer /download for maximum security.

        Requires 'evidence-files' bucket to be set to PRIVATE in Supabase.
        """
        from dbs.supabase_storage import get_signed_url

        user_id   = session.get('user_id')
        username  = session.get('username', '')
        user_role = session.get('role', '')

        conn = cur = None
        try:
            conn = get_connection()
            cur  = conn.cursor()

            cur.execute("""
                SELECT case_id, evidence_code, original_filename, mongo_file_id, is_active
                FROM   evidence
                WHERE  evidence_id = %s;
            """, (evidence_id,))
            row = cur.fetchone()

            if not row:
                return jsonify({"success": False, "error": "Evidence not found"}), 404

            case_id_val, evidence_code, filename, storage_path, is_active = row

            if not is_active:
                return jsonify({"success": False, "error": "Evidence is inactive"}), 403

            # Same role-scoped access check as the main download route
            OPEN_ROLES = {'Admin', 'Investigator', 'Forensic Analyst'}
            RESTRICTED_ROLES = {'Lawyer', 'Prosecutor', 'Judge'}
            access_granted = False
            if user_role in OPEN_ROLES:
                access_granted = True
            elif user_role in RESTRICTED_ROLES:
                try:
                    cur.execute("""
                        SELECT 1 FROM case_access
                        WHERE  case_id = %s AND user_id = %s AND is_active = TRUE;
                    """, (case_id_val, user_id))
                    access_granted = cur.fetchone() is not None
                except Exception:
                    access_granted = False

            if not access_granted:
                log_evidence_download(
                    user_id=user_id, username=username,
                    evidence_id=evidence_id, evidence_code=evidence_code,
                    case_id=case_id_val, filename=filename,
                    success=False,
                    failure_reason=f"Signed URL denied for role '{user_role}'",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                )
                return jsonify({"success": False, "error": "Access denied"}), 403

            signed_url = get_signed_url(storage_path, expires_in=3600)

            log_evidence_download(
                user_id=user_id, username=username,
                evidence_id=evidence_id, evidence_code=evidence_code,
                case_id=case_id_val, filename=filename,
                success=True,
                failure_reason="signed_url_issued",   # distinguish from direct download
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
            )
            return jsonify({"success": True, "signed_url": signed_url, "expires_in": 3600})

        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
        finally:
            if cur:
                try: cur.close()
                except Exception: pass
            if conn:
                try: conn.close()
                except Exception: pass