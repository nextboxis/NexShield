import os
import io
import csv
import json
import uuid
import re
import secrets
import threading
import requests # type: ignore
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response # type: ignore
from flask_pymongo import PyMongo # type: ignore
from flask_cors import CORS # type: ignore
from flask_socketio import SocketIO, emit # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from functools import wraps
from bson import ObjectId, json_util # type: ignore
from datetime import datetime, timezone, timedelta, date

# Internal Logic Modules
from ai_logic import compute_risk_scores # type: ignore
from config import threats, network_scans, activity_log, users, cve_cache, check_connection # type: ignore

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
ALLOWED_EXPORT_FORMATS = {"csv", "json"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TARGET_RE = re.compile(r"^[A-Za-z0-9.,:/\-\s]+$")
PORTS_RE = re.compile(r"^[0-9,\-\s]*$")


# ═════════════════════════════════════════════════════════════════════
#  Utility & Logging
# ═════════════════════════════════════════════════════════════════════

def _serialize(doc):
    """
    Standardizes MongoDB document serialization.
    Handles BSON types (ObjectId, datetime) for JSON-safe API delivery.
    """
    return json.loads(json_util.dumps(doc))


def _log_activity(event_type, message, severity="info"):
    """
    Centralized logging utility for the NexShield Activity Log.
    Ensures systemic events are persisted for the "Mission Control" console.
    """
    try:
        if check_connection():
            activity_log.insert_one({
                "type": event_type,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc),
            })
    except Exception as e:
        print(f"[!] Activity logging failed: {e}")


def _normalize_limit(value: int | None, default: int, maximum: int) -> int:
    if value is None:
        return default
    return max(1, min(value, maximum))


def _validate_username(username):
    candidate = (username or "").strip()
    if not USERNAME_RE.fullmatch(candidate):
        raise ValueError("Username must be 3-32 characters and use only letters, numbers, ., _, or -.")
    return candidate


def _validate_scan_inputs(target: str | None, ports: str | None, default_ports: str = "") -> tuple[str, str]:
    clean_target = (target or "").strip()
    clean_ports = (ports or "").strip()

    if not clean_target:
        raise ValueError("A scan target is required.")
    if len(clean_target) > 120 or not TARGET_RE.fullmatch(clean_target):
        raise ValueError("Scan target contains unsupported characters.")

    if not clean_ports:
        clean_ports = default_ports.strip()

    if clean_ports:
        if len(clean_ports) > 120 or not PORTS_RE.fullmatch(clean_ports):
            raise ValueError("Port list must contain only digits, commas, spaces, or hyphens.")

        for part in [segment.strip() for segment in clean_ports.split(",") if segment.strip()]:
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                if not start_str.isdigit() or not end_str.isdigit():
                    raise ValueError("Port ranges must be numeric.")
                start_port = int(start_str)
                end_port = int(end_str)
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError("Port ranges must stay within 1-65535.")
            else:
                if not part.isdigit():
                    raise ValueError("Port values must be numeric.")
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError("Port values must stay within 1-65535.")

    return clean_target, clean_ports


def _validate_cve_id(cve_id):
    candidate = (cve_id or "").strip().upper()
    if not CVE_RE.fullmatch(candidate):
        raise ValueError("Invalid CVE identifier. Use the format CVE-YYYY-NNNN.")
    return candidate


def _start_background_task(target, *args):
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# No global CORS needed if running on same origin/proxy


# ═════════════════════════════════════════════════════════════════════
#  Security / Authentication
# ═════════════════════════════════════════════════════════════════════

# Generate a secure random token for this server session
WS_TOKEN = os.environ.get("WS_TOKEN", secrets.token_hex(16))

@app.route("/api/auth/token", methods=["GET"])
def get_ws_token():
    """
    Returns the WebSocket authorization token.
    (Note: Once a login system is added, protect this route with @login_required)
    """
    return jsonify({"status": "complete", "token": WS_TOKEN})

@socketio.on("connect")
def handle_connect(auth):
    """Secure the WebSocket connection by validating the auth token."""
    if not auth or auth.get("token") != WS_TOKEN:
        _log_activity("security", f"Blocked unauthorized WebSocket connection (IP: {request.remote_addr})", "high")
        raise ConnectionRefusedError("Unauthorized: Invalid or missing token")
    # Connection accepted



# ═════════════════════════════════════════════════════════════════════
#  Frontend
# ═════════════════════════════════════════════════════════════════════




# ═════════════════════════════════════════════════════════════════════
#  API — Seed Data (Bootstrap AI)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/seed-data", methods=["POST"])
def seed_data():
    """Synthetic seed data is disabled; only live scan data is accepted."""
    return jsonify({
        "status": "error",
        "message": "Synthetic seed data has been disabled. Use a real-time scan target instead.",
    }), 410


@app.route("/api/reset-data", methods=["POST"])
def reset_data():
    """Clear operational data while preserving user accounts."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database offline."}), 503

    body = request.get_json(silent=True) or {}
    include_cache = bool(body.get("include_cache", False))

    deleted = {
        "threats": threats.delete_many({}).deleted_count,
        "network_scans": network_scans.delete_many({}).deleted_count,
        "activity_log": activity_log.delete_many({}).deleted_count,
        "cve_cache": 0,
    }

    if include_cache:
        deleted["cve_cache"] = cve_cache.delete_many({}).deleted_count  # type: ignore

    cleared_total = sum(deleted.values())
    cache_note = " including CVE cache" if include_cache else ""
    message = f"Reset complete. Removed {cleared_total} old records{cache_note}."

    _log_activity("system", f"Operational data reset by '{"anonymous_admin"}'", "high")
    socketio.emit("data_reset", {"status": "success", "message": message, "deleted": deleted})

    return jsonify({
        "status": "complete",
        "message": message,
        "deleted": deleted,
    })

@app.route("/")
def index():
    return render_template("index.html")


# ═════════════════════════════════════════════════════════════════════
#  API — Threats
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/threats", methods=["GET"])
def get_threats():
    """Return the latest 10 threats, sorted by detection time (descending)."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable", "threats": []}), 503

    limit = _normalize_limit(request.args.get("limit", 10, type=int), 10, 100)

    docs = list(
        threats.find()
        .sort("detected_at", -1)
        .limit(limit)
    )
    return jsonify({"status": "complete", "threats": _serialize(docs)})


# ═════════════════════════════════════════════════════════════════════
#  API — Active Response (Zero-Trust)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/quarantine", methods=["POST"])
def quarantine_host():
    """Simulate a network-level quarantine and remediate threats."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    body = request.get_json(silent=True) or {}
    host = (body.get("host") or "").strip()

    if not host:
        return jsonify({"status": "error", "message": "Host IP is required."}), 400

    # Quarantine logic: Update all active threats for this host
    result = threats.update_many(
        {"host": host, "severity": {"$ne": "low"}},
        {"$set": {
            "severity": "low",
            "detail": "[QUARANTINED] Network access restricted. "
        }}
    )

    if result.modified_count > 0:
        _log_activity("security", f"Host {host} quarantined by {"anonymous_admin"}", "critical")
        
        # Trigger risk score recalculation
        try:
            from ai_logic import compute_risk_scores # type: ignore
            compute_risk_scores()
        except BaseException as e:
            print(f"[!] Warning: Risk recalculation failed post-quarantine: {e}")

        # Broadcast update
        socketio.emit("quarantine_complete", {
            "status": "success",
            "message": f"Host {host} successfully isolated.",
            "host": host
        })

        return jsonify({
            "status": "complete",
            "message": f"Isolated {host} and neutralized {result.modified_count} threats."
        })
    else:
        return jsonify({
            "status": "info",
            "message": f"Host {host} has no active threats to quarantine."
        })

# ═════════════════════════════════════════════════════════════════════
#  API — Target Node Profiling
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/host/<path:ip>", methods=["GET"])
def get_host_profile(ip):
    """Retrieve deep scan results (footprint) for a particular IP."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    ip = ip.strip()
    
    # Retrieve the latest scan footprint for this host
    scan_doc = network_scans.find_one(
        {"host": ip},
        sort=[("scanned_at", -1)]
    )
    
    return jsonify({
        "status": "complete",
        "host": ip,
        "footprint": _serialize(scan_doc) if scan_doc else None
    })

@app.route("/api/export-scan", methods=["GET"])
def export_scan():
    """Export the raw JSON scan footprint for a particular IP."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    ip = (request.args.get("host") or "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "Target IP required."}), 400

    scan_doc = network_scans.find_one(
        {"host": ip},
        sort=[("scanned_at", -1)]
    )

    if not scan_doc:
        return jsonify({"status": "error", "message": "No scan records found for this host."}), 404

    safe_doc = _serialize(scan_doc)
    json_data = json.dumps(safe_doc, indent=2)

    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=scan_footprint_{ip.replace('.','_')}.json"}
    )

# ═════════════════════════════════════════════════════════════════════
#  API — Stats
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return aggregate counts: total threats, scans, severity breakdown."""
    if not check_connection():
        return jsonify({
            "status": "error",
            "message": "Database unavailable",
            "db_online": False,
            "total_threats": 0, "total_scans": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        }), 503

    total_threats = threats.count_documents({})
    total_scans = network_scans.count_documents({})
    critical = threats.count_documents({"severity": "critical"})
    high = threats.count_documents({"severity": "high"})
    medium = threats.count_documents({"severity": "medium"})
    low = threats.count_documents({"severity": "low"})

    return jsonify({
        "status": "complete",
        "db_online": True,
        "total_threats": total_threats,
        "total_scans": total_scans,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    })


# ═════════════════════════════════════════════════════════════════════
#  API — Severity Timeline (last 7 days)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/timeline", methods=["GET"])
def get_timeline():
    """Return threat counts per day per severity for the last 7 days."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    days = _normalize_limit(request.args.get("days", 7, type=int), 7, 30)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    pipeline = [
        {"$match": {"detected_at": {"$gte": cutoff}}},
        {"$group": {
            "_id": {
                "day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$detected_at"}},
                "severity": "$severity",
            },
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.day": 1}},
    ]

    results = list(threats.aggregate(pipeline))

    # Build a structured response: { "2026-03-15": { "critical": 2, "high": 5, ... }, ... }
    timeline = {}
    for r in results:
        day = r["_id"]["day"]
        sev = r["_id"]["severity"]
        if day not in timeline:
            timeline[day] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        if sev in timeline[day]:
            timeline[day][sev] = r["count"]

    # Fill in missing days with zeros
    all_days = []
    for i in range(days):
        d = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        all_days.append(d)
        if d not in timeline:
            timeline[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    return jsonify({
        "status": "complete",
        "days": all_days,
        "timeline": timeline,
    })


# ═════════════════════════════════════════════════════════════════════
#  API — Scan trigger
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    """Trigger a network scan. Accepts optional JSON body {target, ports}."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database is offline. Please start MongoDB."}), 503

    def background_scan(tgt, prts):
        try:
            _log_activity("scan_start", f"Scan initiated on {tgt} (ports: {prts})")
            results = run_scan(tgt, prts)
            msg = f"Scan complete: {len(results)} host(s) found on {tgt}"
            _log_activity("scan_complete", msg, "success")
            socketio.emit("scan_complete", {"status": "success", "message": msg})
        except Exception as err:
            msg = f"Scan failed: {str(err)}"
            _log_activity("scan_error", msg, "error")
            socketio.emit("scan_complete", {"status": "error", "message": msg})

    try:
        from scanner import run_scan, DEFAULT_PORTS  # type: ignore

        body = request.get_json(silent=True) or {}
        target, ports = _validate_scan_inputs(
            body.get("target"),
            body.get("ports"),
            DEFAULT_PORTS,
        )

        # Run scan in the background to prevent HTTP timeout
        _start_background_task(background_scan, target, ports)

        return jsonify({
            "status": "accepted",
            "message": "Scan started in the background. Check activity logs for completion.",
            "target": target,
        }), 202
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as e:
        _log_activity("scan_error", f"Scan failed: {str(e)}", "error")
        return jsonify({"status": "error", "message": str(e)}), 500


# ═════════════════════════════════════════════════════════════════════
#  API — Analyze & Deduplicate
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/analyze", methods=["POST"])
def trigger_analysis():
    """Run AI analysis on scan data and merge duplicates."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database is offline. Please start MongoDB."}), 503

    def background_analyze():
        try:
            from ai_logic import analyze_scan_results, merge_duplicates, compute_risk_scores  # type: ignore
            _log_activity("analysis_start", "AI multi-model analysis initiated (9 engines) in background")
            
            created = analyze_scan_results()
            scores = compute_risk_scores()
            removed = merge_duplicates()

            msg = f"Pipeline done: {created} threats, {len(scores)} hosts scored, {removed} deduped"
            _log_activity("analysis_complete", msg, "success")
            socketio.emit("analysis_complete", {"status": "success", "message": msg})
            socketio.emit("stats_update", {"total_threats": created})
            if created > 0:
                socketio.emit("threat_update", {"count": created})
        except Exception as e:
            msg = f"Analysis failed: {str(e)}"
            _log_activity("analysis_error", msg, "error")
            socketio.emit("analysis_complete", {"status": "error", "message": msg})

    try:
        _start_background_task(background_analyze)

        return jsonify({
            "status": "accepted",
            "message": "AI analysis started in the background. Check activity logs for completion."
        }), 202
    except Exception as e:
        _log_activity("analysis_error", f"Failed to start analysis thread: {str(e)}", "error")
        return jsonify({"status": "error", "message": str(e)}), 500


# ═════════════════════════════════════════════════════════════════════
#  API — Train ML Model
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/train", methods=["POST"])
def trigger_training():
    """Trigger AI Machine Learning model training."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database is offline. Please start MongoDB."}), 503

    def background_train():
        try:
            from ai_logic import train_ml_model  # type: ignore
            _log_activity("analysis_start", "ML model training initiated in background")
            success = train_ml_model()

            if success:
                _log_activity("analysis_complete", "ML model successfully trained on historical data", "success")
                socketio.emit("training_complete", {"status": "success", "message": "AI model trained successfully!"})
            else:
                _log_activity("analysis_error", "ML model training aborted (insufficient data or missing libs)", "error")
                socketio.emit("training_complete", {"status": "error", "message": "Training aborted: Ensure at least 20 threats exist."})
        except Exception as e:
            _log_activity("analysis_error", f"ML training failed: {str(e)}", "error")
            socketio.emit("training_complete", {"status": "error", "message": f"ML training failed: {str(e)}"})

    try:
        # Run training in the background to prevent HTTP timeout
        _start_background_task(background_train)

        return jsonify({
            "status": "accepted",
            "message": "AI model training started in the background. Check activity logs for completion."
        }), 202
    except Exception as e:
        _log_activity("analysis_error", f"Failed to start ML training thread: {str(e)}", "error")
        return jsonify({"status": "error", "message": str(e)}), 500


# ═════════════════════════════════════════════════════════════════════
#  API — Scan History
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/scan-history", methods=["GET"])
def get_scan_history():
    """Return the last 20 scans grouped by scan_id."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    pipeline = [
        {"$group": {
            "_id": "$scan_id",
            "target": {"$first": "$target"},
            "host_count": {"$sum": 1},
            "scanned_at": {"$max": "$scanned_at"},
        }},
        {"$sort": {"scanned_at": -1}},
        {"$limit": 20},
    ]

    results = list(network_scans.aggregate(pipeline))
    return jsonify({"status": "complete", "scans": _serialize(results)})


# ═════════════════════════════════════════════════════════════════════
#  API — Export (CSV / JSON)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/export", methods=["GET"])
def export_threats():
    """Export threats as CSV or JSON, with optional filtering by host/severity."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    fmt = request.args.get("format", "json").lower()
    host = (request.args.get("host") or "").strip()
    severity = (request.args.get("severity") or "").strip().lower()

    if fmt not in ALLOWED_EXPORT_FORMATS:
        return jsonify({"status": "error", "message": "Export format must be csv or json."}), 400
    if severity and severity not in ALLOWED_SEVERITIES:
        return jsonify({"status": "error", "message": "Invalid severity filter."}), 400

    # Build Filter Query
    query = {}
    if host:
        query["host"] = host
    if severity:
        query["severity"] = severity.lower()

    docs = list(threats.find(query).sort("detected_at", -1).limit(1000))
    
    # Activity logging
    log_msg = f"Threat data exported as {fmt.upper()} ({len(docs)} records)"
    if host: log_msg += f" for host {host}"
    _log_activity("export", log_msg)

    # Filename construction
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    base_name = f"nexshield_report_{timestamp}"
    if host:
        base_name = f"nexshield_report_{host.replace('.', '_')}_{timestamp}"
    filename = f"{base_name}.{fmt}"

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Severity", "Name", "Host", "CVE_ID", "Source", "Detail", "Detected_At"])
        for doc in docs:
            writer.writerow([
                doc.get("severity", "").upper(),
                doc.get("name", ""),
                doc.get("host", ""),
                doc.get("cve_id", ""),
                doc.get("source", ""),
                doc.get("detail", ""),
                doc.get("detected_at", "").strftime("%Y-%m-%d %H:%M:%S") if isinstance(doc.get("detected_at"), datetime) else str(doc.get("detected_at", "")),
            ])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # Default: JSON
    return Response(
        json_util.dumps(docs, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═════════════════════════════════════════════════════════════════════
#  API — CVE Lookup
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/cve/<cve_id>", methods=["GET"])
def cve_detail(cve_id):
    """Look up a CVE from the NVD database."""
    try:
        cve_id = _validate_cve_id(cve_id)
        from cve_lookup import lookup_cve  # type: ignore
        result = lookup_cve(cve_id)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 404
        return jsonify({"status": "complete", **result})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



# ═════════════════════════════════════════════════════════════════════
#  API — Activity Log
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/activity", methods=["GET"])
def get_activity():
    """Return the last 50 activity log entries."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    docs = list(
        activity_log.find()
        .sort("timestamp", -1)
        .limit(50)
    )
    return jsonify({"status": "complete", "events": _serialize(docs)})


# ═════════════════════════════════════════════════════════════════════
#  API — Host Risk Scores
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/risk-scores", methods=["GET"])
def get_risk_scores():
    """
    Returns composite risk scores per host.
    Logic delegated to ai_logic for consistency across the analysis pipeline.
    """
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    scores = compute_risk_scores(persist=False) # Don't re-tag every GET
    
    # Format for frontend grid
    formatted = []
    for host, data in scores.items():
        formatted.append({
            "host": host,
            "score": data["score"],
            "risk_level": data["risk_level"],
            "threat_count": data["threat_count"],
            "engines_flagged": data["engines_flagged"]
        })

    return jsonify({"status": "complete", "scores": formatted})


# ═════════════════════════════════════════════════════════════════════
#  API — Threat Trends (Severity Distribution + Type Breakdown)
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/threat-trends", methods=["GET"])
def get_threat_trends():
    """Return severity distribution and threat source breakdown."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    # Severity distribution
    sev_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    sev_results = list(threats.aggregate(sev_pipeline))
    severity_dist = {r["_id"]: r["count"] for r in sev_results if r["_id"]}

    # Source engine breakdown
    src_pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    src_results = list(threats.aggregate(src_pipeline))
    source_dist = {r["_id"]: r["count"] for r in src_results if r["_id"]}

    # Tag frequency
    tag_pipeline = [
        {"$unwind": "$tags"},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 15},
    ]
    try:
        tag_results = list(threats.aggregate(tag_pipeline))
        tags = {r["_id"]: r["count"] for r in tag_results if r["_id"]}
    except Exception:
        tags = {}

    return jsonify({
        "status": "complete",
        "severity_distribution": severity_dist,
        "source_distribution": source_dist,
        "tag_frequency": tags,
    })


# ═════════════════════════════════════════════════════════════════════
#  Run
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 58)
    print("   NexShield — AI-Powered Threat Intelligence Platform")
    print("   Dashboard -> http://127.0.0.1:5000")
    print("=" * 58)
    _log_activity("system", "NexShield platform started")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
