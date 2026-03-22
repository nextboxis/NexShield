"""
app.py — Flask API for the AI-Powered Threat Intelligence Platform
"""

from flask import Flask, jsonify, render_template, request, Response  # type: ignore
from datetime import datetime, timezone, timedelta
from bson import json_util  # type: ignore
import json
import csv
import io

from config import threats, network_scans, activity_log, check_connection  # type: ignore

app = Flask(__name__)


# ═════════════════════════════════════════════════════════════════════
#  Utility
# ═════════════════════════════════════════════════════════════════════

def _serialize(doc):
    """Convert a MongoDB doc to JSON-safe dict."""
    return json.loads(json_util.dumps(doc))


def _cors(response):
    """Add CORS headers for local dev."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


def _log_activity(event_type, message, severity="info"):
    """Log an event to the activity_log collection."""
    try:
        if check_connection():
            activity_log.insert_one({
                "type": event_type,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc),
            })
    except Exception:
        pass  # Don't let logging failures crash the app


app.after_request(_cors)


# ═════════════════════════════════════════════════════════════════════
#  Frontend
# ═════════════════════════════════════════════════════════════════════

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

    limit = request.args.get("limit", 10, type=int)
    limit = min(limit, 100)  # Cap at 100

    docs = list(
        threats.find()
        .sort("detected_at", -1)
        .limit(limit)
    )
    return jsonify({"status": "complete", "threats": _serialize(docs)})


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

    days = request.args.get("days", 7, type=int)
    days = min(days, 30)
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

    try:
        from scanner import run_scan, DEFAULT_TARGET, DEFAULT_PORTS  # type: ignore

        body = request.get_json(silent=True) or {}
        target = body.get("target", DEFAULT_TARGET)
        ports = body.get("ports", DEFAULT_PORTS)

        _log_activity("scan_start", f"Scan initiated on {target} (ports: {ports})")
        results = run_scan(target, ports)
        _log_activity("scan_complete", f"Scan complete: {len(results)} host(s) found on {target}", "success")

        return jsonify({
            "status": "complete",
            "hosts_found": len(results),
            "target": target,
        })
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

    try:
        from ai_logic import analyze_scan_results, merge_duplicates, compute_risk_scores  # type: ignore

        _log_activity("analysis_start", "AI multi-model analysis initiated (7 engines)")
        created = analyze_scan_results()
        scores = compute_risk_scores()
        removed = merge_duplicates()

        # Build a summary of engines used
        engines_used = [
            "PortRisk-v2", "VersionVuln-v2", "ServiceFP-v1",
            "DefaultCreds-v1", "MitreMap-v1", "RiskScore-v1", "DedupMerge-v2"
        ]

        _log_activity("analysis_complete",
                       f"Pipeline done: {created} threats, {len(scores)} hosts scored, {removed} deduped",
                       "success")

        return jsonify({
            "status": "complete",
            "threats_created": created,
            "duplicates_removed": removed,
            "hosts_scored": len(scores),
            "risk_scores": scores,
            "engines_used": engines_used,
        })
    except Exception as e:
        _log_activity("analysis_error", f"Analysis failed: {str(e)}", "error")
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
    """Export all threats as CSV or JSON."""
    if not check_connection():
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    fmt = request.args.get("format", "json").lower()
    docs = list(threats.find().sort("detected_at", -1).limit(500))

    _log_activity("export", f"Threat data exported as {fmt.upper()} ({len(docs)} records)")

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Severity", "Name", "Host", "CVE_ID", "Source", "Detail", "Detected_At"])
        for doc in docs:
            writer.writerow([
                doc.get("severity", ""),
                doc.get("name", ""),
                doc.get("host", ""),
                doc.get("cve_id", ""),
                doc.get("source", ""),
                doc.get("detail", ""),
                str(doc.get("detected_at", "")),
            ])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=nexshield_threats.csv"},
        )

    # Default: JSON
    return Response(
        json_util.dumps(docs, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=nexshield_threats.json"},
    )


# ═════════════════════════════════════════════════════════════════════
#  API — CVE Lookup
# ═════════════════════════════════════════════════════════════════════

@app.route("/api/cve/<cve_id>", methods=["GET"])
def cve_detail(cve_id):
    """Look up a CVE from the NVD database."""
    try:
        from cve_lookup import lookup_cve  # type: ignore
        result = lookup_cve(cve_id)
        if "error" in result:
            return jsonify({"status": "error", "message": result["error"]}), 404
        return jsonify({"status": "complete", **result})
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
#  Run
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 58)
    print("   NexShield — AI-Powered Threat Intelligence Platform")
    print("   Dashboard -> http://127.0.0.1:5000")
    print("=" * 58)
    _log_activity("system", "NexShield platform started")
    app.run(debug=True, host="0.0.0.0", port=5000)
