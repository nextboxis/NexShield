"""
webhook_notifier.py — Outbound SOC Webhook Alert Engine for NexShield

Supports:
  1. Slack Webhooks
  2. Discord Webhooks
  3. Microsoft Teams Webhooks
  4. Generic JSON Webhooks (SIEM / Splunk / Elastic)
"""

import json
import logging
import os
import requests
from typing import Any, Optional

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
GENERIC_WEBHOOK_URL = os.environ.get("GENERIC_WEBHOOK_URL", "").strip()


def dispatch_webhook_alert(threat_data: dict[str, Any]) -> dict[str, Any]:
    """
    Dispatch threat alert notifications to configured Slack, Discord, Teams, or Generic webhooks.
    """
    severity = str(threat_data.get("severity", "low")).lower()
    name = threat_data.get("name", "Unknown Threat")
    host = threat_data.get("host", "Unknown Host")
    cve_id = threat_data.get("cve_id", "N/A")
    detail = threat_data.get("detail", "N/A")
    results = {"slack": False, "discord": False, "teams": False, "generic": False}

    # 1. Slack Webhook Dispatch
    if SLACK_WEBHOOK_URL:
        results["slack"] = _send_slack(SLACK_WEBHOOK_URL, name, severity, host, cve_id, detail)

    # 2. Discord Webhook Dispatch
    if DISCORD_WEBHOOK_URL:
        results["discord"] = _send_discord(DISCORD_WEBHOOK_URL, name, severity, host, cve_id, detail)

    # 3. Teams Webhook Dispatch
    if TEAMS_WEBHOOK_URL:
        results["teams"] = _send_teams(TEAMS_WEBHOOK_URL, name, severity, host, cve_id, detail)

    # 4. Generic JSON Webhook Dispatch
    if GENERIC_WEBHOOK_URL:
        results["generic"] = _send_generic(GENERIC_WEBHOOK_URL, threat_data)

    return results


def _send_slack(url: str, name: str, severity: str, host: str, cve_id: str, detail: str) -> bool:
    payload = {
        "text": f" *NexShield Security Alert: {severity.upper()}*",
        "attachments": [{
            "color": "#f87171" if severity in ("critical", "high") else "#fbbf24",
            "fields": [
                {"title": "Threat Name", "value": name, "short": True},
                {"title": "Host Node", "value": f"`{host}`", "short": True},
                {"title": "CVE ID", "value": f"`{cve_id}`", "short": True},
                {"title": "Details", "value": detail, "short": False},
            ]
        }]
    }
    return _post_json(url, payload)


def _send_discord(url: str, name: str, severity: str, host: str, cve_id: str, detail: str) -> bool:
    payload = {
        "username": "NexShield Mission Control",
        "embeds": [{
            "title": f" Threat Detected: {name}",
            "color": 16281969 if severity in ("critical", "high") else 16498468,
            "fields": [
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {"name": "Host", "value": f"`{host}`", "inline": True},
                {"name": "CVE ID", "value": f"`{cve_id}`", "inline": True},
                {"name": "Detail", "value": detail, "inline": False},
            ]
        }]
    }
    return _post_json(url, payload)


def _send_teams(url: str, name: str, severity: str, host: str, cve_id: str, detail: str) -> bool:
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "F87171" if severity in ("critical", "high") else "FBBF24",
        "summary": f"NexShield Threat Alert: {name}",
        "sections": [{
            "activityTitle": f" NexShield Alert: {name}",
            "activitySubtitle": f"Severity: {severity.upper()} | Target: {host}",
            "facts": [
                {"name": "CVE ID", "value": cve_id},
                {"name": "Details", "value": detail},
            ],
            "markdown": True
        }]
    }
    return _post_json(url, payload)


def _send_generic(url: str, threat_data: dict) -> bool:
    return _post_json(url, threat_data)


def _post_json(url: str, data: dict) -> bool:
    try:
        resp = requests.post(url, json=data, timeout=5)
        return resp.status_code in (200, 201, 202, 204)
    except Exception as exc:
        logger.debug("Webhook post failed for %s: %s", url, exc)
        return False
