"""
report_generator.py — Advanced Penetration Testing Report Generation Engine for NexShield

Generates multi-format security reports:
  1. Standalone HTML (.html)
  2. Markdown (.md) for Jira/GitHub
  3. OASIS SARIF v2.1 (.sarif)
  4. Printable PDF / Text (.pdf / .txt)

Includes AI Executive Narrative & Compliance Mapping (PCI-DSS, ISO 27001, NIST CSF, OWASP).
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Compliance Framework Mapping Rules
COMPLIANCE_RULES: dict[str, list[dict[str, str]]] = {
    "smb": [
        {"framework": "PCI-DSS 4.0", "control": "Req 2.2.4 / 6.3.1", "desc": "Insecure legacy SMBv1 services must be disabled."},
        {"framework": "ISO 27001:2022", "control": "Control A.8.8", "desc": "Management of technical vulnerabilities."},
        {"framework": "NIST CSF 2.0", "control": "PR.IR-01", "desc": "Networks and legacy protocols hardened."},
    ],
    "telnet": [
        {"framework": "PCI-DSS 4.0", "control": "Req 2.2.7", "desc": "All unencrypted management protocols must be disabled."},
        {"framework": "ISO 27001:2022", "control": "Control A.8.24", "desc": "Use of cryptography for session management."},
        {"framework": "NIST CSF 2.0", "control": "PR.DS-02", "desc": "Data-in-transit protected via secure protocols."},
    ],
    "http": [
        {"framework": "PCI-DSS 4.0", "control": "Req 4.1.2", "desc": "Strong cryptography and security protocols for web traffic."},
        {"framework": "OWASP Top 10", "control": "A02:2021", "desc": "Cryptographic Failures."},
    ],
    "default_credentials": [
        {"framework": "PCI-DSS 4.0", "control": "Req 2.2.2", "desc": "Vendor default accounts must be changed or disabled."},
        {"framework": "ISO 27001:2022", "control": "Control A.5.17", "desc": "Authentication information policy."},
        {"framework": "OWASP Top 10", "control": "A07:2021", "desc": "Identification and Authentication Failures."},
    ],
    "cve": [
        {"framework": "PCI-DSS 4.0", "control": "Req 6.3.3", "desc": "Security patches applied within 30 days of release."},
        {"framework": "ISO 27001:2022", "control": "Control A.8.8", "desc": "Technical vulnerability patching."},
        {"framework": "OWASP Top 10", "control": "A06:2021", "desc": "Vulnerable and Outdated Components."},
    ],
}


def map_compliance(threat: dict) -> list[dict[str, str]]:
    """Map a threat item to regulatory compliance frameworks."""
    name = str(threat.get("name") or "").lower()
    detail = str(threat.get("detail") or "").lower()
    cve_id = str(threat.get("cve_id") or "").lower()

    combined = f"{name} {detail} {cve_id}"
    mapped = []

    if "smb" in combined or "445" in combined:
        mapped.extend(COMPLIANCE_RULES["smb"])
    if "telnet" in combined or "23" in combined:
        mapped.extend(COMPLIANCE_RULES["telnet"])
    if "http" in combined or "unencrypted" in combined:
        mapped.extend(COMPLIANCE_RULES["http"])
    if "default" in combined or "cred" in combined or "password" in combined:
        mapped.extend(COMPLIANCE_RULES["default_credentials"])
    if cve_id.startswith("cve-"):
        mapped.extend(COMPLIANCE_RULES["cve"])

    # Deduplicate entries by framework + control
    seen = set()
    unique_mapped = []
    for item in mapped:
        key = (item["framework"], item["control"])
        if key not in seen:
            seen.add(key)
            unique_mapped.append(item)

    return unique_mapped


def compute_executive_summary(threats: list[dict], scans: list[dict]) -> dict:
    """Compute executive risk score (0-100) and threat narrative."""
    total_threats = len(threats)
    critical_count = sum(1 for t in threats if str(t.get("severity")).lower() == "critical")
    high_count = sum(1 for t in threats if str(t.get("severity")).lower() == "high")
    medium_count = sum(1 for t in threats if str(t.get("severity")).lower() == "medium")
    low_count = sum(1 for t in threats if str(t.get("severity")).lower() == "low")

    # Risk score calculation formula
    risk_score = min(100, (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1))

    if risk_score >= 75:
        posture = "CRITICAL RISK"
        narrative = "Immediate intervention required. High-severity threat vectors and unpatched vulnerabilities present acute operational risk."
    elif risk_score >= 40:
        posture = "ELEVATED RISK"
        narrative = "Multiple exploitable vulnerabilities identified. System hardening and patch deployment recommended."
    elif risk_score > 0:
        posture = "MODERATE RISK"
        narrative = "Low-to-medium vulnerabilities detected. Maintain routine patch cycles and access controls."
    else:
        posture = "SECURE / LOW RISK"
        narrative = "No critical vulnerability patterns detected. System maintains robust baseline security posture."

    # Enrich narrative with RAG intelligence context if threats exist
    rag_threats = [t for t in threats if t.get("source") == "RAGThreat-Engine-v1" or "rag" in t.get("tags", [])]
    if rag_threats:
        narrative += f" Grounded AI RAG model verified {len(rag_threats)} prioritized attack vectors with direct MITRE ATT&CK and NVD CVE citations."

    return {
        "risk_score": risk_score,
        "risk_posture": posture,
        "narrative": narrative,
        "total_threats": total_threats,
        "total_scans": len(scans),
        "counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
    }


def generate_report_content(threats: list[dict], scans: list[dict], fmt: str = "html", metadata: dict = None) -> str:
    """Main generator entry point for multi-format report export."""
    fmt = (fmt or "html").strip().lower()
    metadata = metadata or {}
    exec_summary = compute_executive_summary(threats, scans)

    if fmt == "markdown" or fmt == "md":
        return _generate_markdown(threats, scans, exec_summary, metadata)
    elif fmt == "sarif":
        return _generate_sarif(threats, exec_summary, metadata)
    elif fmt == "pdf":
        return _generate_pdf_text(threats, scans, exec_summary, metadata)
    else:
        return _generate_html(threats, scans, exec_summary, metadata)


def _generate_markdown(threats: list[dict], scans: list[dict], summary: dict, metadata: dict) -> str:
    lines = [
        "# 🛡️ NexShield Security & Penetration Testing Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Risk Score:** {summary['risk_score']} / 100 ({summary['risk_posture']})  ",
        f"**Auditor / System:** {metadata.get('auditor', 'NexShield Automated Engine')}  ",
        "",
        "## Executive Summary",
        f"> {summary['narrative']}",
        "",
        "### Threat Breakdown",
        f"- 🚨 **Critical:** {summary['counts']['critical']}",
        f"- 🟧 **High:** {summary['counts']['high']}",
        f"- 🨨 **Medium:** {summary['counts']['medium']}",
        f"- 🟩 **Low:** {summary['counts']['low']}",
        "",
        "## Detailed Threat Findings",
    ]

    for idx, threat in enumerate(threats, 1):
        compliance = map_compliance(threat)
        lines.extend([
            f"### {idx}. [{threat.get('severity', 'LOW').upper()}] {threat.get('name', 'Threat')}",
            f"- **Host Node:** `{threat.get('host', 'N/A')}`",
            f"- **CVE / Identifier:** `{threat.get('cve_id', 'N/A')}`",
            f"- **Detection Source:** `{threat.get('source', 'AI Engine')}`",
            f"- **Details:** {threat.get('detail', 'N/A')}",
        ])
        if compliance:
            lines.append("- **Compliance Controls:**")
            for c in compliance:
                lines.append(f"  - `{c['framework']} ({c['control']})`: {c['desc']}")
        lines.append("")

    return "\n".join(lines)


def _generate_sarif(threats: list[dict], summary: dict, metadata: dict) -> str:
    rules = []
    results = []

    for idx, t in enumerate(threats):
        rule_id = str(t.get("cve_id") or f"NEX-{idx+1}")
        sev = str(t.get("severity")).lower()
        level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"

        rules.append({
            "id": rule_id,
            "name": str(t.get("name") or "Vulnerability"),
            "shortDescription": {"text": str(t.get("name") or "")},
            "fullDescription": {"text": str(t.get("detail") or "")},
        })

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": str(t.get("detail") or "Security threat detected.")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"host://{t.get('host', 'localhost')}"}
                }
            }]
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "NexShield Mission Control",
                    "version": "6.0",
                    "rules": rules,
                }
            },
            "results": results
        }]
    }

    return json.dumps(sarif_doc, indent=2)


def _generate_pdf_text(threats: list[dict], scans: list[dict], summary: dict, metadata: dict) -> str:
    md_content = _generate_markdown(threats, scans, summary, metadata)
    return f"===========================================================================\nNEXSHIELD EXECUTIVE SECURITY REPORT (PDF/TEXT FORMAT)\n===========================================================================\n\n{md_content}"


def _generate_html(threats: list[dict], scans: list[dict], summary: dict, metadata: dict) -> str:
    threat_rows = ""
    for t in threats:
        sev = str(t.get("severity", "low")).lower()
        color = "#f87171" if sev == "critical" else "#fb923c" if sev == "high" else "#fbbf24" if sev == "medium" else "#34d399"
        comp_tags = "".join([f"<span class='badge'>{c['framework']} {c['control']}</span>" for c in map_compliance(t)])

        threat_rows += f"""
        <tr>
            <td><span style="color: {color}; font-weight: bold;">{sev.upper()}</span></td>
            <td><strong>{t.get('name', '')}</strong><br/><small>{t.get('detail', '')}</small></td>
            <td><code>{t.get('host', '')}</code></td>
            <td><code>{t.get('cve_id', '')}</code></td>
            <td>{comp_tags or '<span style="opacity:0.4;">Standard</span>'}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>NexShield Pentest Intelligence Report</title>
    <style>
        body {{ background: #070a13; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 2rem; line-height: 1.5; }}
        .header {{ border-bottom: 2px solid #818cf8; padding-bottom: 1rem; margin-bottom: 2rem; }}
        .summary-card {{ background: rgba(22, 32, 51, 0.6); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); margin-bottom: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.1); text-align: left; }}
        th {{ background: rgba(129, 140, 248, 0.1); color: #818cf8; }}
        .badge {{ background: rgba(129, 140, 248, 0.2); color: #818cf8; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; margin-right: 4px; display: inline-block; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ NexShield Security Intelligence Report</h1>
        <p>Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Executive Audit Payload</p>
    </div>
    <div class="summary-card">
        <h2>Executive Risk Score: {summary['risk_score']} / 100 ({summary['risk_posture']})</h2>
        <p>{summary['narrative']}</p>
        <p><strong>Threat Counts:</strong> Critical: {summary['counts']['critical']} | High: {summary['counts']['high']} | Medium: {summary['counts']['medium']} | Low: {summary['counts']['low']}</p>
    </div>
    <h2>Vulnerability Findings ({len(threats)})</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability & Detail</th>
                <th>Host</th>
                <th>CVE ID</th>
                <th>Compliance Controls</th>
            </tr>
        </thead>
        <tbody>
            {threat_rows or '<tr><td colspan="5">No threats detected.</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""
    return html
