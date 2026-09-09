"""
diagnostics.py — System Diagnostic and Self-Test Suite for NexShield
====================================================================
Performs full verification of database access, AI logic, CVE parsing,
remediation generation, report generation, alerting, and RAG search.

Decoupled from run.py and app.py to eliminate circular dependencies.
"""

from typing import List, Tuple


def _print_status(icon: str, message: str) -> None:
    """Print status line with icon indicator."""
    print(f"   [{icon}] {message}")


def _print_header(title: str) -> None:
    """Print formatted section header."""
    print(f"\n{'-' * 60}")
    print(f"  {title}")
    print(f"{'-' * 60}")


def run_self_test() -> bool:
    """Run full system diagnostic self-test suite embedded in the project."""
    _print_header("System Self-Test Suite")
    results: List[Tuple[str, bool]] = []

    # 1. Database Check
    try:
        from config import check_connection
        results.append(("Database Read/Write", check_connection()))
    except Exception:
        results.append(("Database Read/Write", False))

    # 2. AI Logic Engine Check
    try:
        from ai_logic import _make_threat
        threat = _make_threat("Test Threat", "high", "127.0.0.1", "CVE-2023-0001", "SelfTest", "Test detail")
        results.append(("21-Engine AI Logic", threat["name"] == "Test Threat"))
    except Exception:
        results.append(("21-Engine AI Logic", False))

    # 3. CVE 5.0 Version Bounds Matching Check
    try:
        from cve_lookup import compare_versions, match_cpe
        ver_ok = compare_versions("2.4.41", "2.4.52") == -1 and match_cpe(
            "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
        )
        results.append(("CVE 5.0 Version Matching", ver_ok))
    except Exception:
        results.append(("CVE 5.0 Version Matching", False))

    # 4. Remediation Code Generator Check
    try:
        from remediation_generator import generate_remediation_script
        ansible_code = generate_remediation_script(
            [{"name": "SMB Exposed", "host": "127.0.0.1"}], "127.0.0.1", "ansible"
        )
        results.append(("Remediation Generator", "hosts:" in ansible_code))
    except Exception:
        results.append(("Remediation Generator", False))

    # 5. Report Exporter Check
    try:
        from report_generator import generate_report_content
        rpt_code = generate_report_content(
            [{"name": "SMB Exposed", "severity": "critical", "host": "127.0.0.1"}],
            [],
            fmt="markdown",
        )
        results.append(("Multi-Format Report Generator", "NexShield Security" in rpt_code))
    except Exception:
        results.append(("Multi-Format Report Generator", False))

    # 6. Webhook Alerting Check
    try:
        from webhook_notifier import dispatch_webhook_alert
        res = dispatch_webhook_alert({"name": "SelfTest Alert", "severity": "low"})
        results.append(("Webhook Alert Dispatcher", isinstance(res, dict)))
    except Exception:
        results.append(("Webhook Alert Dispatcher", False))

    # 7. RAG Intelligence Engine Check
    try:
        from rag_engine import knowledge_store, rag_retriever
        docs = rag_retriever.retrieve("SMB EternalBlue", top_k=1)
        results.append(("RAG Intelligence Engine", len(docs) > 0 and len(knowledge_store.all_documents()) > 0))
    except Exception:
        results.append(("RAG Intelligence Engine", False))

    # 8. IP Geolocation & ASN Intelligence Check
    try:
        from ip_lookup import lookup_ip, is_private_ip
        lan_check = is_private_ip("192.168.1.1")
        loop_check = is_private_ip("127.0.0.1")
        pub_check = lookup_ip("8.8.8.8")
        geo_ok = (
            lan_check and loop_check
            and pub_check.get("country_code") == "US"
            and pub_check.get("asn") == 15169
        )
        results.append(("IP Geolocation & ASN Engine", geo_ok))
    except Exception:
        results.append(("IP Geolocation & ASN Engine", False))

    _print_header("Self-Test Results")
    all_ok = True
    for name, ok in results:
        icon = "✓" if ok else "✗"
        _print_status(icon, f"{name}: {'PASSED' if ok else 'FAILED'}")
        if not ok:
            all_ok = False

    return all_ok
