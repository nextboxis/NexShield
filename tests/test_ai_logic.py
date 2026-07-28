"""
test_ai_logic.py — Unit tests for AI threat engines, risk scoring, and hashing
"""

from ai_logic import _make_threat, _threat_hash, MODELS, SEVERITY_WEIGHTS, SENSITIVE_PORTS


def test_make_threat_helper():
    threat = _make_threat(
        name="Test Threat",
        severity="high",
        host="192.168.1.5",
        cve_id="CVE-2021-44228",
        source=MODELS["version_vuln"],
        detail="Log4j vulnerability detected",
        tags=["log4j", "rce"]
    )
    assert threat["name"] == "Test Threat"
    assert threat["severity"] == "high"
    assert threat["host"] == "192.168.1.5"
    assert "detected_at" in threat


def test_threat_hash_deduplication():
    t1 = _make_threat(
        name="Threat 1", severity="high", host="10.0.0.1",
        cve_id="CVE-2021-44228", source="EngineA", detail="Detail A"
    )
    t2 = _make_threat(
        name="Threat 1 Different Detail", severity="critical", host="10.0.0.1",
        cve_id="CVE-2021-44228", source="EngineA", detail="Detail B"
    )
    assert _threat_hash(t1) == _threat_hash(t2)


def test_severity_weights_mapping():
    assert SEVERITY_WEIGHTS["critical"] == 10
    assert SEVERITY_WEIGHTS["high"] == 7
    assert SEVERITY_WEIGHTS["medium"] == 4
    assert SEVERITY_WEIGHTS["low"] == 2
    assert SEVERITY_WEIGHTS["info"] == 0


def test_sensitive_ports_knowledge_base():
    assert 22 in SENSITIVE_PORTS
    assert 445 in SENSITIVE_PORTS
    assert SENSITIVE_PORTS[445][1] == "critical"


def test_apt_threat_actor_engine():
    from ai_logic import _engine_threat_actor
    ctx = {"host": "192.168.1.10", "port": 445, "protocol": "tcp", "service": "smb"}
    threats = _engine_threat_actor(ctx)
    assert len(threats) > 0
    assert "APT Signature Match" in threats[0]["name"]
    assert "Lazarus" in threats[0]["detail"]


def test_ml_exploitability_engine():
    from ai_logic import _engine_ml_exploitability
    ctx = {"host": "192.168.1.10", "port": 445, "protocol": "tcp", "service": "smb"}
    threats = _engine_ml_exploitability(ctx)
    assert len(threats) > 0
    assert "RCE Exploitability Index" in threats[0]["name"]


def test_remediation_effort_engine():
    from ai_logic import _engine_remediation_effort
    ctx = {"host": "192.168.1.10", "port": 3389, "protocol": "tcp", "service": "rdp"}
    threats = _engine_remediation_effort(ctx)
    assert len(threats) > 0
    assert "Remediation Time Estimate" in threats[0]["name"]

