"""
tests/test_ai_training.py — Automated Test Suite for NexShield AI & Training Subsystems
"""

import sys
import os
import pytest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "nexshield"))
sys.path.insert(0, str(_ROOT))

from ai_logic import (
    extract_vuln_keywords,
    infer_port_and_protocol,
    extract_is_sensitive_port,
    _engine_ml_predict,
    MODEL_PATH,
    VECTORIZER_PATH,
)
from rag_engine import (
    knowledge_store,
    rag_retriever,
    INDEX_CACHE_PATH,
)


def test_vuln_keyword_extraction():
    """Verify vulnerability keyword extraction identifies high-risk exploit terms."""
    desc = "Apache HTTP Server 2.4.49 path traversal flaw allows remote code execution via unauthenticated request."
    kw = extract_vuln_keywords(desc)
    assert "remote code execution" in kw or "rce" in kw
    assert "path traversal" in kw
    assert "unauthenticated" in kw


def test_port_protocol_inference():
    """Verify that known network software names map to realistic default ports."""
    port, proto = infer_port_and_protocol("OpenSSH 8.2p1", "")
    assert port == 22
    assert proto == "tcp"

    port, proto = infer_port_and_protocol("Apache HTTP Server", "")
    assert port == 80
    assert proto == "tcp"

    port, proto = infer_port_and_protocol("Windows SMB", "")
    assert port == 445
    assert proto == "tcp"

    port, proto = infer_port_and_protocol("BIND DNS Server", "")
    assert port == 53
    assert proto == "udp"


def test_sensitive_port_extraction():
    """Verify sensitive port transformer accurately flags sensitive administrative ports."""
    import pandas as pd
    df = pd.DataFrame({"port": [22, 80, 445, 9999]})
    flags = extract_is_sensitive_port(df)
    assert flags[0][0] == 1  # 22 is sensitive
    assert flags[1][0] == 1  # 80 is sensitive
    assert flags[2][0] == 1  # 445 is sensitive
    assert flags[3][0] == 0  # 9999 is not in sensitive ports list


def test_ml_model_artifacts_and_prediction():
    """Verify trained ML pipeline artifacts exist and perform accurate inference."""
    if not os.path.exists(MODEL_PATH):
        pytest.skip("ML model file not found. Train model first.")

    # High-risk context: Apache Log4j RCE
    ctx_log4j = {
        "service": "http",
        "product": "log4j",
        "version": "2.14.1",
        "port": 8080,
        "protocol": "tcp",
        "host": "192.168.1.50",
        "banner": "Apache Log4j JNDI RCE CVE-2021-44228 remote code execution",
    }
    threats = _engine_ml_predict(ctx_log4j)
    assert len(threats) >= 1
    assert threats[0]["severity"] in ["high", "critical"]
    assert "ai_predicted" in threats[0]["tags"]


def test_rag_knowledge_retrieval():
    """Verify RAG retriever fetches relevant documents for security queries."""
    results = rag_retriever.retrieve("SMB windows admin shares lateral movement", top_k=2)
    assert len(results) >= 1
    top_doc = results[0].document
    assert top_doc is not None
    assert "smb" in top_doc.content.lower() or "smb" in top_doc.title.lower() or "t1021.002" in top_doc.doc_id.lower()
