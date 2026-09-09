"""
tests/test_ip_lookup.py — Unit Tests for IP Geolocation & ASN Engine
"""

import pytest
from ip_lookup import lookup_ip, lookup_batch, is_private_ip, get_country, get_asn, ip_to_int, int_to_ip


def test_ip_integer_conversion():
    assert ip_to_int("0.0.0.0") == 0
    assert ip_to_int("255.255.255.255") == 4294967295
    assert ip_to_int("127.0.0.1") == 2130706433
    assert int_to_ip(2130706433) == "127.0.0.1"
    assert ip_to_int("invalid") is None


def test_private_network_classification():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.5.25") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("169.254.10.20") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_public_ip_resolution():
    res_google = lookup_ip("8.8.8.8")
    assert res_google["country_code"] == "US"
    assert "United States" in res_google["country_name"]
    assert res_google["asn"] == 15169
    assert "Google" in res_google["as_name"]
    assert res_google["is_private"] is False
    assert res_google["network_type"] == "public"

    res_cf = lookup_ip("1.1.1.1")
    assert res_cf["country_code"] == "AU"
    assert res_cf["asn"] == 13335
    assert "Cloudflare" in res_cf["as_name"]


def test_batch_lookup():
    ips = ["8.8.8.8", "192.168.1.1", "127.0.0.1"]
    batch = lookup_batch(ips)
    assert len(batch) == 3
    assert batch["8.8.8.8"]["asn"] == 15169
    assert batch["192.168.1.1"]["is_private"] is True
    assert batch["127.0.0.1"]["network_type"] == "loopback"


def test_invalid_ip_handling():
    res = lookup_ip("not-a-valid-ip")
    assert res["network_type"] == "invalid"
    assert res["country_code"] == ""
    assert res["asn"] == 0


def test_api_geo_endpoint():
    from app import app
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    resp = client.get("/api/geo/8.8.8.8")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "complete"
    assert data["geo"]["country_code"] == "US"
    assert data["geo"]["asn"] == 15169
