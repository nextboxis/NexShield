"""Tests for app.py — API route testing."""

import pytest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Create a test client with a temporary TinyDB database."""
    # Patch environment to use TinyDB
    monkeypatch.delenv("MONGO_URI", raising=False)
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret-key-for-testing")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")

    from app import app, _provision_admin_user
    app.config["TESTING"] = True
    _provision_admin_user()

    with app.test_client() as client:
        yield client


def _login(client, username="admin", password="admin"):
    """Helper to log in and return response."""
    return client.post(
        "/api/auth/login",
        data=json.dumps({"username": username, "password": password}),
        content_type="application/json",
    )


def test_health_check(client):
    """Health endpoint should be accessible without auth."""
    resp = client.get("/api/health")
    data = resp.get_json()
    assert resp.status_code in (200, 503)
    assert "status" in data
    assert "version" in data
    assert data["version"] == "6.0"


def test_login_success(client):
    """Successful login returns user info and redirect."""
    resp = _login(client)
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["status"] == "complete"
    assert data["user"] == "admin"
    assert "redirect" in data


def test_login_bad_credentials(client):
    """Failed login returns 401."""
    resp = _login(client, "admin", "wrongpassword")
    assert resp.status_code == 401


def test_login_missing_fields(client):
    """Login with missing fields returns 400."""
    resp = client.post(
        "/api/auth/login",
        data=json.dumps({"username": "admin"}),
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_session_check_unauthenticated(client):
    """Session check without login returns authenticated=False."""
    resp = client.get("/api/auth/session")
    data = resp.get_json()
    assert data["authenticated"] is False


def test_session_check_authenticated(client):
    """Session check after login returns authenticated=True."""
    _login(client)
    resp = client.get("/api/auth/session")
    data = resp.get_json()
    assert data["authenticated"] is True
    assert data["user"] == "admin"


def test_stats_requires_auth(client):
    """Stats endpoint should return 401 without login."""
    resp = client.get("/api/stats")
    assert resp.status_code == 401


def test_stats_with_auth(client):
    """Stats endpoint returns data when authenticated."""
    _login(client)
    resp = client.get("/api/stats")
    data = resp.get_json()
    assert resp.status_code in (200, 503)
    if resp.status_code == 200:
        assert "total_threats" in data
        assert "total_scans" in data


def test_threats_requires_auth(client):
    """Threats endpoint should return 401 without login."""
    resp = client.get("/api/threats")
    assert resp.status_code == 401


def test_threats_with_auth(client):
    """Threats endpoint returns list when authenticated."""
    _login(client)
    resp = client.get("/api/threats")
    data = resp.get_json()
    assert resp.status_code in (200, 503)
    if resp.status_code == 200:
        assert "threats" in data


def test_threat_single_requires_auth(client):
    """Single threat endpoint should require auth (v6 security fix)."""
    resp = client.get("/api/threat/nonexistent-id")
    assert resp.status_code == 401


def test_report_download_rc_requires_auth(client):
    """RC download endpoint should require auth (v6 security fix)."""
    resp = client.get("/api/report/download-rc")
    assert resp.status_code == 401


def test_change_password(client):
    """Password change with valid current password should succeed."""
    _login(client)
    resp = client.post(
        "/api/auth/change-password",
        data=json.dumps({
            "current_password": "admin",
            "new_password": "newpass123",
            "confirm_password": "newpass123",
        }),
        content_type="application/json",
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["status"] == "complete"

    # Login with new password should work
    client.post("/api/auth/logout", content_type="application/json")
    resp2 = _login(client, "admin", "newpass123")
    assert resp2.status_code == 200

    # Restore original password so other tests aren't affected
    client.post(
        "/api/auth/change-password",
        data=json.dumps({
            "current_password": "newpass123",
            "new_password": "admin",
            "confirm_password": "admin",
        }),
        content_type="application/json",
    )


def test_change_password_wrong_current(client):
    """Password change with wrong current password returns 401."""
    _login(client)
    resp = client.post(
        "/api/auth/change-password",
        data=json.dumps({
            "current_password": "wrongpass",
            "new_password": "newpass123",
            "confirm_password": "newpass123",
        }),
        content_type="application/json",
    )
    assert resp.status_code == 401


def test_change_password_mismatch(client):
    """Password change with mismatched new passwords returns 400."""
    _login(client)
    resp = client.post(
        "/api/auth/change-password",
        data=json.dumps({
            "current_password": "admin",
            "new_password": "newpass123",
            "confirm_password": "different456",
        }),
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_profile_endpoint(client):
    """Profile endpoint returns user info."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
    resp = client.get("/api/auth/profile")
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["username"] == "admin"
    assert data["role"] == "admin"


def test_dashboard_summary(client):
    """Dashboard summary combines stats and recent data."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
    resp = client.get("/api/dashboard/summary")
    data = resp.get_json()
    assert resp.status_code in (200, 503)
    if resp.status_code == 200:
        assert "stats" in data
        assert "recent_threats" in data
        assert "recent_activity" in data


def test_logout(client):
    """Logout clears the session."""
    _login(client)
    resp = client.post("/api/auth/logout", content_type="application/json")
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["status"] == "complete"

    # Session should be cleared
    resp2 = client.get("/api/auth/session")
    assert resp2.get_json()["authenticated"] is False


def test_root_redirect_unauthenticated(client):
    """Root path redirects to login when not authenticated."""
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_export_requires_auth(client):
    """Export endpoint requires auth."""
    resp = client.get("/api/export?format=json")
    assert resp.status_code == 401


def test_registration_disabled(client):
    """Registration should return 403 (disabled)."""
    resp = client.post(
        "/api/auth/register",
        data=json.dumps({"username": "newuser", "password": "pass123"}),
        content_type="application/json",
    )
    assert resp.status_code == 403
