"""
routes.dashboard — Frontend Page Serving Blueprint for NexShield
==================================================================
Handles serving HTML pages: login, dashboard, report.
"""

import os
import logging

from flask import Blueprint, render_template, redirect, url_for, session

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)

DEFAULT_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "Admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ADMIN")


@dashboard_bp.route("/")
def serve_root():
    """Entry point: always start at the login page."""
    return redirect(url_for("dashboard.serve_login"))


@dashboard_bp.route("/login")
def serve_login():
    """Serve the authentication page. Always shown first on each run."""
    return render_template(
        "login.html",
        default_username=DEFAULT_ADMIN_USERNAME,
        default_password=DEFAULT_ADMIN_PASSWORD,
    )


@dashboard_bp.route("/index")
def serve_dashboard():
    """Serve the NexShield Mission Control dashboard. Requires login."""
    if "user" not in session:
        return redirect(url_for("dashboard.serve_login", next="/index"))
    return render_template("index.html")


@dashboard_bp.route("/report")
def serve_report():
    """Serve the formatted HTML penetration testing report page. Requires login."""
    if "user" not in session:
        return redirect(url_for("dashboard.serve_login", next="/report"))
    return render_template("report.html")
