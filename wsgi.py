"""
WSGI Production Entry Point for NexShield
==========================================
This module serves as the entry point for production WSGI servers
like Gunicorn and Waitress. It properly initializes the Flask app
with SocketIO and handles graceful shutdowns.

Usage:
    Gunicorn:  gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 wsgi:app
    Waitress:  waitress-serve --port=5000 wsgi:app
"""

import os
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

os.environ.setdefault("FLASK_ENV", "production")
os.environ.setdefault("FLASK_DEBUG", "false")

os.environ["WERKZEUG_RUN_MAIN"] = "true"

from app import app, socketio, _startup_banner, _provision_admin_user, _log_activity  # type: ignore


def init_app():
    """Initialize application for production."""
    _startup_banner()
    _provision_admin_user()
    _log_activity("system", "NexShield production server started", "info")
    logger.info("✓ NexShield production WSGI app initialized")
    return app


app = init_app()

if __name__ == "__main__":
    logger.warning("⚠️  Direct execution detected. Use Gunicorn or Waitress instead!")
    logger.warning("    Example: gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 wsgi:app")
    
    port = int(os.environ.get("PORT", 5000))
    socketio.run(
        app,
        debug=False,
        host="127.0.0.1",
        port=port,
        use_reloader=False,
        use_debugger=False,
        allow_unsafe_werkzeug=True,
    )
