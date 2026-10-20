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
import signal
import logging
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "nexshield"))
sys.path.insert(0, str(_PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("nexshield.wsgi")

os.environ.setdefault("FLASK_ENV", "production")
os.environ.setdefault("FLASK_DEBUG", "false")
os.environ["WERKZEUG_RUN_MAIN"] = "true"

from app import app, socketio, _startup_banner, _provision_admin_user, _log_activity  # type: ignore


def _handle_shutdown(signum, frame):
    """Handle graceful shutdown signals."""
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.info(f"Shutdown signal received ({sig_name}). Exiting cleanly...")
    try:
        _log_activity("system", f"NexShield production server stopped ({sig_name})", "info")
    except Exception:
        pass
    sys.exit(0)


def init_app():
    """Initialize application for production."""
    try:
        signal.signal(signal.SIGTERM, _handle_shutdown)
        signal.signal(signal.SIGINT, _handle_shutdown)
    except (ValueError, AttributeError):
        pass

    _startup_banner()
    _provision_admin_user()
    _log_activity("system", "NexShield production server started", "info")
    logger.info("✓ NexShield production WSGI app initialized")
    return app


app = init_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")

    # If waitress is available on Windows, prefer it for production serving
    try:
        import waitress  # type: ignore
        logger.info(f"🚀 Starting Waitress production server on http://{host}:{port}")
        waitress.serve(app, host=host, port=port, threads=8)
    except ImportError:
        logger.warning("⚠️  Waitress/Gunicorn not detected. Starting standard SocketIO runner...")
        logger.warning("    For production, install waitress: pip install waitress")
        socketio.run(
            app,
            debug=False,
            host=host,
            port=port,
            use_reloader=False,
            use_debugger=False,
            allow_unsafe_werkzeug=True,
        )
