#!/usr/bin/env python3
"""
run.py — NexShield Unified Launcher
====================================
Single command to setup, configure, and run NexShield.

Usage:
    python run.py                  # Start NexShield (auto-configures everything)
    python run.py --port 8080      # Start on custom port
    python run.py --check          # Verify setup without starting
    python run.py --reset-db       # Reset the database
    python run.py --host 0.0.0.0   # Listen on all interfaces
    python run.py --debug          # Enable debug mode
"""

import os
import sys
import shutil
import platform
import subprocess
from pathlib import Path

# Fix Windows console encoding for Unicode output
try:
    sys.stdout.reconfigure(encoding='utf-8')  # type: ignore
except Exception:
    pass

# ─── Constants ───────────────────────────────────────────────────────
MIN_PYTHON = (3, 9)
PROJECT_DIR = Path(__file__).parent.resolve()
VENV_DIR = PROJECT_DIR / ".venv"
DATA_DIR = PROJECT_DIR / "data"
ENV_FILE = PROJECT_DIR / ".env"
ENV_EXAMPLE = PROJECT_DIR / ".env.example"
REQ_FILE = PROJECT_DIR / "requirements.txt"

BANNER = r"""
 _   _           ____  _     _      _     _
| \ | | _____  _/ ___|| |__ (_) ___| | __| |
|  \| |/ _ \ \/ /\___ \| '_ \| |/ _ \ |/ _` |
| |\  |  __/>  <  ___) | | | | |  __/ | (_| |
|_| \_|\___/_/\_\|____/|_| |_|_|\___|_|\__,_|
                 MISSION CONTROL v5.0
"""


def print_status(icon, message):
    """Print a status message with icon."""
    print(f"   [{icon}] {message}")


def print_header(title):
    """Print a section header."""
    print(f"\n{'-' * 60}")
    print(f"  {title}")
    print(f"{'-' * 60}")


def check_python_version():
    """Verify Python version meets minimum requirements."""
    ver = sys.version_info[:2]
    if ver < MIN_PYTHON:
        print_status("X", f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required, found {ver[0]}.{ver[1]}")
        print_status("!", "Download Python: https://www.python.org/downloads/")
        return False
    print_status("+", f"Python {ver[0]}.{ver[1]} detected")
    return True


def check_pip_packages():
    """Check and install missing pip packages."""
    missing = []
    required_packages = {
        "flask": "Flask",
        "tinydb": "tinydb",
        "flask_socketio": "Flask-SocketIO",
        "flask_cors": "flask-cors",
        "dotenv": "python-dotenv",
        "requests": "requests",
        "jinja2": "Jinja2",
    }

    for import_name, pip_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)

    if missing:
        print_status("!", f"Missing packages: {', '.join(missing)}")
        print_status("*", "Installing missing packages...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q"] + missing,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print_status("✓", "Packages installed successfully")
        except subprocess.CalledProcessError:
            print_status("✗", "Failed to install packages. Run manually:")
            print(f"        pip install -r {REQ_FILE}")
            return False
    else:
        print_status("✓", "All core packages installed")
    return True


def check_nmap():
    """Check if nmap is installed."""
    nmap_path = shutil.which("nmap")
    if nmap_path:
        print_status("+", f"Nmap found: {nmap_path}")
        return True
        
    print_status("!", "Nmap NOT found (scanning will not work)")
    os_name = platform.system()
    if os_name == "Windows":
        print_status("!", "Install: https://nmap.org/download.html")
        print_status("!", "After install, add nmap to your system PATH")
    elif os_name == "Linux":
        print_status("!", "Install: sudo apt install nmap  (Debian/Ubuntu)")
        print_status("!", "         sudo yum install nmap  (CentOS/RHEL)")
    elif os_name == "Darwin":
        print_status("!", "Install: brew install nmap")
    return False


def check_env_file():
    """Ensure .env file exists."""
    if ENV_FILE.exists():
        print_status("+", ".env configuration file found")
        return True

    if ENV_EXAMPLE.exists():
        shutil.copy2(ENV_EXAMPLE, ENV_FILE)
        print_status("+", "Created .env from .env.example")
    else:
        # Create a minimal .env
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.write("# NexShield Configuration\n")
            f.write("FLASK_ENV=development\n")
            f.write("FLASK_DEBUG=true\n")
            f.write("PORT=5000\n")
            f.write("ADMIN_PASSWORD=admin\n")
        print_status("+", "Created default .env file")
    return True


def check_data_dir():
    """Ensure data directory exists."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print_status("+", f"Data directory ready: {DATA_DIR}")
    return True


def check_database():
    """Verify database connectivity."""
    try:
        from config import check_connection, _using_mongodb  # type: ignore
        if check_connection():
            db_type = "MongoDB" if _using_mongodb else "TinyDB (built-in)"
            print_status("+", f"Database ready: {db_type}")
            return True
            
        print_status("X", "Database initialization failed")
        return False
    except Exception as e:
        print_status("X", f"Database check error: {e}")
        return False


def provision_admin():
    """Create default admin user if not exists."""
    try:
        from config import users, check_connection  # type: ignore
        if not check_connection():
            return False

        existing = users.find_one({"username": "admin"})
        if existing:
            print_status("+", "Admin user exists")
            return True

        from werkzeug.security import generate_password_hash  # type: ignore
        from datetime import datetime, timezone

        password = os.environ.get("ADMIN_PASSWORD", "admin")
        users.insert_one({
            "username": "admin",
            "password_hash": generate_password_hash(password),
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        print_status("+", f"Admin user created (password: {password})")
        return True
    except Exception as e:
        print_status("!", f"Admin provisioning: {e}")
        return False


def reset_database():
    """Reset the database (delete all data)."""
    print_header("Database Reset")
    db_file = DATA_DIR / "nexshield_db.json"
    if db_file.exists():
        os.remove(db_file)
        print_status("+", "TinyDB database deleted")
    else:
        print_status("!", "No database file found to delete")
    print_status("+", "Database reset complete. Restart to recreate.")


def run_checks():
    """Run all setup checks."""
    print_header("System Checks")
    results = []

    results.append(("Python Version", check_python_version()))
    results.append(("Pip Packages", check_pip_packages()))
    results.append(("Environment File", check_env_file()))
    results.append(("Data Directory", check_data_dir()))
    results.append(("Database", check_database()))
    results.append(("Admin User", provision_admin()))
    results.append(("Nmap Scanner", check_nmap()))

    print_header("Check Results")
    all_ok = True
    for name, ok in results:
        icon = "+" if ok else "X"
        print_status(icon, name)
        if name not in ("Nmap Scanner",) and not ok:
            all_ok = False

    return all_ok


def start_server(host="127.0.0.1", port=5000, debug=False):
    """Start the NexShield Flask server."""
    print_header("Starting NexShield Server")
    print_status("*", f"Host: {host}")
    print_status("*", f"Port: {port}")
    print_status("*", f"Debug: {'ON' if debug else 'OFF'}")
    print_status("*", f"Dashboard: http://{host}:{port}")
    print()
    print("   Press Ctrl+C to stop the server.")
    print()

    try:
        from app import app, socketio, _log_activity  # type: ignore
        _log_activity("system", "NexShield platform started", "info")
        socketio.run(
            app,
            debug=debug,
            host=host,
            port=port,
            use_reloader=debug,
            allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        print("\n")
        print_status("*", "NexShield stopped. Goodbye!")
    except Exception as e:
        print_status("X", f"Server error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="NexShield — AI-Powered Threat Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                  Start NexShield (auto-configures)
  python run.py --port 8080      Start on port 8080
  python run.py --check          Verify setup only
  python run.py --reset-db       Reset the database
  python run.py --debug          Enable debug mode
        """,
    )
    parser.add_argument("--port", type=int, default=None, help="Server port (default: 5000)")
    parser.add_argument("--host", type=str, default=None, help="Server host (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--check", action="store_true", help="Run setup checks only, don't start server")
    parser.add_argument("--reset-db", action="store_true", help="Reset the database")

    args = parser.parse_args()

    # Print banner
    print(BANNER)
    print(f"   OS: {platform.system()} {platform.release()}")
    print(f"   Python: {sys.version.split()[0]}")
    print(f"   Project: {PROJECT_DIR}")

    # Handle reset
    if args.reset_db:
        reset_database()
        sys.exit(0)

    # Run checks
    ok = run_checks()

    if args.check:
        sys.exit(0 if ok else 1)

    if not ok:
        print()
        print_status("!", "Some checks failed. Fix the issues above, then try again.")
        print_status("!", "Or run: pip install -r requirements.txt")
        sys.exit(1)

    # Resolve port and host
    port = args.port or int(os.environ.get("PORT", "5000"))
    host = args.host or os.environ.get("HOST", "127.0.0.1")
    debug = args.debug or os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # Start server
    start_server(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
