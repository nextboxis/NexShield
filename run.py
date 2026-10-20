#!/usr/bin/env python3
"""
run.py — NexShield Unified Pure-Rust Runner & Dispatcher
=========================================================
100% Zero-Python-Dependency Launcher.
Transparently delegates all commands to the compiled native NexShield Rust binary
(target/release/nexshield-cli), delivering microsecond-latency security operations.

Usage:
    python run.py                  # Start NexShield Pure-Rust Web Server (default: 5000)
    python run.py --port 8080      # Start on custom port
    python run.py --check          # Run pre-flight security system checks
    python run.py --self-test      # Run 6-subsystem embedded diagnostic test suite
    python run.py --reset-db       # Reset local document store
    python run.py --train [limit]  # Train & calibrate ML threat heuristic engine
    python run.py scan <target>    # Execute native port scan & vulnerability assessment
    python run.py report <target>  # Generate HTML/Markdown/SARIF threat report
    python run.py diag             # Inspect DSA memory footprint & performance metrics
"""

import sys
import os
import subprocess
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
BINARY_NAME = "nexshield-cli.exe" if sys.platform == "win32" else "nexshield-cli"
RELEASE_BIN = PROJECT_ROOT / "target" / "release" / BINARY_NAME
DEBUG_BIN = PROJECT_ROOT / "target" / "debug" / BINARY_NAME


def find_cargo() -> str:
    """Find cargo binary in PATH or default installation directory."""
    cargo = shutil.which("cargo")
    if cargo:
        return cargo

    # Check default cargo home on Windows/Unix
    user_home = Path.home()
    default_cargo = user_home / ".cargo" / "bin" / ("cargo.exe" if sys.platform == "win32" else "cargo")
    if default_cargo.exists():
        return str(default_cargo)

    return ""


def ensure_binary() -> Path:
    """Ensure the native NexShield Rust binary is compiled and available."""
    if RELEASE_BIN.exists():
        return RELEASE_BIN
    if DEBUG_BIN.exists():
        return DEBUG_BIN

    print("[*] NexShield compiled native binary not found.")
    print("[*] Initiating zero-dependency standard library build via Cargo...")

    cargo = find_cargo()
    if not cargo:
        print("[!] ERROR: 'cargo' compiler was not found in PATH or ~/.cargo/bin.")
        print("    Please install Rust via https://rustup.rs/ to compile NexShield.")
        sys.exit(1)

    cmd = [cargo, "build", "--release", "--offline"]
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        # If offline build failed (e.g. initial setup), retry online
        cmd_online = [cargo, "build", "--release"]
        result = subprocess.run(cmd_online, cwd=str(PROJECT_ROOT))
        if result.returncode != 0:
            print("[!] Build failed. Please verify Rust installation.")
            sys.exit(1)

    if RELEASE_BIN.exists():
        return RELEASE_BIN
    print("[!] Target binary missing after build.")
    sys.exit(1)


def parse_and_dispatch():
    """Translate legacy Python CLI flags and dispatch directly to native Rust CLI."""
    args = sys.argv[1:]
    target_bin = ensure_binary()

    rust_args = []

    if not args:
        # Default: start server
        rust_args = ["run", "5000", "127.0.0.1"]
    elif "--check" in args or "check" in args:
        rust_args = ["check"]
    elif "--self-test" in args or "self-test" in args:
        rust_args = ["self-test"]
    elif "--reset-db" in args or "reset-db" in args:
        rust_args = ["reset-db"]
    elif "--train" in args or "train" in args:
        limit = "5000"
        for i, a in enumerate(args):
            if a in ("--train", "train") and i + 1 < len(args) and args[i + 1].isdigit():
                limit = args[i + 1]
                break
        rust_args = ["train", limit]
    elif "--import-cve" in args or "import-cve" in args:
        rust_args = ["import-cve"] + [a for a in args if a not in ("--import-cve", "import-cve")]
    elif args[0] in ("scan", "geo", "report", "cve", "fix", "rag", "msf", "diag", "serve"):
        rust_args = args
    else:
        # Check for port / host flags
        port = "5000"
        host = "127.0.0.1"
        for i, a in enumerate(args):
            if a in ("--port", "-p") and i + 1 < len(args):
                port = args[i + 1]
            elif a in ("--host", "-h") and i + 1 < len(args):
                host = args[i + 1]
        rust_args = ["run", port, host]

    # Execute native binary directly replacing or subprocessing
    cmd = [str(target_bin)] + rust_args
    try:
        sys.exit(subprocess.run(cmd, cwd=str(PROJECT_ROOT)).returncode)
    except KeyboardInterrupt:
        print("\n[*] Terminated by user.")
        sys.exit(0)


if __name__ == "__main__":
    parse_and_dispatch()
