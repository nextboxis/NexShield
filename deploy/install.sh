#!/bin/bash
cd "$(dirname "$0")/.."

echo ""
echo "========================================================"
echo "  NexShield v6.1 - Linux/macOS Setup (Pure Rust Engine)"
echo "========================================================"
echo ""

# ── Check Cargo / Rust ─────────────────────────────────────────
if ! command -v cargo &> /dev/null; then
    echo "[!] Rust / Cargo is NOT installed."
    echo "    Install it via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

RUSTVER=$(cargo --version 2>&1 | awk '{print $2}')
echo "[+] Cargo $RUSTVER detected"

# ── Compile Release Binaries ───────────────────────────────────
echo ""
echo "[*] Compiling optimized release binaries (zero external dependencies)..."
cargo build --release --offline || cargo build --release

# ── Create .env ────────────────────────────────────────────────
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    echo "[+] Created .env from template"
fi

# ── Done ───────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Setup Complete!"
echo "========================================================"
echo ""
echo "  To start NexShield, run:"
echo ""
echo "      ./target/release/nexshield-cli run"
echo ""
echo "  Dashboard will open at: http://127.0.0.1:5000"
echo ""
