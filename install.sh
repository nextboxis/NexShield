#!/bin/bash

echo ""
echo "========================================================"
echo "  NexShield v5 - Linux/macOS Setup"
echo "========================================================"
echo ""

# ── Check Python 3 ───────────────────────────────────────────
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "[!] Python3 is NOT installed."
    echo "    Install it:"
    echo "      Ubuntu/Debian: sudo apt install python3 python3-venv python3-pip"
    echo "      CentOS/RHEL:  sudo yum install python3"
    echo "      macOS:        brew install python3"
    exit 1
fi

PYVER=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "[+] Python $PYVER detected ($PYTHON_CMD)"

# ── Create Virtual Environment ───────────────────────────────
echo ""
echo "[*] Creating virtual environment (.venv)..."
if [ -d ".venv" ]; then
    echo "[+] Virtual environment already exists, reusing it."
else
    $PYTHON_CMD -m venv .venv
    if [ $? -ne 0 ]; then
        echo "[!] Failed to create virtual environment."
        echo "    Try: sudo apt install python3-venv  (Ubuntu/Debian)"
        exit 1
    fi
fi

# ── Activate ─────────────────────────────────────────────────
echo "[*] Activating virtual environment..."
source .venv/bin/activate

# ── Upgrade pip ──────────────────────────────────────────────
echo "[*] Upgrading pip..."
pip install --upgrade pip -q

# ── Install Dependencies ─────────────────────────────────────
echo "[*] Installing dependencies..."
pip install -r requirements.txt -q
if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Some packages failed. Trying individual installs..."
    pip install flask tinydb flask-socketio flask-cors python-dotenv requests python-nmap -q
fi

# ── Create .env ──────────────────────────────────────────────
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    echo "[+] Created .env from template"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Setup Complete!"
echo "========================================================"
echo ""
echo "  To start NexShield, run:"
echo ""
echo "      source .venv/bin/activate"
echo "      python run.py"
echo ""
echo "  That's it! No database setup needed."
echo "  Page flow: Login -> Dashboard -> Report"
echo "  1. Login:     http://127.0.0.1:5000/login"
echo "  2. Dashboard: http://127.0.0.1:5000/index"
echo "  3. Report:    http://127.0.0.1:5000/report"
echo ""
echo "  Optional: Install nmap for network scanning:"
echo "      sudo apt install nmap   (Debian/Ubuntu)"
echo "      brew install nmap       (macOS)"
echo ""
