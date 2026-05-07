#!/bin/bash

echo "========================================================"
echo "  NexShield v5 - Automated Linux/macOS Setup"
echo "========================================================"
echo ""

# Check for Python 3
if ! command -v python3 &> /dev/null
then
    echo "[!] Python3 could not be found. Please install Python 3.10+ and try again."
    exit 1
fi

echo "[*] Creating virtual environment (.venv)..."
python3 -m venv .venv

echo "[*] Activating virtual environment..."
source .venv/bin/activate

echo "[*] Installing dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "========================================================"
echo "  Setup Complete!"
echo "========================================================"
echo "To start NexShield:"
echo ""
echo "  1. Ensure MongoDB is running locally"
echo "  2. Activate the environment: source .venv/bin/activate"
echo "  3. Start the server:        python app.py"
echo ""
