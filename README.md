# NexShield v5

## AI-Powered Threat Intelligence & Local Security Scanner

```text
███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
                           MISSION CONTROL v5.0
```

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Framework-000000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge)](LICENSE)

---

NexShield is a **local-first** cybersecurity platform that scans your network, analyzes findings with a 16-engine AI pipeline, and generates professional penetration testing reports — all from your own machine. **No cloud. No external databases. No complicated setup.**

---

## 🚀 Quick Start (3 Steps)

### Step 1: Clone & Install

**Windows:**
```cmd
git clone https://github.com/nextboxis/NexShield.git
cd NexShield
install.bat
```

**Linux / macOS:**
```bash
git clone https://github.com/nextboxis/NexShield.git
cd NexShield
chmod +x install.sh && ./install.sh
```

**Or manually:**
```bash
git clone https://github.com/nextboxis/NexShield.git
cd NexShield
python -m venv .venv

# Activate the virtual environment:
# Windows:     .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

pip install -r requirements.txt
```

### Step 2: Run

```bash
python run.py
```

That's it! NexShield will:
- ✅ Check your Python version
- ✅ Auto-create the database (built-in, no setup needed)
- ✅ Create a default admin account
- ✅ Start the web dashboard

### Step 3: Open Dashboard

Open your browser to: **http://127.0.0.1:5000**

Login with:
- **Username:** `admin`
- **Password:** `admin`

---

## 📋 Requirements

| Requirement | Required? | Notes |
| --- | --- | --- |
| **Python 3.9+** | ✅ Yes | [Download Python](https://www.python.org/downloads/) — check "Add to PATH" during install |
| **Nmap** | ⚡ For scanning | [Download Nmap](https://nmap.org/download.html) — add to PATH after install |
| **MongoDB** | ❌ Optional | Built-in TinyDB database works out of the box |
| **Metasploit** | ❌ Optional | Only needed for live exploit execution |

> **Note:** NexShield uses a built-in database (TinyDB) by default. You do **not** need to install MongoDB, PostgreSQL, or any other database server.

---

## ⚙️ Configuration

NexShield auto-creates a `.env` file on first run. To customize:

```bash
# Copy the template
cp .env.example .env

# Edit with your preferred editor
```

### Key Settings

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `5000` | Server port |
| `ADMIN_USERNAME` | `admin` | Default admin username |
| `ADMIN_PASSWORD` | `admin` | Default admin password |
| `FLASK_DEBUG` | `true` | Enable debug mode |
| `MONGO_URI` | *(empty)* | Set to use MongoDB instead of built-in TinyDB |
| `FLASK_SECRET_KEY` | *(auto)* | Session encryption key |

---

## 🎯 CLI Commands

```bash
# Start NexShield (auto-configures everything)
python run.py

# Start on a different port
python run.py --port 8080

# Check setup without starting
python run.py --check

# Reset the database
python run.py --reset-db

# Enable debug mode
python run.py --debug

# Listen on all interfaces (not just localhost)
python run.py --host 0.0.0.0
```

---

## ✨ Key Features

| Feature | Description |
| --- | --- |
| **Mission Control HUD** | Real-time SOC dashboard with animated topology map, severity radar, and 7-day timeline |
| **16-Engine AI Pipeline** | CVE correlation, default credentials, SSL/TLS audit, lateral movement, zero-day heuristics |
| **ML Threat Prediction** | Ensemble model (Random Forest + Gradient Boosting) trained on your scan data |
| **Metasploit Integration** | Automatic exploit module mapping with RC script generation |
| **9 Scan Types** | Quick, Default, Deep, Stealth, OS Detect, Vuln Scripts, SSL/TLS, UDP, Full |
| **Pentest Reporting** | Executive summary, risk matrix, remediation roadmap, topology visualization |
| **Real-time WebSocket** | Live scan progress, analysis status, and threat notifications |
| **CVE Intelligence** | Built-in CVE lookup with NVD API integration |
| **Host Quarantine** | Zero-trust isolation of compromised nodes |
| **Export** | CSV/JSON export, Metasploit RC scripts |

---

## 🧠 AI Analysis Engines

NexShield's analysis pipeline runs **16 independent engines** against scan data:

| # | Engine | Detection Scope |
| --- | --- | --- |
| 1 | CVE Correlation | Known vulnerabilities from NVD |
| 2 | Default Credentials | Common username/password pairs |
| 3 | SSL/TLS Audit | Weak ciphers, expired certificates |
| 4 | DNS Zone Analysis | Zone transfer, subdomain enumeration |
| 5 | SMB/NetBIOS | Share exposure, null sessions |
| 6 | SNMP Community | Default community strings |
| 7 | Web Application | Directory traversal, header analysis |
| 8 | Database Exposure | Open database ports, auth bypass |
| 9 | Email Infrastructure | Open relays, SPF/DKIM issues |
| 10 | IoT/SCADA | Industrial protocol exposure |
| 11 | Cloud Metadata | Cloud service misconfigurations |
| 12 | Container Escape | Docker/Kubernetes exposure |
| 13 | Lateral Movement | Pivot path analysis |
| 14 | Behavioral Anomaly | Port/service mismatch detection |
| 15 | Zero-Day Heuristics | High-entropy banners, C2 beacons |
| 16 | Metasploit Mapping | Automatic exploit module correlation |

---

## 🗂️ Project Structure

```text
NexShield/
├── run.py                     # ⭐ Main launcher — just run this!
├── app.py                     # Flask backend — API routes, WebSocket, auth
├── config.py                  # Database config (TinyDB/MongoDB auto-detection)
├── ai_logic.py                # 16-engine AI analysis pipeline & ML training
├── scanner.py                 # Network scanning engine (Nmap wrapper)
├── cve_lookup.py              # CVE database and NVD API integration
├── exploit_cli.py             # CLI for exploit RC script generation
├── msf_rpc.py                 # Metasploit RPC client (optional)
├── wsgi.py                    # Production WSGI entry point
├── requirements.txt           # Core Python dependencies
├── requirements-optional.txt  # Advanced/optional dependencies
├── .env.example               # Configuration template
├── install.bat                # Windows installer
├── install.sh                 # Linux/macOS installer
├── data/                      # Database files (auto-created)
│   └── nexshield_db.json      # TinyDB database
├── templates/
│   └── login.html             # Authentication page
└── static/
    ├── css/style.css           # UI design system
    └── js/script.js            # Dashboard logic
```

---

## 🔧 Troubleshooting

### "pip install fails"

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# If scikit-learn fails on Windows, try:
pip install scikit-learn --only-binary=:all:

# Or install core packages individually:
pip install flask tinydb flask-socketio flask-cors python-dotenv requests
```

### "Nmap not found"

NexShield works without nmap, but scanning requires it:

- **Windows:** Download from [nmap.org](https://nmap.org/download.html), add to PATH
- **Linux:** `sudo apt install nmap`
- **macOS:** `brew install nmap`

### "Database error"

The built-in TinyDB database should work automatically. If you see errors:

```bash
# Reset the database
python run.py --reset-db

# Restart
python run.py
```

### "Port 5000 already in use"

```bash
# Use a different port
python run.py --port 8080
```

---

## 🔒 Advanced: Using MongoDB (Optional)

If you prefer MongoDB over the built-in TinyDB:

1. Install MongoDB: [mongodb.com/docs](https://www.mongodb.com/docs/manual/installation/)
2. Install the Python driver:
   ```bash
   pip install -r requirements-optional.txt
   ```
3. Edit `.env`:
   ```ini
   MONGO_URI=mongodb://localhost:27017/
   MONGO_DB=threat_intel
   ```
4. Restart NexShield — it will auto-detect and use MongoDB.

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
| --- | --- |
| `S` | Focus scan target input |
| `A` | Run AI analysis pipeline |
| `T` | Train / optimize AI model |
| `R` | Refresh all dashboard data |
| `?` | Show shortcuts help panel |
| `Esc` | Close modal / dismiss |

---

## 🔒 Ethical Notice

This software is intended for **authorized security testing and research only**. Unauthorized use against targets without prior written consent is strictly prohibited and may violate applicable laws. Always obtain proper authorization before conducting any security assessment.

---

## Recent Improvements

- **Zero-install database**: TinyDB replaces MongoDB as default — no database server needed
- **Local-only authentication**: Auto-provisioned admin account, no registration required
- **Unified CLI launcher**: `python run.py` auto-configures and starts everything
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Simplified install**: `install.bat` / `install.sh` handle everything
- **Auto-config**: `.env` file auto-created on first run with sensible defaults
