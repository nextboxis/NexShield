<div align="center">

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
[![MongoDB](https://img.shields.io/badge/MongoDB-Database-47A248.svg?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-AI_Engine-F7931E.svg?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge)](LICENSE)

</div>

---

# 🛡️ NexShield v5

### AI-Powered Threat Intelligence & SOC Mission Control

NexShield v5 is a professional-grade cybersecurity platform that bridges the gap between raw vulnerability data and actionable intelligence. It transforms network reconnaissance into an **"Intelligence-to-Action"** mission workflow — scanning targets, analyzing findings with a 16-engine AI pipeline, correlating exploits from Metasploit, and generating executive-ready pentest reports.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Mission Control HUD** | Real-time SOC dashboard with animated topology map, severity radar, and 7-day incident timeline |
| **16-Engine AI Pipeline** | Automated threat detection covering CVE correlation, default credentials, SSL/TLS audit, lateral movement, zero-day heuristics, and more |
| **ML Threat Prediction** | Ensemble model (Random Forest + Gradient Boosting) trained on your scan data to predict threat severity |
| **Metasploit Integration** | Automatic exploit module mapping with one-click RC script generation and live exploit launch via RPC |
| **Multi-Scan Types** | Quick, Default, Deep, Stealth, OS Detect, Vuln Scripts, SSL/TLS, UDP, and Full port scanning |
| **Pentest Reporting** | Full intelligence report with executive summary, risk matrix, remediation roadmap, and topology visualization |
| **Real-time WebSocket** | Live scan progress, analysis status, and threat notifications via Socket.IO |
| **CVE Intelligence** | Built-in CVE lookup with NVD integration and local caching |
| **Host Quarantine** | Zero-trust isolation of compromised nodes with automatic threat remediation |
| **Export & Automation** | CSV/JSON export, downloadable Metasploit RC scripts, and keyboard shortcuts |

---

## 📋 Prerequisites

Before installing NexShield, ensure these are available on your system:

| Dependency | Purpose | Install Guide |
|-----------|---------|---------------|
| **Python 3.9+** | Runtime | [python.org](https://www.python.org/downloads/) |
| **MongoDB 6.0+** | Threat & scan data storage | [mongodb.com/docs](https://www.mongodb.com/docs/manual/installation/) |
| **Nmap 7.80+** | Network scanning engine | [nmap.org](https://nmap.org/download.html) |
| **Metasploit** *(optional)* | Exploit execution via RPC | [metasploit.com](https://www.metasploit.com/) |

> **Note:** `python-nmap` is a Python wrapper — it requires the `nmap` binary installed and accessible in your system `PATH`.

---

## 🚀 Quick Start

### The Easy Way (Automated Setup)

**Windows:**
Double-click `install.bat` or run it from the command line:
```cmd
install.bat
```

**Linux / macOS:**
Make the script executable and run it:
```bash
chmod +x install.sh
./install.sh
```

### The Manual Way

```bash
# 1. Clone the repository
git clone https://github.com/your-org/nexshield-v5.git
cd nexshield-v5

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Start MongoDB (if not running as a service)
mongod --dbpath /data/db

# 5. Launch NexShield
python app.py
```

Open your browser to **http://localhost:5000** to access Mission Control.

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string |
| `WS_TOKEN` | *(auto-generated)* | WebSocket authentication token. If not set, a secure random token is generated at startup |

Set these before running `app.py`:

```bash
export MONGO_URI="mongodb://localhost:27017/"
export WS_TOKEN="your-secret-token"    # Optional
```

---

## 🗂️ Project Structure

```
nexshield-v5/
├── app.py                  # Flask backend — API routes, WebSocket, background tasks
├── ai_logic.py             # 16-engine AI analysis pipeline & ML model training
├── config.py               # MongoDB connection management & configuration
├── msf_rpc.py              # Metasploit RPC client for exploit execution
├── exploit_cli.py          # CLI interface for exploit operations
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   ├── index.html          # Mission Control dashboard
│   └── report.html         # Pentest intelligence report
└── static/
    ├── css/
    │   └── style.css       # Complete UI design system
    └── js/
        └── script.js       # Dashboard logic, charts, real-time updates
```

---

## 🧠 AI Analysis Engines

NexShield's analysis pipeline runs **16 independent engines** against scan data:

| # | Engine | Detection Scope |
|---|--------|----------------|
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

## 🗺️ Strategic Roadmap

### 🟢 Phase 1: Foundation — *Complete*
- [x] Real-time SOC Mission Control HUD
- [x] Multi-engine vulnerability correlation (Nmap, CVE-DB)
- [x] Canvas-rendered topology map and severity radar

### 🟡 Phase 2: Weaponization — *Complete*
- [x] Intelligence-to-Action: Automatic Metasploit module mapping
- [x] Fluid Reporting: SOC-grade responsive reporting engine
- [x] RC script generation and preview

### 🟠 Phase 3: Automation — *Active*
- [x] Direct Launch: Trigger exploits directly from the HUD
- [x] Pivoting Engine: Visual lateral movement paths
- [ ] AI-Guided Engagement: Automated decision support
- [ ] Scheduled scanning and continuous monitoring

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `S` | Focus scan target input |
| `A` | Run AI analysis pipeline |
| `T` | Train / optimize AI model |
| `R` | Refresh all dashboard data |
| `?` | Show shortcuts help panel |
| `Esc` | Close modal / dismiss |

---

## 🔒 Ethical Notice

> **This software is intended for authorized security testing and research only.**
> Unauthorized use against targets without prior written consent is strictly prohibited and may violate applicable laws. Always obtain proper authorization before conducting any security assessment.

---

<div align="center">
<strong>NexShield Core v5.0 — Mission Ready.</strong>
</div>
\n## Recent Improvements\n- Added API endpoints: POST /api/analyze, POST /api/train, GET /api/threat/<id> for on-demand analysis, training, and single-threat fetch.\n- Normalized threat hashing and severity handling in i_logic.py to improve deduplication accuracy.\n- Imported MSF_MAPPINGS in pp.py and enriched threat responses with exploit_module.\n\n
