# NexShield v5

## AI-Powered Threat Intelligence & SOC Mission Control

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

---

NexShield v5 is a professional-grade cybersecurity platform that bridges the gap between raw vulnerability data and actionable intelligence. It transforms network reconnaissance into an **Intelligence-to-Action** mission workflow — scanning targets, analyzing findings with a 16-engine AI pipeline, correlating exploits from Metasploit, and generating executive-ready pentest reports.

---

## ✨ Key Features

| Feature | Description |
| --- | --- |
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
| --- | --- | --- |
| **Python 3.9+** | Runtime | [python.org](https://www.python.org/downloads/) |
| **MongoDB 6.0+** | Threat & scan data storage | [mongodb.com/docs](https://www.mongodb.com/docs/manual/installation/) |
| **Nmap 7.80+** | Network scanning engine | [nmap.org](https://nmap.org/download.html) |
| **Metasploit** *(optional)* | Exploit execution via RPC | [metasploit.com](https://www.metasploit.com/) |

> **Note:** `python-nmap` is a Python wrapper — it requires the `nmap` binary installed and accessible in your system `PATH`.

---

## 🚀 Quick Start

### Automated Setup

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

### Manual Setup

1. Clone the repository:

```bash
git clone https://github.com/nextboxis/NexShield.git
cd NexShield
```

2. Create a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Start MongoDB (if not running as a service):

```bash
mongod --dbpath /data/db
```

5. Launch NexShield:

```bash
python app.py
```

Open your browser to [http://0.0.0.0:5000](http://0.0.0.0:5000) to access Mission Control.

---

## 🚨 Production Deployment

### Important: Development vs Production

The development server warning you see when running `python app.py` is a **Werkzeug security warning**. This server is designed for development only and should **NEVER** be used in production.

### Development Mode

Run the development server with:

```bash
# Windows
run_development.bat

# Linux/macOS
export FLASK_ENV=development
export FLASK_DEBUG=true
python app.py
```

### Production Mode

For production, you **must** use a production WSGI server like **Gunicorn** or **Waitress**.

**Option 1: Using Gunicorn** (Recommended)

```bash
# Windows
run_production.bat

# Linux/macOS
export FLASK_ENV=production
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 wsgi:app
```

**Option 2: Using Waitress**

```bash
waitress-serve --host=0.0.0.0 --port=5000 wsgi:app
```

**Option 3: Using uWSGI**

```bash
uwsgi --http 0.0.0.0:5000 --wsgi-file wsgi.py --callable app --processes 4 --threads 2
```

### Configuration for Production

1. Create `.env` file from template:

```bash
cp .env.example .env
```

2. Edit `.env` with your settings:

```ini
FLASK_ENV=production
FLASK_DEBUG=false
FLASK_SECRET_KEY=your-super-secret-key-change-this
ADMIN_PASSWORD=change-me-immediately
MONGO_URI=mongodb://user:password@your-mongo-host:27017/
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

3. Proxy Configuration (Nginx):

Place behind a reverse proxy for SSL/TLS termination:

```nginx
upstream nexshield {
    server 127.0.0.1:5000;
}

server {
    listen 443 ssl http2;
    server_name nexshield.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://nexshield;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_buffering off;
    }
}
```

### Performance Tuning

- **Worker processes**: Set to (2 × CPU cores) + 1
- **Timeout**: Increase to 180s for long scans
- **Database**: Ensure MongoDB indexes are optimized
- **Logging**: Redirect logs to a file, not stdout

---

## ⚙️ Environment Variables

| Variable | Default | Description | Required |
| --- | --- | --- | --- |
| `FLASK_ENV` | `development` | Environment mode: `development` or `production` | ✓ |
| `FLASK_DEBUG` | `false` | Enable debug mode (development only) | ✗ |
| `FLASK_SECRET_KEY` | *(auto-generated)* | Session encryption key - **MUST change in production** | ✓ |
| `ADMIN_PASSWORD` | `admin` | Default admin user password - **MUST change in production** | ✓ |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string | ✓ |
| `MONGO_DB` | `threat_intel` | Database name | ✓ |
| `PORT` | `5000` | Server listen port | ✗ |
| `ALLOWED_ORIGINS` | `http://127.0.0.1:5000,http://localhost:5000` | CORS allowed origins (comma-separated) | ✗ |
| `MSF_RPC_HOST` | `127.0.0.1` | Metasploit RPC host | ✗ |
| `MSF_RPC_PORT` | `55553` | Metasploit RPC port | ✗ |
| `LOG_LEVEL` | `INFO` | Logging level | ✗ |

Set these before running the application:

```bash
# Linux/macOS
export FLASK_ENV=production
export MONGO_URI="mongodb://your-host:27017/"

# Windows (PowerShell)
$env:FLASK_ENV="production"
$env:MONGO_URI="mongodb://your-host:27017/"
```

---

## 🗂️ Project Structure

```text
nexshield-v5/
├── app.py                  # Flask backend — API routes, WebSocket, background tasks
├── wsgi.py                 # Production WSGI entry point for Gunicorn/Waitress
├── config.py               # MongoDB connection management & configuration
├── ai_logic.py             # 16-engine AI analysis pipeline & ML model training
├── msf_rpc.py              # Metasploit RPC client for exploit execution
├── exploit_cli.py          # CLI interface for exploit operations
├── scanner.py              # Network scanning engine (Nmap wrapper)
├── cve_lookup.py           # CVE database and NVD API integration
├── requirements.txt        # Python dependencies (pinned to stable versions)
├── .env.example            # Environment variable template
├── run_production.bat       # Windows production startup script
├── run_development.bat      # Windows development startup script
├── install.bat             # Windows automated installation
├── install.sh              # Linux/macOS automated installation
├── README.md               # This file
├── SECURITY.md             # Security guidelines
├── templates/
│   ├── index.html          # Mission Control dashboard (WebSocket real-time)
│   ├── login.html          # Authentication page
│   └── report.html         # Pentest intelligence report (PDF export)
└── static/
    ├── css/
    │   └── style.css       # Complete UI design system with animations
    └── js/
        └── script.js       # Dashboard logic, charts, real-time updates
```

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

## 🗺️ Strategic Roadmap

### Phase 1: Foundation

- [x] Real-time SOC Mission Control HUD
- [x] Multi-engine vulnerability correlation (Nmap, CVE-DB)
- [x] Canvas-rendered topology map and severity radar

### Phase 2: Weaponization

- [x] Intelligence-to-Action: Automatic Metasploit module mapping
- [x] Fluid Reporting: SOC-grade responsive reporting engine
- [x] RC script generation and preview

### Phase 3: Automation

- [x] Direct Launch: Trigger exploits directly from the HUD
- [x] Pivoting Engine: Visual lateral movement paths
- [ ] AI-Guided Engagement: Automated decision support
- [ ] Scheduled scanning and continuous monitoring

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

This software is intended for authorized security testing and research only. Unauthorized use against targets without prior written consent is strictly prohibited and may violate applicable laws. Always obtain proper authorization before conducting any security assessment.

---

## Recent Improvements

- Added API endpoints: `POST /api/analyze`, `POST /api/train`, `GET /api/threat/<id>` for on-demand analysis and threat retrieval
- Improved threat deduplication and severity handling in `ai_logic.py`
- Imported `MSF_MAPPINGS` in `app.py` and enriched threat responses with `exploit_module` metadata
- Minor UI and report-generation fixes in `templates/report.html`
