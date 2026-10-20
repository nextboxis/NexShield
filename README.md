# NexShield v6.1

## AI Threat Operations Center & High-Speed Security Assessment Engine
### 100% Pure Native Rust Architecture (`std`-only, Zero Python Runtime Dependencies)

```text
███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
                 MISSION CONTROL v6.1 (100% PURE RUST)
```

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0%20External%20(Pure%20Std)-brightgreen.svg?style=for-the-badge)](https://doc.rust-lang.org/std/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge)](LICENSE)

---

NexShield is an **enterprise-grade, local-first threat assessment platform & AI Security Operations Center (SOC)**. In version 6.1, the entire system has been converted to **100% pure native Rust** using exclusively the Rust standard library (`std`). It delivers microsecond-level execution times, native computer science data structures (DSA), zero external runtime dependencies, standalone compilation, and a sleek, minimalist SOC mission control web interface.

---

## ⚡ Key Architectural Capabilities

- 🦀 **100% Pure Native Rust Core (13 Crates):** Built exclusively on Rust's `std` library without any third-party crate dependencies. Compiles offline instantaneously to standalone single binaries.
- 🚀 **High-Speed DSA Port Scanner:** Scans 65,535 ports using 64-bit word bitmaps (`PortBitmap`), non-blocking TCP socket connect loops, and token-bucket rate limiting ($O(1)$ operations).
- 🎯 **Advanced Graph Analytics (Tarjan & Dijkstra):** Detects choke-points and critical attack paths using Tarjan's Strongly Connected Components algorithm and Dijkstra's pivot analysis ($O(V + E)$).
- ⚡ **Radix IPv4 CIDR Trie:** Sub-microsecond longest-prefix matching ($O(32)$) for instant offline IP geolocation and Autonomous System (ASN) lookup.
- 🧠 **Embedded Cybersecurity RAG Engine:** In-memory TF-IDF sparse token index with cosine similarity search across local CVE repositories and MITRE ATT&CK techniques.
- 🛡️ **Intelligent Port Conflict Resolver:** Automatically handles occupied ports (`AddrInUse` / Windows error 10048) by probing and falling back to sequential available ports (`5000 -> 5001+`).
- 💻 **Ultra-Minimalist SOC Web Dashboard:** Clean, responsive, distraction-free modern dark interface for threat telemetry, network topology, and automated hardening script generation (Ansible, PowerShell, Bash).
- 🔄 **Unified Transparent Launching:** Run directly via `run.bat`, the native binary `nexshield-cli.exe`, or via the zero-dependency Python forwarder `python run.py`.

---

## 🚀 Quick Start

### 1. Launch Mission Control Server

Simply double-click or run:

```powershell
# Windows Batch Launcher:
.\run.bat

# Or direct native binary:
.\target\release\nexshield-cli.exe run

# Or via zero-dependency Python forwarder:
python run.py
```

*The server will start listening at `http://127.0.0.1:5000` (or automatically fall back to `5001+` if 5000 is occupied).*

### 2. Pre-Flight Health Checks & Self-Tests

Verify system readiness and run all embedded algorithmic diagnostic tests in $<0.01\text{ s}$:

```powershell
# Pre-flight system checks:
.\target\release\nexshield-cli.exe check

# Run all 6 critical DSA subsystem self-tests:
.\target\release\nexshield-cli.exe self-test
```

### 3. ML Model Calibration & Knowledge Indexing

```powershell
# Calibrate native ML threat severity predictor across 5,000 samples:
.\target\release\nexshield-cli.exe train 5000

# Stream-ingest CVE records into inverted index:
.\target\release\nexshield-cli.exe import-cve cve_data 5000
```

### 4. Interactive Command-Line Security Operations

```powershell
# High-speed native port scan:
.\target\release\nexshield-cli.exe scan 127.0.0.1 80,443,5000,8080

# Offline IP geolocation & ASN lookup:
.\target\release\nexshield-cli.exe geo 8.8.8.8

# Offline CVE and CISA KEV query:
.\target\release\nexshield-cli.exe cve CVE-2021-44228

# Query Cybersecurity RAG knowledge base:
.\target\release\nexshield-cli.exe rag "SMB EternalBlue remote code execution"

# Generate automated system hardening scripts (bash, powershell, ansible):
.\target\release\nexshield-cli.exe fix smb powershell
.\target\release\nexshield-cli.exe fix rdp ansible

# Generate Metasploit verification script:
.\target\release\nexshield-cli.exe msf smb 192.168.1.100

# Generate compliance and risk reports (HTML, Markdown, SARIF):
.\target\release\nexshield-cli.exe report 127.0.0.1 html

# Run internal DSA diagnostics:
.\target\release\nexshield-cli.exe diag
```

---

## 🖥️ Modern Minimalist Web Dashboard

Once launched, navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

Default Operator Credentials:
- **Username:** `admin`
- **Password:** `admin`

### Dashboard Capabilities:
1. **Target Security Scanner:** Real-time multi-threaded port scans with configurable port presets (`Web`, `Common`, `Top 1K`, `Full 65K`).
2. **Network Attack Surface Map:** Interactive visual topology showing scanned hosts, latency, open port chips, and risk severity.
3. **Active Threat Findings Table:** Search and filter threats by severity (Critical, High, Medium, Low) with one-click modal inspection.
4. **Automated Remediation Generator:** Export instant fix playbooks in Ansible YAML, PowerShell PS1, or Bash SH.
5. **AI Copilot Drawer:** Interactive RAG assistant for threat queries, compliance baselines, and exploit explanations.

---

## 🏗️ 100% Pure Rust Architecture (`crates/`)

NexShield's native backend consists of 13 decoupled, standard-library-only crates:

| Crate | Responsibility | Key Algorithms / Data Structures |
| :--- | :--- | :--- |
| [`nexshield-types`](crates/nexshield-types) | Common data contracts, findings, severities, hosts | Zero-copy serializable structs |
| [`nexshield-core`](crates/nexshield-core) | Core cybersecurity data structures | 65,536-bit `PortBitmap`, `IpRadixTrie` ($O(1)$ LPM), `AttackGraph` (Tarjan SCC & Dijkstra), `TokenBucket` |
| [`nexshield-scanner`](crates/nexshield-scanner) | Asynchronous multithreaded TCP port scanner | Thread-pooled non-blocking socket connect loops |
| [`nexshield-engine`](crates/nexshield-engine) | 21 threat assessment engines & ML heuristic scoring | Shannon entropy, Naive Bayes threat classifier, offline IP geo |
| [`nexshield-cve`](crates/nexshield-cve) | Embedded CISA Known Exploited Vulnerabilities (KEV) | Inverted product index & streaming JSON importer |
| [`nexshield-storage`](crates/nexshield-storage) | Multi-collection file JSON document database | Pure `std` SHA-256 salted password hashing & query engine |
| [`nexshield-remediation`](crates/nexshield-remediation)| Automated remediation playbook generator | Ansible, PowerShell, Bash templates |
| [`nexshield-notifier`](crates/nexshield-notifier) | Outbound SOC alert webhook dispatcher | Slack, Discord, MS Teams, SIEM payloads |
| [`nexshield-rag`](crates/nexshield-rag) | Cybersecurity knowledge retrieval engine | Sparse token index, TF-IDF cosine similarity |
| [`nexshield-exploit`](crates/nexshield-exploit) | Metasploit module mapper | Automated `.rc` resource script generator |
| [`nexshield-reports`](crates/nexshield-reports) | Multi-format executive reporting engine | HTML, Executive Markdown, and SARIF v2.1.0 generation |
| [`nexshield-server`](crates/nexshield-server) | Multithreaded pure HTTP/1.1 REST & Dashboard server | Worker thread-pool, smart port binding (`5000 -> 5001+`) |
| [`nexshield-cli`](crates/nexshield-cli) | Unified native command-line interface | Multi-subcommand dispatcher replacing legacy python scripts |

---

## 🧪 Testing & Verification

Run the entire offline test suite across all 13 crates:

```powershell
cargo test --offline
```

*All 24 unit tests across the workspace pass in $<0.25\text{ s}$ with zero runtime warnings.*

---

## 🛡️ License

Proprietary & Confidential — NexShield Cybersecurity Systems. All rights reserved.
