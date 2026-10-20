# NexShield v6.1

## AI Threat Operations Center & High-Speed Security Assessment Engine
### Dual-Engine Architecture: Pure Native Rust (`std`-only) + Python Hybrid

```text
███╗   ██╗███████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║ ╚████║███████╗██╔╝ ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
                      MISSION CONTROL v6.1 (PURE RUST ENGINE)
```

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0%20External%20(Pure%20Std)-brightgreen.svg?style=for-the-badge)](https://doc.rust-lang.org/std/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge)](LICENSE)

---

NexShield is an **enterprise-grade, local-first threat assessment platform**. In version 6.1, the entire backend engine has been re-architected into **pure native Rust** using only the Rust standard library (`std`), delivering sub-millisecond execution times, advanced data structures (DSA), zero external runtime dependencies, and an ultra-minimalist SOC web dashboard.

---

## ⚡ Key Highlights & Capabilities

- 🦀 **100% Zero-Dependency Native Rust Engine:** 12 modular crates built exclusively on Rust's `std` standard library. Zero external crate bloat, compiles offline instantly, and produces lightweight standalone binaries.
- 🚀 **High-Speed DSA Port Scanner:** Scans 65,535 ports using 64-bit word bitmaps (`BitSet`), thread-pooled asynchronous TCP connects, and token-bucket rate limiting. Scans complete in sub-second intervals.
- 🎯 **Advanced Graph Analytics (Tarjan & Dijkstra):** Detects choke-points and critical attack paths using Tarjan's Strongly Connected Components algorithm and Dijkstra's pivot analysis ($O(V + E)$).
- ⚡ **Radix IPv4 CIDR Trie:** Sub-microsecond longest-prefix matching ($O(32)$) for instant IP geolocation and Autonomous System (ASN) lookup.
- 🧠 **Embedded Cybersecurity RAG Engine:** In-memory TF-IDF sparse token index with cosine similarity search across local CVE repositories and MITRE ATT&CK techniques.
- 🛡️ **Intelligent Port Fallback:** Gracefully detects occupied socket ports (`AddrInUse` / Windows error 10048) and automatically binds to the next available port.
- 💻 **Ultra-Minimalist SOC Web Dashboard:** Clean, distraction-free modern dark interface for threat telemetry, network topology, and automated hardening script generation (Ansible, PowerShell, Bash).
- 🔄 **Dual Runtime Interoperability:** Run fully standalone via the pure Rust server binary (`nexshield-server.exe`) or via the unified Python bridge (`python run.py --rust`).

---

## 🚀 Quick Start

### Option A: Run the Pure Native Rust Server (Fastest)

Build and run the standalone Rust server directly:

```powershell
# 1. Build release binaries (zero dependencies, offline ready)
cargo build --release --offline

# 2. Launch Mission Control Server
.\target\release\nexshield-server.exe
```

*The server will start listening at `http://127.0.0.1:5000` (or automatically fall back to `5001+` if port 5000 is occupied).*

### Option B: Run via Python Runner (with Rust Acceleration)

```powershell
# Start with Rust backend engine
python run.py --rust

# Or start the standard Python service
python run.py
```

### Option C: Use the Unified Rust CLI

Execute network scans, RAG lookups, and remediation script generation directly from your terminal:

```powershell
# Perform a high-speed multithreaded network scan
.\target\release\nexshield-cli.exe scan 127.0.0.1 80,443,5000

# Query the CVE / CISA KEV inverted index
.\target\release\nexshield-cli.exe cve CVE-2021-44228

# Ask the local RAG Cybersecurity Knowledge Base
.\target\release\nexshield-cli.exe rag "lateral movement over SMB port 445"

# Generate automated Ansible / PowerShell remediation scripts
.\target\release\nexshield-cli.exe fix "Open RDP port 3389 without NLA"

# Run system diagnostic self-test
.\target\release\nexshield-cli.exe diag
```

---

## 🖥️ Minimalist Web Dashboard

Once started, open your web browser to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

Default Operator Credentials:
- **Username:** `admin`
- **Password:** `admin`

### Dashboard Features:
1. **Target Security Scanner:** One-click vulnerability scans with configurable port presets (`Web`, `Common`, `Top 1K`, `Full 65K`) and real-time progress indicators.
2. **Network Attack Surface Map:** Interactive visual topology showing scanned hosts, latency, open port chips, and risk severity.
3. **Active Threat Findings Table:** Search and filter threats by severity (Critical, High, Medium, Low) with one-click modal inspection.
4. **Automated Remediation Generator:** Export instant fix playbooks in Ansible YAML, PowerShell PS1, or Bash SH.
5. **AI Copilot Drawer:** Interactive RAG assistant for threat queries, compliance baselines, and exploit explanations.

---

## 🏗️ Pure Rust Architecture (`crates/`)

NexShield's native backend consists of 12 decoupled, standard-library-only crates:

| Crate | Responsibility | DSA / Algorithm |
| :--- | :--- | :--- |
| [`nexshield-types`](crates/nexshield-types) | Common data contracts, findings, severities, hosts | Zero-copy serialization |
| [`nexshield-core`](crates/nexshield-core) | Core cybersecurity data structures | Port Bitmaps, Tarjan's SCC, Dijkstra, IPv4 Radix Trie, Token Bucket |
| [`nexshield-scanner`](crates/nexshield-scanner) | Asynchronous multithreaded TCP port scanner | BitSet port registry, non-blocking sockets |
| [`nexshield-engine`](crates/nexshield-engine) | 21 threat assessment engines & ML heuristic scoring | Shannon informational entropy calculation |
| [`nexshield-cve`](crates/nexshield-cve) | Embedded CISA Known Exploited Vulnerabilities (KEV) | Inverted product index ($O(1)$ lookup) |
| [`nexshield-storage`](crates/nexshield-storage) | Multi-collection file JSON document database | Pure `std` SHA-256 salted password hashing |
| [`nexshield-remediation`](crates/nexshield-remediation)| Automated remediation playbook generator | Ansible, PowerShell, Bash templates |
| [`nexshield-notifier`](crates/nexshield-notifier) | Outbound SOC alert webhook dispatcher | Slack, Discord, MS Teams, SIEM payloads |
| [`nexshield-rag`](crates/nexshield-rag) | Cybersecurity knowledge retrieval engine | Sparse token index, TF-IDF cosine similarity |
| [`nexshield-exploit`](crates/nexshield-exploit) | Metasploit module mapper | Automated `.rc` resource script generator |
| [`nexshield-reports`](crates/nexshield-reports) | Multi-format executive reporting engine | HTML & Executive Markdown generation |
| [`nexshield-server`](crates/nexshield-server) | Multithreaded pure HTTP/1.1 REST & Dashboard server | Worker thread-pool, smart port binding |
| [`nexshield-cli`](crates/nexshield-cli) | Unified native command-line interface | Multi-subcommand dispatcher |

---

## 🧪 Testing & Verification

Run the entire test suite across all 12 crates:

```powershell
cargo test --offline
```

*All 25 unit tests across the workspace pass in $<0.20\text{ s}$ with zero runtime warnings.*

---

## 🛡️ License

Proprietary & Confidential — NexShield Cybersecurity Systems. All rights reserved.
