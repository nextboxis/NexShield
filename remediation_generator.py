"""
remediation_generator.py — One-Click Automated Remediation Code Generator for NexShield

Generates automated remediation & hardening scripts in Ansible (.yml),
PowerShell (.ps1), and Bash (.sh) formats based on detected threats.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Remediation database mapping vulnerability signatures to automated fixes
REMEDIATION_DB: dict[str, dict[str, Any]] = {
    "smb": {
        "title": "Disable Insecure SMBv1 and Restrict SMB Access",
        "ansible": [
            "- name: Disable SMBv1 feature on Windows",
            "  ansible.windows.win_optional_feature:",
            "    name: SMB1Protocol",
            "    state: absent",
            "- name: Enforce SMB Signing",
            "  ansible.windows.win_regedit:",
            "    path: HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "    name: RequireSecuritySignature",
            "    data: 1",
            "    type: dword",
        ],
        "powershell": [
            "# Disable SMBv1 Protocol",
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -Value 1",
        ],
        "bash": [
            "# Restrict SMB / Samba access via UFW firewall",
            "sudo ufw deny 445/tcp",
            "sudo ufw deny 139/tcp",
        ],
    },
    "telnet": {
        "title": "Disable Telnet Service & Enforce SSH",
        "ansible": [
            "- name: Stop and disable Telnet service",
            "  ansible.builtin.service:",
            "    name: telnet",
            "    state: stopped",
            "    enabled: false",
            "  ignore_errors: true",
        ],
        "powershell": [
            "# Remove Telnet Client and Server features",
            "Disable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart",
            "Stop-Service -Name 'tlntsvr' -ErrorAction SilentlyContinue",
            "Set-Service -Name 'tlntsvr' -StartupType Disabled -ErrorAction SilentlyContinue",
        ],
        "bash": [
            "# Stop & disable Telnet and block port 23",
            "sudo systemctl stop inetd 2>/dev/null || true",
            "sudo systemctl disable telnetd 2>/dev/null || true",
            "sudo ufw deny 23/tcp",
        ],
    },
    "http": {
        "title": "Upgrade HTTP to HTTPS & Enforce Security Headers",
        "ansible": [
            "- name: Ensure HTTPS redirection is enabled in Nginx/Apache",
            "  ansible.builtin.lineinfile:",
            "    path: /etc/nginx/sites-available/default",
            "    regexp: '^\\s*listen 80;'",
            "    line: '    listen 80 default_server; return 301 https://$host$request_uri;'",
            "  ignore_errors: true",
        ],
        "powershell": [
            "# Enable HTTP to HTTPS Redirection in IIS",
            "Import-Module WebAdministration -ErrorAction SilentlyContinue",
            "Set-WebConfigurationProperty -Filter 'system.webServer/httpRedirect' -Name 'enabled' -Value $true -ErrorAction SilentlyContinue",
        ],
        "bash": [
            "# Close unencrypted port 80 or enforce redirect",
            "sudo ufw allow 443/tcp",
            "echo '[+] Ensure Web Server configuration redirects port 80 to 443 (TLS).'",
        ],
    },
    "default_credentials": {
        "title": "Enforce Authentication & Change Default Passwords",
        "ansible": [
            "- name: Ensure root remote login is disabled in SSH",
            "  ansible.builtin.lineinfile:",
            "    path: /etc/ssh/sshd_config",
            "    regexp: '^PermitRootLogin'",
            "    line: 'PermitRootLogin no'",
            "  notify: restart ssh",
        ],
        "powershell": [
            "# Enforce Strong Password Policy on Local Accounts",
            "net accounts /minpwlen:12 /maxpwage:90 /unique:5",
        ],
        "bash": [
            "# Enforce SSH hardening & disable password login for root",
            "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sudo systemctl restart sshd || sudo systemctl restart ssh",
        ],
    },
    "encryption": {
        "title": "Disable Weak Cryptographic Ciphers & TLS 1.0/1.1",
        "ansible": [
            "- name: Disable TLS 1.0 and 1.1 in Crypto Policies",
            "  ansible.builtin.command:",
            "    cmd: update-crypto-policies --set DEFAULT:NO-SHA1",
            "  ignore_errors: true",
        ],
        "powershell": [
            "# Disable TLS 1.0 and TLS 1.1 in Registry",
            "New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force | Out-Null",
            "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0 -PropertyType DWORD -Force | Out-Null",
        ],
        "bash": [
            "# Restrict SSH to strong ciphers",
            "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' | sudo tee -a /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ],
    },
}

# Generic fallback fix generator
GENERIC_FIX = {
    "ansible": [
        "- name: Apply Security Update for Discovered Vulnerability",
        "  ansible.builtin.package:",
        "    name: '*'",
        "    state: latest",
    ],
    "powershell": [
        "# Install latest Security Updates via Windows Update",
        "Install-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue",
        "Get-WindowsUpdate -AcceptAll -Install -AutoReboot",
    ],
    "bash": [
        "# Update system security packages and apply patches",
        "sudo apt-get update && sudo apt-get upgrade -y --only-upgrade",
    ],
}


def _match_remediation_keys(threat: dict) -> list[str]:
    """Extract relevant database remediation keys matching a threat item."""
    name = str(threat.get("name") or "").lower()
    detail = str(threat.get("detail") or "").lower()
    tags = [str(t).lower() for t in threat.get("tags") or []]
    source = str(threat.get("source") or "").lower()

    combined = f"{name} {detail} {' '.join(tags)} {source}"
    matched = []

    if "smb" in combined or "445" in combined or "ms17-010" in combined:
        matched.append("smb")
    if "telnet" in combined or "port 23" in combined:
        matched.append("telnet")
    if "default" in combined or "cred" in combined or "password" in combined:
        matched.append("default_credentials")
    if "encryption" in combined or "plain" in combined or "tls" in combined or "http without" in combined:
        matched.append("encryption")
        if "http" in combined:
            matched.append("http")
    elif "http" in combined or "port 80" in combined:
        matched.append("http")

    return list(dict.fromkeys(matched))


def generate_remediation_script(threats: list[dict], target_host: str, fmt: str = "ansible") -> str:
    """
    Generate an automated remediation script in the requested format (ansible, powershell, or bash).
    Leverages RAG intelligence to dynamically generate customized playbooks, falling back
    to static templates if RAG context is unavailable.
    """
    fmt = (fmt or "ansible").strip().lower()
    if fmt not in ("ansible", "powershell", "bash"):
        fmt = "ansible"

    target_host = target_host or "127.0.0.1"

    # Attempt dynamic RAG remediation synthesis first
    try:
        from rag_engine import rag_generator  # type: ignore
        rag_script = rag_generator.generate_dynamic_remediation(target_host, threats, fmt=fmt)
        if rag_script and len(rag_script.splitlines()) > 10:
            return rag_script
    except Exception as exc:
        logger.debug(f"RAG dynamic remediation fallback to static DB: {exc}")

    # Fallback to static rules
    matched_keys = []
    for threat in threats:
        keys = _match_remediation_keys(threat)
        matched_keys.extend(keys)

    matched_keys = list(dict.fromkeys(matched_keys))

    if fmt == "ansible":
        return _generate_ansible(threats, target_host, matched_keys)
    elif fmt == "powershell":
        return _generate_powershell(threats, target_host, matched_keys)
    else:
        return _generate_bash(threats, target_host, matched_keys)


def _generate_ansible(threats: list[dict], target_host: str, matched_keys: list[str]) -> str:
    lines = [
        "---",
        f"# NexShield Auto-Generated Ansible Remediation Playbook",
        f"# Target Host: {target_host}",
        f"# Total Threats Addressed: {len(threats)}",
        " - name: Auto-Remediate Discovered Security Vulnerabilities",
        f"  hosts: {target_host}",
        "  become: true",
        "  tasks:",
    ]

    if not matched_keys:
        for task in GENERIC_FIX["ansible"]:
            lines.append(f"    {task}")
    else:
        for key in matched_keys:
            data = REMEDIATION_DB[key]
            lines.append(f"    # --- {data['title']} ---")
            for task in data["ansible"]:
                lines.append(f"    {task}")

    return "\n".join(lines)


def _generate_powershell(threats: list[dict], target_host: str, matched_keys: list[str]) -> str:
    lines = [
        f"# ===========================================================================",
        f"# NexShield Auto-Generated PowerShell Hardening Script",
        f"# Target Host: {target_host}",
        f"# Total Threats Addressed: {len(threats)}",
        f"# ===========================================================================",
        "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force",
        "",
    ]

    if not matched_keys:
        lines.extend(GENERIC_FIX["powershell"])
    else:
        for key in matched_keys:
            data = REMEDIATION_DB[key]
            lines.append(f"# --- {data['title']} ---")
            lines.extend(data["powershell"])
            lines.append("")

    lines.append("Write-Host '[+] NexShield PowerShell Remediation Script Completed.' -ForegroundColor Green")
    return "\n".join(lines)


def _generate_bash(threats: list[dict], target_host: str, matched_keys: list[str]) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# ===========================================================================",
        f"# NexShield Auto-Generated Bash Remediation Script",
        f"# Target Host: {target_host}",
        f"# Total Threats Addressed: {len(threats)}",
        "# ===========================================================================",
        "set -euo pipefail",
        "",
        "echo '[*] Starting NexShield Automated Hardening Tasks...'",
        "",
    ]

    if not matched_keys:
        lines.extend(GENERIC_FIX["bash"])
    else:
        for key in matched_keys:
            data = REMEDIATION_DB[key]
            lines.append(f"# --- {data['title']} ---")
            lines.extend(data["bash"])
            lines.append("")

    lines.append("echo '[+] NexShield Bash Remediation Completed Successfully.'")
    return "\n".join(lines)
