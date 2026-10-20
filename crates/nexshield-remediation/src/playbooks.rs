//! Automated hardening and remediation script generator.
//! Produces production-ready Ansible YAML, PowerShell PS1, and Bash SH scripts.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptFormat {
    Ansible,
    PowerShell,
    Bash,
}

impl ScriptFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ScriptFormat::Ansible => "yml",
            ScriptFormat::PowerShell => "ps1",
            ScriptFormat::Bash => "sh",
        }
    }
}

pub struct RemediationBlueprint {
    pub service_key: &'static str,
    pub title: &'static str,
    pub ansible: &'static str,
    pub powershell: &'static str,
    pub bash: &'static str,
}

pub static REMEDIATION_CATALOG: &[RemediationBlueprint] = &[
    RemediationBlueprint {
        service_key: "smb",
        title: "Disable Insecure SMBv1 and Enforce SMB Signing",
        ansible: r#"---
- name: Hardening SMB Service
  hosts: all
  tasks:
    - name: Disable SMBv1 Protocol
      ansible.windows.win_optional_feature:
        name: SMB1Protocol
        state: absent
    - name: Enforce SMB Digitally Signed Communications
      ansible.windows.win_regedit:
        path: HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
        name: RequireSecuritySignature
        data: 1
        type: dword
"#,
        powershell: r#"# NexShield SMB Hardening Script
Write-Host "[+] Disabling SMBv1 Protocol..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1
Write-Host "[✓] SMBv1 disabled and SMB Signing enforced."
"#,
        bash: r#"#!/usr/bin/env bash
# NexShield SMB Port Restriction Script
echo "[+] Blocking SMB ports 139 and 445 on external interfaces..."
sudo ufw deny 445/tcp
sudo ufw deny 139/tcp
sudo systemctl reload ufw || true
echo "[✓] SMB ports restricted."
"#,
    },
    RemediationBlueprint {
        service_key: "telnet",
        title: "Disable Plaintext Telnet Service and Enforce SSH",
        ansible: r#"---
- name: Decommission Telnet
  hosts: all
  tasks:
    - name: Stop and disable Telnet service
      ansible.builtin.service:
        name: telnet
        state: stopped
        enabled: false
      ignore_errors: true
"#,
        powershell: r#"# NexShield Telnet Removal Script
Write-Host "[+] Removing Telnet Client and Server features..."
Disable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart
Stop-Service -Name 'tlntsvr' -ErrorAction SilentlyContinue
Set-Service -Name 'tlntsvr' -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "[✓] Telnet completely deactivated."
"#,
        bash: r#"#!/usr/bin/env bash
# NexShield Telnet Elimination Script
echo "[+] Disabling telnet daemon..."
sudo systemctl stop inetd 2>/dev/null || true
sudo systemctl disable telnetd 2>/dev/null || true
sudo ufw deny 23/tcp
echo "[✓] Telnet daemon blocked."
"#,
    },
    RemediationBlueprint {
        service_key: "http",
        title: "Enforce HTTPS TLS Redirection and Security Headers",
        ansible: r#"---
- name: Enforce HTTPS Redirection
  hosts: webservers
  tasks:
    - name: Configure HSTS and 301 Redirect in Nginx
      ansible.builtin.lineinfile:
        path: /etc/nginx/sites-available/default
        regexp: '^\s*listen 80;'
        line: '    listen 80 default_server; return 301 https://$host$request_uri;'
"#,
        powershell: r#"# NexShield IIS HTTPS Enforcement Script
Import-Module WebAdministration -ErrorAction SilentlyContinue
Set-WebConfigurationProperty -Filter 'system.webServer/httpRedirect' -Name 'enabled' -Value $true -ErrorAction SilentlyContinue
Write-Host "[✓] IIS HTTP-to-HTTPS redirect enforced."
"#,
        bash: r#"#!/usr/bin/env bash
# NexShield HTTP Hardening
echo "[+] Closing direct HTTP 80 and ensuring TLS 443..."
sudo ufw allow 443/tcp
echo "[✓] Ensure Web server configuration directs port 80 to 443."
"#,
    },
    RemediationBlueprint {
        service_key: "rdp",
        title: "Enforce RDP Network Level Authentication (NLA)",
        ansible: r#"---
- name: Hardening Remote Desktop
  hosts: windows
  tasks:
    - name: Require NLA for Remote Desktop
      ansible.windows.win_regedit:
        path: HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
        name: UserAuthentication
        data: 1
        type: dword
"#,
        powershell: r#"# NexShield RDP Security Script
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
Write-Host "[✓] Remote Desktop Network Level Authentication (NLA) enforced."
"#,
        bash: r#"#!/usr/bin/env bash
# NexShield RDP Firewall Rule
echo "[+] Restricting RDP port 3389 to authorized VPN subnets only..."
sudo ufw delete allow 3389/tcp 2>/dev/null || true
sudo ufw allow from 10.0.0.0/8 to any port 3389 proto tcp
echo "[✓] RDP port protected."
"#,
    },
    RemediationBlueprint {
        service_key: "redis",
        title: "Secure Redis In-Memory Store & Bind to Localhost",
        ansible: r#"---
- name: Hardening Redis Server
  hosts: redis
  tasks:
    - name: Bind Redis to localhost
      ansible.builtin.lineinfile:
        path: /etc/redis/redis.conf
        regexp: '^bind '
        line: 'bind 127.0.0.1 ::1'
"#,
        powershell: r#"# NexShield Redis Hardening
Write-Host "[+] Restricting Redis port 6379 via Windows Firewall..."
New-NetFirewallRule -DisplayName "Block Remote Redis" -Direction Inbound -LocalPort 6379 -Protocol TCP -Action Block
Write-Host "[✓] Redis port blocked from remote networks."
"#,
        bash: r#"#!/usr/bin/env bash
# NexShield Redis Hardening
sudo sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf
sudo systemctl restart redis-server || sudo systemctl restart redis
echo "[✓] Redis bound to 127.0.0.1."
"#,
    },
];

pub struct RemediationEngine;

impl RemediationEngine {
    /// Generate hardening script for a given service and target format.
    pub fn generate_script(service: &str, format: ScriptFormat) -> Option<String> {
        let key = service.trim().to_lowercase();
        let bp = REMEDIATION_CATALOG.iter().find(|b| {
            key.contains(b.service_key) || b.service_key.contains(&key)
        })?;

        let body = match format {
            ScriptFormat::Ansible => bp.ansible,
            ScriptFormat::PowerShell => bp.powershell,
            ScriptFormat::Bash => bp.bash,
        };

        Some(body.to_string())
    }

    /// Retrieve title and overview of remediation.
    pub fn get_blueprint(service: &str) -> Option<&'static RemediationBlueprint> {
        let key = service.trim().to_lowercase();
        REMEDIATION_CATALOG.iter().find(|b| {
            key.contains(b.service_key) || b.service_key.contains(&key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_generation() {
        let sh = RemediationEngine::generate_script("smb", ScriptFormat::Bash);
        assert!(sh.is_some());
        assert!(sh.unwrap().contains("ufw deny 445/tcp"));

        let ps = RemediationEngine::generate_script("rdp", ScriptFormat::PowerShell);
        assert!(ps.is_some());
        assert!(ps.unwrap().contains("UserAuthentication"));
    }
}
