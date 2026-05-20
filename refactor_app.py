import sys

def refactor():
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    # 1. Add import at the top
    if "from msf_utils import map_threat_to_module, generate_rc_script" not in content:
        content = content.replace(
            "from flask import Flask,",
            "from msf_utils import map_threat_to_module, generate_rc_script\nfrom flask import Flask,"
        )

    # 2. Replace get_threats logic
    old_threat_logic = """        module = None
        for keyword, mod in MSF_MAPPINGS.items():
            if keyword in name or keyword in detail or keyword in cve:
                module = mod
                break
        
        t_serialized["exploit_module"] = module"""
    
    new_threat_logic = """        t_serialized["exploit_module"] = map_threat_to_module(t)"""
    content = content.replace(old_threat_logic, new_threat_logic)
    
    # 3. Replace MSF_MAPPINGS & EXPLOIT_DATABASE
    # Find start and end of EXPLOIT_DATABASE and MSF_MAPPINGS
    import re
    # We remove everything from EXPLOIT_DATABASE = { down to cve-2021-44228": "exploit/multi/http/log4shell_header_injection",\n})
    # This is a large chunk.
    # Instead of regex, let's just find the indices.
    start_idx = content.find("EXPLOIT_DATABASE = {")
    end_idx = content.find('    "cve-2021-44228": "exploit/multi/http/log4shell_header_injection",\n})')
    if start_idx != -1 and end_idx != -1:
        end_idx += len('    "cve-2021-44228": "exploit/multi/http/log4shell_header_injection",\n})')
        content = content[:start_idx] + "# EXPLOIT_DATABASE and MSF_MAPPINGS have been moved to msf_utils.py\n" + content[end_idx:]

    # 4. Replace api_generate_exploit_rc logic
    old_rc_logic = """    rc_lines = [
        "# NexShield Auto-Generated Metasploit Script",
        f"# Targets: {host if host else 'All High/Critical Hosts'}",
        "spool msf_nexshield_session.log",
        "setg VERBOSE true",
        ""
    ]
    
    modules_added = set()
    for t in docs:
        t_host = t.get("host")
        detail = str(t.get("detail") or "").lower()
        name = str(t.get("name") or "").lower()
        cve = str(t.get("cve_id") or "").lower()
        
        module = None
        for keyword, mod in MSF_MAPPINGS.items():
            if keyword in detail or keyword in name or keyword in cve:
                module = mod
                break
        
        if not module:
            module = "auxiliary/scanner/portscan/tcp"
                
        if module:
            combo_key = f"{t_host}_{module}"
            if combo_key not in modules_added:
                rc_lines.extend([
                    f"# Target: {t_host} - {t.get('name')}",
                    f"use {module}",
                    f"set RHOSTS {t_host}",
                    "set LHOST eth0  # Update this if needed",
                    "exploit -j",
                    ""
                ])
                modules_added.add(combo_key)
                
    if not modules_added:
        msg = "[-] Could not map any discovered threats to known Metasploit modules."
        return jsonify({"status": "error", "message": msg}) if preview else (msg, 404)
        
    return jsonify({"status": "complete", "rc": "\\n".join(rc_lines), "modules": list(modules_added)}) if preview else Response("\\n".join(rc_lines), mimetype="text/plain")"""
    
    new_rc_logic = """    rc_content, modules_added = generate_rc_script(docs, host)
    
    if not modules_added:
        msg = "[-] Could not map any discovered threats to known Metasploit modules."
        return jsonify({"status": "error", "message": msg}) if preview else (msg, 404)
        
    return jsonify({"status": "complete", "rc": rc_content, "modules": list(modules_added)}) if preview else Response(rc_content, mimetype="text/plain")"""
    
    content = content.replace(old_rc_logic, new_rc_logic)

    with open("app.py", "w", encoding="utf-8") as f:
        f.write(content)

if __name__ == "__main__":
    refactor()
