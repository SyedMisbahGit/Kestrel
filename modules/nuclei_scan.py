import subprocess
import json
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def run_nuclei(session, config):
    console.print("\n[bold blue]━━ PHASE 4: THE NUCLEI PIPELINE (CVE & MISCONFIG MAPPING) ━━[/bold blue]")

    targets = set()
    for h in session.get_live_hosts():
        if isinstance(h, dict) and 'url' in h: targets.add(h['url'])
        elif isinstance(h, str): targets.add(h)
    for u in session.get_crawled_urls():
        if isinstance(u, dict) and 'url' in u: targets.add(u['url'])
        elif isinstance(u, str): targets.add(u)

    if not targets:
        console.print("WARNING  No targets available for the Nuclei pipeline. Skipping.")
        return

    console.print(f"INFO     Piping {len(targets)} targets into Nuclei...")
    
    # Pre-Flight: Force Template Update to prevent blind failures
    console.print("INFO     Synchronizing Nuclei Templates...")
    subprocess.run(["nuclei", "-ut", "-silent"], capture_output=True)

    target_list = "\n".join(targets)
    
    # Added -as (Automatic Scan based on Wappalyzer) and lowered severity to include LOW
    cmd = [
        "nuclei", "-silent", "-json", 
        "-as", # Automatic Tech-based scan
        "-severity", "low,medium,high,critical",
        "-c", "50"
    ]

    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=target_list)

        # UN-BLINDING THE ENGINE: Catch silent binary crashes
        if stderr and "error" in stderr.lower():
            log.error(f"Nuclei Engine Error: {stderr.strip()}")

        vulns = []
        for line in stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                vulns.append(data)
                
                info = data.get('info', {})
                sev = info.get('severity', 'info').upper()
                name = info.get('name', 'Unknown')
                url = data.get('matched-at', '')
                color = "red" if sev in ["HIGH", "CRITICAL"] else "yellow" if sev == "MEDIUM" else "cyan"
                console.print(f"[{color}]  ! [{sev}] {name} -> {url}[/{color}]")
            except json.JSONDecodeError:
                pass

        if vulns:
            session.vulnerabilities.extend(vulns)
            console.print(f"  + Nuclei pipeline complete. {len(vulns)} vulnerabilities mapped into State Graph.")
        else:
            console.print("  + Nuclei pipeline complete. No automated vulnerabilities detected.")

    except Exception as e:
        log.error(f"Nuclei execution failed: {e}")
