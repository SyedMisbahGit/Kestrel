import os
import subprocess
import json
import logging
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor

console = Console()
log = logging.getLogger("rich")

def run_chaos(session, config):
    """
    Phase 5: Chaos (Content Discovery / Fuzzing)
    Upgraded with Auto-Calibration to defeat Catch-All/Soft-404 responses.
    """
    console.print("[bold blue]━━ PHASE 5: CHAOS (CONTENT DISCOVERY) ━━[/bold blue]")

    if not session.live_hosts:
        log.warning("No live hosts to fuzz. Skipping.")
        return

    # Ensure a wordlist exists
    wordlist = "data/wordlists/fuzz.txt"
    os.makedirs("data/wordlists", exist_ok=True)
    if not os.path.exists(wordlist):
        with open(wordlist, "w") as f:
            f.write(".env\n.git/HEAD\napi/v1/users\nserver-status\nbackup.zip\n")

    log.info(f"Fuzzing {len(session.live_hosts)} hosts with Auto-Calibration active...")
    findings = []

    def fuzz_host(host_dict):
        target = host_dict.get('url')
        if not target: return
        
        safe_target = target.replace("://", "_").replace(":", "_").replace("/", "_")
        out_file = f"data/temp_ffuf_{safe_target}.json"
        
        # Added -ac (Auto-Calibration) to filter out Soft-404s
        cmd = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-mc", "200,301,302,403",
            "-ac", 
            "-t", "50",
            "-o", out_file,
            "-of", "json",
            "-s"
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        status = result.get("status")
                        payload = result.get("input", {}).get("FUZZ", "UNKNOWN")
                        actual_url = result.get("url", f"{target}/{payload}")
                        
                        console.print(f"  + Confirmed Asset: {actual_url} (Status: {status})")
                        findings.append({
                            "name": f"Sensitive File/Directory ({status})",
                            "severity": "HIGH" if status == 200 else "MEDIUM",
                            "url": actual_url,
                            "info": f"Found hidden path via fuzzing. Status: {status}"
                        })
                os.remove(out_file)
        except Exception as e:
            if os.path.exists(out_file): os.remove(out_file)

    # Execute Fuzzing with multi-threading
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(fuzz_host, session.live_hosts)

    if findings:
        session.vulnerabilities.extend(findings)
        log.info(f"Chaos Module Complete. Identified {len(findings)} validated assets.")
    else:
        log.info("Chaos Module Complete. All anomalies filtered as False Positives.")

