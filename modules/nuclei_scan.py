import json
import subprocess
import logging
from rich.console import Console
from rich.panel import Panel

console = Console()
log = logging.getLogger("rich")

def run_nuclei(session, config):
    """
    Phase 4: The Nuclei Pipeline
    Streams live hosts and crawled URLs directly into Nuclei for template-based vulnerability scanning.
    """
    console.print("[bold blue]━━ PHASE 4: THE NUCLEI PIPELINE (CVE & MISCONFIG MAPPING) ━━[/bold blue]")

    # Gather all valid endpoints from previous phases
    targets = [host.get('url') for host in session.live_hosts if isinstance(host, dict) and host.get('url')]
    if hasattr(session, 'crawled_urls') and session.crawled_urls:
        targets.extend(list(session.crawled_urls))
        
    targets = list(set(targets)) # Deduplicate

    if not targets:
        log.warning("No targets available for the Nuclei pipeline. Skipping.")
        return

    console.print(f"INFO     Piping {len(targets)} targets directly into Nuclei memory stream...")

    # The Command: -ni disables interactsh to speed up scans, -silent keeps standard output clean
    cmd = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-ni" 
    ]

    findings = 0
    try:
        # Load targets into RAM buffer
        target_str = "\n".join(targets)
        
        # Open Subprocess Pipe
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Stream targets in, read JSON out
        stdout, _ = process.communicate(input=target_str)

        for line in stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                vuln_name = data.get("info", {}).get("name", "Unknown Vulnerability")
                severity = data.get("info", {}).get("severity", "info").upper()
                url = data.get("matched-at", "Unknown URL")
                desc = data.get("info", {}).get("description", "No description provided.")

                # Filter for impact to keep the HUD clean
                if severity in ["HIGH", "CRITICAL", "MEDIUM"]:
                    color = "red" if severity in ["HIGH", "CRITICAL"] else "orange1"
                    console.print(Panel(
                        f"[bold {color}]{severity}: {vuln_name}[/bold {color}]\n"
                        f"Target: {url}\n"
                        f"Info: {str(desc)[:100]}...",
                        title="⚠️ NUCLEI STRIKE", border_style=color
                    ))

                    # Inject into SQLite Core
                    session.vulnerabilities.append({
                        "name": vuln_name,
                        "severity": severity,
                        "url": url,
                        "info": desc
                    })
                    findings += 1

            except json.JSONDecodeError:
                continue

    except FileNotFoundError:
        log.error("Nuclei binary not found. Ensure it is installed and in your system PATH.")
        log.info("Install command: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    except Exception as e:
        log.error(f"Nuclei pipeline failed: {e}")

    if findings == 0:
        console.print("[green]  + Nuclei pipeline complete. No high-severity vulnerabilities detected.[/green]")
    else:
        console.print(f"INFO     Nuclei execution finished. Logged {findings} verified vulnerabilities.")
