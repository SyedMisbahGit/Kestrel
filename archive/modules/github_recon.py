import requests
import time
import logging
import os
from rich.console import Console
from rich.panel import Panel
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger("rich")

# Lethal keyword combinations
KEYWORDS = ["password", "secret", "api_key", "token", "aws_access_key_id", "credentials"]

def run_github(session, config):
    """
    Phase 2.8: GitHub Intelligence (Source Code Recon)
    Hunts for leaked secrets related to the target domain via GitHub API.
    """
    console.print("[bold blue]━━ PHASE 2.8: GITHUB INTELLIGENCE (SOURCE CODE RECON) ━━[/bold blue]")

    domain = session.domain
    # Pull token from settings.yaml OR environment variable
    github_token = config.get("github_token") or os.getenv("GITHUB_TOKEN")

    if not github_token or github_token == "YOUR_GITHUB_TOKEN":
        log.warning("No GitHub Token detected. Skipping Phase 2.8.")
        console.print("[dim]  + Add 'github_token: YOUR_TOKEN' to config/settings.yaml to enable this weapon.[/dim]")
        return

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    console.print(f"INFO     Hunting for leaked secrets related to '{domain}' across GitHub...")
    findings = 0

    for keyword in KEYWORDS:
        query = f'"{domain}" "{keyword}"'
        url = f"https://api.github.com/search/code?q={query}"
        
        try:
            r = requests.get(url, headers=headers, timeout=10)
            
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items[:5]: # Cap at top 5 per keyword to avoid terminal flood
                    repo_name = item.get("repository", {}).get("full_name", "Unknown")
                    file_url = item.get("html_url", "")
                    
                    console.print(f"[bold red]  ! LEAK SUSPECTED ({keyword}):[/bold red] {repo_name} -> {file_url}")
                    
                    session.vulnerabilities.append({
                        "name": f"GitHub Source Code Leak ({keyword})",
                        "severity": "HIGH",
                        "url": file_url,
                        "info": f"Found '{keyword}' associated with '{domain}' in repository '{repo_name}'."
                    })
                    findings += 1
            elif r.status_code == 403:
                log.warning("GitHub API rate limit exceeded. Pausing module.")
                break
            
            # Critical: GitHub Code Search allows only 30 requests per minute.
            time.sleep(3) 
        except Exception as e:
            log.error(f"GitHub API request failed: {e}")
            break

    if findings == 0:
        console.print("[green]  + No immediate source code leaks found on GitHub.[/green]")
    else:
        console.print(f"INFO     GitHub Recon Complete. Logged {findings} potential leaks.")
