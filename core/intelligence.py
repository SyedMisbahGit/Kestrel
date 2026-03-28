import re
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
log = logging.getLogger("rich")

# Heuristic Signatures
P1_URL_KWS = re.compile(r'(api|dev|stage|test|uat|admin|corp|internal|dashboard|portal|vpn|sso|auth|login)', re.I)
P1_TITLE_KWS = re.compile(r'(swagger|admin|login|sign in|dashboard|portal|gitlab|jenkins|grafana|kibana)', re.I)
P4_URL_KWS = re.compile(r'(mail|autodiscover|smtp|pop|imap|cpanel|webmail|ns\d+)', re.I)

def analyze_host(host):
    """
    The Decision Engine. 
    Analyzes a host dictionary and assigns a Priority (P1-P4) and Context string.
    """
    url = host.get('url', '').lower()
    title = host.get('title', '').lower()
    status = host.get('status', 0)
    tech = [t.lower() for t in host.get('tech', [])]
    
    # Default State
    priority = "P3"
    context = "Static / Low Value"

    # Rule 1: Ignore Junk / Dead infrastructure (P4)
    if status in [404, 502, 503, 521, 522, 530] or P4_URL_KWS.search(url):
        return "P4", "Infrastructure Junk / Dead"

    # Rule 2: High-Value Targets (P1)
    if P1_URL_KWS.search(url) or P1_TITLE_KWS.search(title):
        context = []
        if 'api' in url: context.append("API Endpoint")
        if re.search(r'(dev|stage|test|uat)', url): context.append("Pre-Production")
        if re.search(r'(admin|internal|corp|vpn)', url): context.append("Internal/Admin")
        if 'login' in url or 'auth' in url or P1_TITLE_KWS.search(title): context.append("Auth/Portal")
        
        return "P1", " | ".join(context) if context else "High-Interest Asset"

    # Rule 3: Interesting Tech or Standard App (P2)
    # If it's returning 200 OK and running dynamic tech or cloud buckets
    dynamic_tech = any(x in str(tech) for x in ['react', 'vue', 'angular', 'php', 'node', 'express', 's3', 'cloudfront'])
    if status == 200 and dynamic_tech:
        return "P2", "Dynamic Application / User-Facing"
    
    if status in [401, 403]:
        return "P2", "Protected/Forbidden Resource"

    return priority, context

def run_intelligence(session, config):
    """
    Processes the live hosts and outputs a prioritized tactical plan.
    """
    console.print("\n[bold blue]━━ INTELLIGENCE ENGINE: THREAT PRIORITIZATION ━━[/bold blue]")
    
    live_hosts = list(session.live_hosts)
    if not live_hosts:
        log.warning("No live hosts available for intelligence analysis.")
        return

    # Categorize
    categorized = {"P1": [], "P2": [], "P3": [], "P4": []}
    
    for host in live_hosts:
        # Some hosts might just be strings if legacy data, ensure dict
        if not isinstance(host, dict): continue
        
        priority, context = analyze_host(host)
        host['priority'] = priority
        host['context'] = context
        categorized[priority].append(host)

    # --- THE HUD (Heads Up Display) ---
    
    # 1. Print P1 (Critical Focus)
    if categorized["P1"]:
        table = Table(title="🚨 PRIORITY 1: IMMEDIATE ACTION REQUIRED", style="red", header_style="bold red")
        table.add_column("Target URL", style="white")
        table.add_column("Status", justify="center")
        table.add_column("Intelligence Context", style="yellow")
        
        for h in categorized["P1"]:
            table.add_row(h['url'], str(h['status']), h['context'])
        console.print(table)

    # 2. Print P2 (Secondary Focus)
    if categorized["P2"]:
        table = Table(title="⚠️ PRIORITY 2: SECONDARY INVESTIGATION", style="yellow", header_style="bold yellow")
        table.add_column("Target URL", style="white")
        table.add_column("Status", justify="center")
        table.add_column("Intelligence Context", style="cyan")
        
        for h in categorized["P2"]:
            # Limit output to prevent screen flooding. Show top 15.
            if categorized["P2"].index(h) > 15:
                table.add_row("...", "...", f"+ {len(categorized['P2']) - 15} more hosts")
                break
            table.add_row(h['url'], str(h['status']), h['context'])
        console.print(table)

    # 3. Summarize P3 and P4 (Reduce the noise)
    console.print(Panel(
        f"[dim white]Background Noise Ignored:[/dim white]\n"
        f"[green]P3 (Low Value):[/green] {len(categorized['P3'])} hosts\n"
        f"[blue]P4 (Junk/Dead):[/blue] {len(categorized['P4'])} hosts",
        title="🛡️ NOISE FILTER", border_style="dim"
    ))
