import logging
import json
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("rich")

def extract_root(url):
    """Extracts the base domain to map trust boundaries (e.g., .target.com)"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    netloc = urlparse(url).netloc
    parts = netloc.split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else netloc

def run_intelligence(session, config):
    console.print("\n[bold blue]━━ PHASE 7: THE BLAST RADIUS GRAPH (CONTEXTUAL RISK ENGINE) ━━[/bold blue]")
    
    # 1. Define High-Value Target (HVT) heuristics
    HVT_KEYWORDS = ["admin", "auth", "login", "portal", "api", "sso", "vpn", "dashboard", "cpanel"]
    
    try:
        c = session.conn.cursor()
        c.execute("SELECT data FROM live_hosts")
        hosts = [json.loads(row[0]) for row in c.fetchall()]
        
        c.execute("SELECT data FROM vulnerabilities")
        vulns = [json.loads(row[0]) for row in c.fetchall()]
    except Exception as e:
        log.error(f"Graph Extraction Failed: {e}")
        return

    if not hosts and not vulns:
        console.print("  + Graph is empty. No intelligence to process.")
        return

    console.print(f"INFO     Compiling Network Graph: {len(hosts)} Nodes, {len(vulns)} Edges...")

    # 2. Build the Context Graph
    graph = {}
    hvt_roots = set()
    
    for h in hosts:
        url = h.get('url', '')
        root = extract_root(url)
        is_hvt = any(k in url.lower() for k in HVT_KEYWORDS)
        
        if is_hvt:
            hvt_roots.add(root)
            
        if root not in graph:
            graph[root] = {'hosts': [], 'hvts': []}
            
        graph[root]['hosts'].append(url)
        if is_hvt: 
            graph[root]['hvts'].append(url)

    # 3. Calculate Blast Radius
    elevated_vulns = []
    
    for v in vulns:
        target_url = v.get('matched-at', '')
        root = extract_root(target_url)
        
        # Handle string parsing failures from Nuclei gracefully
        info = v.get('info', {}) if isinstance(v.get('info'), dict) else {}
        
        sev = info.get('severity', 'LOW').upper()
        name = info.get('name') or v.get('name') or 'Unknown Vulnerability'
        
        context = "Isolated Node"
        new_sev = sev
        
        # Rule 1: Direct HVT Compromise
        if target_url in graph.get(root, {}).get('hvts', []):
            context = "[red]DIRECT HVT COMPROMISE[/red]"
            new_sev = "CRITICAL"
        
        # Rule 2: Lateral Movement / Shared Root Cookie Risk
        elif root in hvt_roots and sev in ["MEDIUM", "HIGH"]:
            hvt_list = ", ".join([urlparse(h).netloc.split('.')[0] for h in graph[root]['hvts'][:2]])
            context = f"[yellow]LATERAL PIVOT RISK (Shares root with: {hvt_list})[/yellow]"
            if sev == "MEDIUM": new_sev = "HIGH"
            if sev == "HIGH": new_sev = "CRITICAL"
            
        elevated_vulns.append({
            "url": target_url,
            "name": name,
            "original_sev": sev,
            "elevated_sev": new_sev,
            "context": context
        })

    # 4. Render the Intelligence Matrix
    if not elevated_vulns:
        console.print("  + No actionable vulnerabilities mapped to the graph.")
        return
        
    table = Table(title="🚨 BLAST RADIUS: CONTEXTUAL RISK MATRIX 🚨", border_style="red")
    table.add_column("Vulnerable Node", style="cyan")
    table.add_column("Vulnerability", style="white")
    table.add_column("Base Sev", justify="center")
    table.add_column("Elevated Sev", justify="center", style="bold red")
    table.add_column("Graph Context", style="magenta")
    
    # Sort so Criticals appear at the bottom for maximum visibility
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    sorted_vulns = sorted(elevated_vulns, key=lambda x: severity_rank.get(x['elevated_sev'], 0))
    
    for ev in sorted_vulns:
        table.add_row(
            ev['url'], 
            ev['name'], 
            ev['original_sev'], 
            ev['elevated_sev'], 
            ev['context']
        )
        
    console.print(table)
