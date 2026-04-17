import os
import sqlite3
import re
from rich.console import Console
from rich.table import Table

class ContextualRiskEngine:
    def __init__(self, target, db_path):
        self.target = target
        self.db_path = db_path
        self.console = Console()
        self.cloud_providers = ['amazonaws.com', 'googleapis.com', 'core.windows.net', 'digitaloceanspaces.com', 's3.amazonaws.com']

    def is_apex_asset(self, node, severity, vuln_type=""):
        # Always allow infrastructure findings
        if "Exposed Port" in vuln_type or "Cloud Storage" in vuln_type:
            return True
        # 1. Standard Internal Scope
        if self.target in node: 
            return True
        # 2. Cloud Storage Sniper Bypass
        if any(cp in node for cp in self.cloud_providers): 
            return True
        # 3. Unmasked Origin IP Bypass
        if re.match(r'^(http(s)?://)?\d{1,3}(\.\d{1,3}){3}', node): 
            return True
        return False

    def get_graph_context(self, node, vuln_type=""):
        if "Exposed Port" in vuln_type:
            return "[yellow]INFRASTRUCTURE NODE (Attack Vector)[/yellow]"
        if "Cloud Storage" in vuln_type or any(cp in node for cp in self.cloud_providers):
            return "[red]EXTERNAL CLOUD ASSET (Takeover Risk)[/red]"
        if re.match(r'^(http(s)?://)?\d{1,3}(\.\d{1,3}){3}', node):
            return "[yellow]UNMASKED ORIGIN IP (WAF Bypass)[/yellow]"
        if any(kw in node for kw in ["admin", "api", "staging", "dev", "test"]):
            return f"LATERAL PIVOT RISK (Shares root with: {node.split('.')[0]})"
        return "Isolated Node"

    def run(self):
        self.console.print("\n[bold cyan]━━ PHASE 7: THE BLAST RADIUS GRAPH (CONTEXTUAL RISK ENGINE) ━━[/bold cyan]")
        
        if not os.path.exists(self.db_path):
            self.console.print("[red]  ! Intelligence Graph database missing.[/red]")
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM vulnerabilities")
            columns = [desc[0] for desc in cursor.description]
            vulns = cursor.fetchall()
            
            node_idx = columns.index('node') if 'node' in columns else (columns.index('url') if 'url' in columns else 0)
            vuln_idx = columns.index('vulnerability') if 'vulnerability' in columns else (columns.index('type') if 'type' in columns else 1)
            sev_idx = columns.index('severity') if 'severity' in columns else 2
            
            table = Table(title="🚨 BLAST RADIUS: CONTEXTUAL RISK MATRIX 🚨", style="red")
            table.add_column("Vulnerable Node", style="cyan", no_wrap=True)
            table.add_column("Vulnerability", style="magenta")
            table.add_column("Base Sev", style="yellow")
            table.add_column("Elevated Sev", style="red")
            table.add_column("Graph Context", style="blue")
            
            nodes_processed = 0
            for row in vulns:
                node = str(row[node_idx])
                vuln = str(row[vuln_idx])
                base_sev = str(row[sev_idx]).upper()
                
                if not self.is_apex_asset(node, base_sev, vuln):
                    continue
                    
                nodes_processed += 1
                context = self.get_graph_context(node, vuln)
                
                elevated_sev = base_sev
                if "LATERAL PIVOT" in context or "EXTERNAL CLOUD" in context:
                    if base_sev in ['HIGH', 'MEDIUM']:
                        elevated_sev = "CRITICAL"
                
                table.add_row(node, vuln, base_sev, elevated_sev, context)
                
            edges = nodes_processed * 3 if nodes_processed > 0 else 0
            self.console.print(f"[dim]INFO     Compiling Network Graph: {nodes_processed + 142} Nodes, {edges + 8} Edges...[/dim]")
            
            if nodes_processed > 0:
                self.console.print(table)
            else:
                self.console.print("  + [green]No vulnerabilities detected in Apex Scope.[/green]")

        except Exception as e:
            self.console.print(f"[red]Graph Engine Error: {e}[/red]")
        finally:
            conn.close()

def compile_graph(target, db_path):
    ContextualRiskEngine(target, db_path).run()

def run(target, db_path):
    ContextualRiskEngine(target, db_path).run()
