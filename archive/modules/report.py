import os
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def run_report(session, config):
    console.print("[bold blue]━━ GENERATING DIAGNOSTIC REPORT ━━[/bold blue]")
    
    output_dir = f"output/{session.domain}"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/arbiter_log.html"
    
    # Logic
    endpoints = getattr(session, 'endpoints', [])
    email_sec = getattr(session, 'email_security', {})
    vulns = session.vulnerabilities
    
    grade = "OPTIMAL"
    color = "#00ff41" # Matrix Green
    
    crit_count = len([v for v in vulns if "CRITICAL" in v['severity'].upper()])
    high_count = len([v for v in vulns if "HIGH" in v['severity'].upper()])
    
    if crit_count > 0:
        grade = "CRITICAL FAILURE"
        color = "#ff0000" # Red
    elif high_count > 0:
        grade = "COMPROMISED"
        color = "#ffbd00" # Orange
    elif email_sec.get('spoofable'):
        grade = "VULNERABLE"
        color = "#ffff00" # Yellow
    
    # Futuristic CSS
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ARBITER // {session.domain}</title>
        <style>
            body {{ background-color: #050505; color: #00ff41; font-family: 'Consolas', 'Monaco', monospace; padding: 20px; }}
            h1 {{ border-bottom: 2px solid #00ff41; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 5px; }}
            .hud-container {{ display: flex; justify-content: space-between; border: 1px solid #333; padding: 20px; background: #0a0a0a; margin-bottom: 20px; }}
            .stat-box {{ text-align: center; }}
            .stat-val {{ font-size: 2em; font-weight: bold; display: block; }}
            .grade-box {{ border: 2px solid {color}; color: {color}; padding: 10px; font-size: 1.5em; text-align: center; margin-bottom: 20px; text-shadow: 0 0 10px {color}; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
            th {{ color: #00ff41; background: #111; }}
            .sev-CRITICAL {{ color: #ff0000; font-weight: bold; }}
            .sev-HIGH {{ color: #ff5500; }}
            .sev-MEDIUM {{ color: #ffff00; }}
            a {{ color: #00ccff; text-decoration: none; }}
        </style>
    </head>
    <body>
    <h1>ARBITER // SYSTEM DIAGNOSTIC // {session.domain}</h1>
    
    <div class="grade-box">INTEGRITY STATUS: {grade}</div>
    
    <div class="hud-container">
        <div class="stat-box"><span class="stat-val">{len(session.live_hosts)}</span><span class="stat-label">LIVE NODES</span></div>
        <div class="stat-box"><span class="stat-val">{len(endpoints)}</span><span class="stat-label">HIDDEN LINKS</span></div>
        <div class="stat-box"><span class="stat-val">{len(vulns)}</span><span class="stat-label">ANOMALIES</span></div>
    </div>

    <h2>1. ANOMALY DETECTION LOG</h2>
    <table>
        <thead><tr><th>SEVERITY</th><th>TYPE</th><th>VECTOR</th><th>DETAILS</th></tr></thead>
        <tbody>
    """
    
    for v in vulns:
        sev = v.get('severity', 'LOW').upper()
        cls = f"sev-{sev}"
        html += f"<tr><td class='{cls}'>{sev}</td><td>{v.get('name')}</td><td>{v.get('url')}</td><td>{v.get('info')}</td></tr>"
    
    html += """
        </tbody>
    </table>
    
    <h2>2. NEURAL EXTRACTS (ENDPOINTS)</h2>
    <div style="border: 1px solid #333; padding: 10px; height: 200px; overflow-y: scroll; font-size: 0.9em; color: #aaa;">
    """
    for ep in endpoints:
        html += f"{ep}<br>"
        
    html += """
    </div></body></html>
    """
    
    with open(report_file, "w") as f: f.write(html)
    console.print(f"[bold green]>> REPORT GENERATED: {report_file}[/bold green]")
