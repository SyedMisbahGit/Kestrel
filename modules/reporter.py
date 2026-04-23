import sqlite3
import json
import glob
import os
from datetime import datetime

def generate_artifacts():
    print("[*] Compiling Kestrel State Graphs into Static SaaS Artifacts...")
    
    all_findings = []
    training_data = []
    
    # 1. Parse all active database sessions
    db_files = glob.glob('data/sessions/*.db')
    for db in db_files:
        target_name = os.basename(db).replace('.db', '').replace('_', '.')
        try:
            conn = sqlite3.connect(db)
            cursor = conn.cursor()
            # Fetching from the NoSQL 'data' column
            cursor.execute("SELECT id, data FROM vulnerabilities")
            rows = cursor.fetchall()
            
            for row in rows:
                vuln_id, data_str = row
                vuln_data = json.loads(data_str)
                
                # Append for the Dashboard
                all_findings.append({
                    "target": target_name,
                    "url": vuln_id,
                    "type": vuln_data.get('name', 'Unknown'),
                    "severity": vuln_data.get('info', {}).get('severity', 'INFO')
                })
                
                # Format for ML Training Loop (Entropy specific)
                if "High Entropy Anomaly" in vuln_data.get('name', ''):
                    training_data.append(f"{vuln_id},{len(vuln_id)},{vuln_data.get('entropy_score', 0)},UNKNOWN")
                    
            conn.close()
        except Exception as e:
            print(f"[!] Failed to parse {db}: {e}")

    # 2. Dump the JSON API for the Frontend
    with open('docs/data.json', 'w') as f:
        json.dump({"last_updated": str(datetime.utcnow()), "findings": all_findings}, f)

    # 3. Generate the Static HTML MVP
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kestrel Cloud MVP</title>
    <style>
        body { font-family: monospace; background-color: #0d1117; color: #c9d1d9; padding: 20px; }
        h1 { color: #58a6ff; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #30363d; text-align: left; }
        th { background-color: #161b22; }
        .CRITICAL { color: #ff7b72; font-weight: bold; }
        .HIGH { color: #d2a8ff; font-weight: bold; }
        .MEDIUM { color: #f2cc60; }
    </style>
</head>
<body>
    <h1>Kestrel Cloud // Blast Radius Overview</h1>
    <p id="timestamp">Loading telemetry...</p>
    <table>
        <thead><tr><th>Target</th><th>Vulnerability</th><th>Severity</th><th>Asset</th></tr></thead>
        <tbody id="vuln-table"></tbody>
    </table>
    <script>
        fetch('data.json').then(res => res.json()).then(data => {
            document.getElementById('timestamp').innerText = 'Last Updated: ' + data.last_updated + ' UTC';
            const table = document.getElementById('vuln-table');
            data.findings.sort((a,b) => (a.severity === 'CRITICAL' ? -1 : 1)).forEach(f => {
                table.innerHTML += `<tr><td>${f.target}</td><td>${f.type}</td><td class="${f.severity}">${f.severity}</td><td>${f.url}</td></tr>`;
            });
        });
    </script>
</body>
</html>"""
    
    with open('docs/index.html', 'w') as f:
        f.write(html_content)

    # 4. Append to Training Ledger
    if training_data:
        with open('data/training_ledger.csv', 'a') as f:
            f.write('\n'.join(training_data) + '\n')
            
    print(f"[+] Compiled {len(all_findings)} total findings into docs/data.json and docs/index.html")

if __name__ == "__main__":
    generate_artifacts()
