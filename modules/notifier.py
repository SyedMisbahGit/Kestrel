import requests
import os
import time

def send_intelligence_payload(node, vuln, base_sev, elevated_sev, context, ml_confidence, details):
    """Dispatches a rich HTML-formatted intelligence payload to Telegram."""
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if not token or not chat_id:
        print("[!] Telegram credentials missing. Skipping alert.")
        return

    sev_emoji = "🔴" if elevated_sev == "CRITICAL" else "🟠" if elevated_sev == "HIGH" else "🟡"
    
    message = f"""
🦅 <b>KESTREL INTELLIGENCE PAYLOAD</b> 🦅

🎯 <b>Target:</b> <code>{node}</code>
{sev_emoji} <b>Severity:</b> {elevated_sev} <i>(Base: {base_sev})</i>

🧠 <b>ML Confidence:</b> {ml_confidence}%
💥 <b>Vulnerability:</b> {vuln}
🕸️ <b>Graph Context:</b> {context}

📝 <b>Extracted Data:</b>
<code>{details}</code>

🔍 <a href="https://{node}">Open Target</a> | <a href="https://shodan.io/search?query={node}">Shodan</a> | <a href="https://crt.sh/?q={node}">CRT.sh</a>
"""

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code != 200:
            print(f"[!] Telegram API Error: {response.text}")
    except Exception as e:
        print(f"[!] Failed to route intelligence payload: {e}")

def run_notifier(target, db_path):
    """Backward compatibility wrapper for arbiter.py"""
    import sqlite3
    
    if not os.path.exists(db_path): return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        from modules.oracle import ask_brain
        cursor.execute("SELECT * FROM vulnerabilities")
        columns = [desc[0] for desc in cursor.description]
        
        node_idx = columns.index('node') if 'node' in columns else (columns.index('url') if 'url' in columns else 0)
        vuln_idx = columns.index('vulnerability') if 'vulnerability' in columns else (columns.index('type') if 'type' in columns else 1)
        sev_idx = columns.index('severity') if 'severity' in columns else 2

        for row in cursor.fetchall():
            node = str(row[node_idx])
            vuln = str(row[vuln_idx])
            severity = str(row[sev_idx]).upper()
            
            if severity not in ('HIGH', 'CRITICAL'): continue
            
            ml_data = ask_brain(len(node), 1)
            
            if ml_data.get("recommendation") != "DROP":
                time.sleep(1.5) # The Telegram Rate-Limit Throttle
                send_intelligence_payload(
                    node=node,
                    vuln=vuln,
                    base_sev=severity,
                    elevated_sev=severity,
                    context="Unmapped Node", 
                    ml_confidence=ml_data.get("confidence_percentage", 0.0),
                    details="Review database for payload specifics."
                )
    except Exception as e:
        print(f"[!] Alert routing error: {e}")
    finally:
        conn.close()

def run(target, db_path):
    run_notifier(target, db_path)
