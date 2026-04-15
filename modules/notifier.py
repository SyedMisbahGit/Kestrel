import requests
import os
    import time

def time.sleep(1.5)
                send_intelligence_payload(node, vuln, base_sev, elevated_sev, context, ml_confidence, details):
    """Dispatches a rich HTML-formatted intelligence payload to Telegram."""
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if not token or not chat_id:
        print("[!] Telegram credentials missing. Skipping alert.")
        return

    # Dynamic visual indicators
    sev_emoji = "🔴" if elevated_sev == "CRITICAL" else "🟠" if elevated_sev == "HIGH" else "🟡"
    
    # Format the payload using Telegram-supported HTML
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
        "disable_web_page_preview": True # Prevents massive preview boxes from cluttering the chat
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code != 200:
            print(f"[!] Telegram API Error: {response.text}")
    except Exception as e:
        print(f"[!] Failed to route intelligence payload: {e}")

# Quick CLI test block
if __name__ == "__main__":
    time.sleep(1.5)
                send_intelligence_payload(
        node="staging.payments.tesla.com",
        vuln="High Entropy Token (H=4.82)",
        base_sev="HIGH",
        elevated_sev="CRITICAL",
        context="LATERAL PIVOT RISK (Shares root with admin)",
        ml_confidence=94.2,
        details="sk_live_51H... [Tap to copy]"
    )

def run_notifier(target, db_path):
    """Backward compatibility wrapper for arbiter.py"""
    import sqlite3
    import os
    import time
    from modules.oracle import ask_brain
    
    if not os.path.exists(db_path): return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Extract only High/Critical findings to avoid spamming your phone
        cursor.execute("SELECT node, vulnerability, severity FROM vulnerabilities WHERE severity IN ('HIGH', 'CRITICAL')")
        for row in cursor.fetchall():
            node, vuln, severity = row
            
            # Query the ML Brain to see if we should drop this alert
            # (Using dummy length/density values until the full pipeline is wired)
            ml_data = ask_brain(len(node), 1)
            
            if ml_data.get("recommendation") != "DROP":
                time.sleep(1.5)
                send_intelligence_payload(
                    node=node,
                    vuln=vuln,
                    base_sev=severity,
                    elevated_sev=severity,
                    context="Unmapped Node", # Will be updated by Graph Engine
                    ml_confidence=ml_data.get("confidence_percentage", 0.0),
                    details="Review database for payload specifics."
                )
    except Exception as e:
        print(f"[!] Alert routing error: {e}")
    finally:
        conn.close()

def run(target, db_path):
    run_notifier(target, db_path)
