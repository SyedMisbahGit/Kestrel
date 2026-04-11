import asyncio
import aiohttp
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

async def send_telegram_message(token, chat_id, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=10) as r:
                if r.status != 200: log.error(f"Telegram Error: {await r.text()}")
    except Exception as e: log.error(f"Telegram failed: {e}")

async def dispatch_alerts(token, chat_id, messages):
    await asyncio.gather(*[send_telegram_message(token, chat_id, msg) for msg in messages])

def run_notifier(session, config):
    console.print("\n[bold blue]━━ PHASE 6: CONTINUOUS ALERTING (TELEGRAM ENGINE) ━━[/bold blue]")

    tg_config = config.get("telegram", {})
    token = tg_config.get("token")
    chat_id = tg_config.get("chat_id")

    if not token or not chat_id: return

    new_hosts = [h for h in session.get_live_hosts() if isinstance(h, dict) and h.get('_is_new')]
    new_vulns = [v for v in session.vulnerabilities if isinstance(v, dict) and v.get('_is_new')]

    if not new_hosts and not new_vulns:
        console.print("  + No temporal changes. Communications silence maintained.")
        return

    console.print(f"INFO     Dispatching {len(new_hosts)} hosts and {len(new_vulns)} vulnerabilities to Telegram...")
    messages = []
    
    if new_hosts:
        msg = "<b>🚨 SENTINEL-X: NEW INFRASTRUCTURE</b>\n\n"
        for h in new_hosts[:15]:
            msg += f"• {h.get('url', 'Unknown')} [<code>{h.get('status', 'N/A')}</code>]\n"
        messages.append(msg)

    if new_vulns:
        msg = "<b>⚠️ SENTINEL-X: NEW VULNERABILITIES</b>\n\n"
        for v in new_vulns[:15]:
            # Absolute Type Enforcement to prevent 'str' object has no attribute 'get'
            info = v.get('info', {})
            if not isinstance(info, dict): 
                info = {}
                
            name = info.get('name') or v.get('name') or 'Unknown Vulnerability'
            sev = info.get('severity', 'HIGH').upper()
            url = v.get('matched-at', 'Unknown Endpoint')
            
            emoji = "🔴" if sev in ["HIGH", "CRITICAL"] else "🟠" if sev == "MEDIUM" else "🔵"
            msg += f"{emoji} <b>[{sev}]</b> {name}\n  └ <code>{url}</code>\n\n"
            
        messages.append(msg)

    if messages:
        asyncio.run(dispatch_alerts(token, chat_id, messages))
        console.print("  + Telegram dispatch complete.")
