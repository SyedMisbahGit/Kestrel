import asyncio
import yaml
import sys
from modules.notifier import send_telegram_message

async def test():
    with open("config/settings.yaml", "r") as f:
        config = yaml.safe_load(f)
    
    token = config.get("telegram", {}).get("token")
    chat_id = config.get("telegram", {}).get("chat_id")
    
    if not token or not chat_id:
        print("Missing credentials in config.")
        sys.exit(1)
        
    print(f"Sending test message to Chat ID: {chat_id}...")
    await send_telegram_message(
        token, 
        chat_id, 
        "<b>🟢 SENTINEL-X COMMS TEST</b>\n\nIf you are reading this, the neural link is established."
    )
    print("Dispatched.")

asyncio.run(test())
