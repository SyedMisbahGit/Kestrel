import asyncio
import aiohttp

async def fetch_crtsh(client, domain):
    """Robust CRT.sh fetcher with a 10-second circuit breaker and JSON fallback."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        # 10-second hard timeout to prevent pipeline stalling
        async with client.get(url, timeout=10) as response:
            if response.status == 200:
                data = await response.json()
                return {entry['name_value'].lower() for entry in data if '*' not in entry['name_value']}
    except asyncio.TimeoutError:
        return set() # Circuit Broken: Gracefully return empty set
    except Exception:
        return set()
    return set()
