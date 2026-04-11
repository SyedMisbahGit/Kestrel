import asyncio
import logging
from functools import wraps

log = logging.getLogger("rich")

def with_retry(max_retries=3, base_delay=1):
    """
    Decorator for robust asynchronous network calls.
    Implements Exponential Backoff to defeat WAF rate limits and network drops.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return await func(*args, **kwargs)
                except (asyncio.TimeoutError, ConnectionError) as e:
                    retries += 1
                    if retries == max_retries:
                        return None
                    delay = base_delay * (2 ** (retries - 1))
                    await asyncio.sleep(delay)
                except Exception:
                    return None # Drop structural failures (like bad DNS)
        return wrapper
    return decorator
