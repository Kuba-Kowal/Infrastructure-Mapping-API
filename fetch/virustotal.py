import requests
import time
import os
import asyncio
from dotenv import load_dotenv
from typing import Any

load_dotenv()

async def fetch_virustotal(domain: str, sem: aiohttp.Semaphore, session: aiohttp.ClientSession) -> dict[str, Any] | dict:
    API_KEY = os.getenv("VT_API_KEY")
    RATE_LIMIT = 4
    MAX_RETRIES = 10

    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={API_KEY}&domain={domain}"

    print(f"[⋆] QUERY VIRUSTOTAL | {domain}")

    for i in range(MAX_RETRIES):
        try:
            async with sem:
                async with session.get(url, ssl=False, timeout=15) as resp:
                    if resp.status == 200:
                        print(f"[+] SUCCESS VIRUSTOTAL | {domain}")
                        return await resp.json()
                    
                await asyncio.sleep(RATE_LIMIT)
                
        except asyncio.TimeoutError:
            continue
        except aiohttp.ClientConnectorDNSError:
            continue

    print(f"[-] FAILED - MAX RETRIES | VIRUSTOTAL | {domain}")
    return {}