import requests
import time
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

async def fetch_certspotter(domain: str, sem: aiohttp.Semaphore, session: aiohttp.ClientSession) -> list[dict[str, Any]] | list:
    API_KEY = os.getenv("CERT_SPOTTER_API")
    RATE_LIMIT = 3
    MAX_RETRIES = 10

    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }

    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer"

    print(f"[⋆] QUERY CERT SPOTTER | {domain}")

    for i in range(MAX_RETRIES):
        try:
            async with sem:
                async with session.get(url, ssl=False, timeout=25) as resp:
                    if resp.status == 200:
                        print(f"[+] SUCCESS CERTSPOTTER | {domain}")
                        return await resp.json()
                    
                await asyncio.sleep(RATE_LIMIT)
                
        except asyncio.TimeoutError:
            continue

    print(f"[-] FAILED - MAX RETRIES | CERTSPOTTER | {domain}")
    return []