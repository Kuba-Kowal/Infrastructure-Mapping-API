import requests
import time
import asyncio

async def fetch_crtsh(domain: str, sem: asyncio.Sempahore, session: aiohttp.ClientSession) -> list[dict[str, Any]] | list:
    MAX_RETRIES = 20
    RATE_LIMIT = 0.5

    url = f"https://crt.sh/?q={domain}&output=json"

    print(f"[⋆] QUERY CRT.SH | {domain}")

    for i in range(MAX_RETRIES):
        try:
            async with sem:
                async with session.get(url, ssl=False, timeout=15) as resp:
                    if resp.status == 200:
                        print(f"[+] SUCCESS CRTSH | {domain}")
                        return await resp.json()
                    
                await asyncio.sleep(RATE_LIMIT)
                
        except asyncio.TimeoutError:
            continue
        except aiohttp.ClientConnectionError:
            continue

    print(f"[-] FAILED - MAX RETRIES | CRTSH | {domain}")
    return []