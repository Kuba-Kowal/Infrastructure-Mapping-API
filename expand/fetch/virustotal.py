import requests
import time
import os
from dotenv import load_dotenv
from typing import Any

load_dotenv()

def fetch_vt(domain: str) -> dict[str, Any] | dict:
    API_KEY = os.getenv("VT_API_KEY")
    RATE_LIMIT = 3
    MAX_RETRIES = 3

    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={API_KEY}&domain={domain}"

    print(f"[⋆] QUERY VIRUSTOTAL | {domain}")

    for i in range(MAX_RETRIES):
        time.sleep(RATE_LIMIT)
        try:
            req = requests.get(url, timeout=20)
        except Exception as e:
            print(f"[-] FAILED - {e}")
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")

            return req.json()

    print("[-] FAILED - MAX RETRIES")
    return {}