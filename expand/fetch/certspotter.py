import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

def fetch_certspotter(domain: str) -> list[dict[str, Any]] | list:
    API_KEY = os.getenv("CERT_SPOTTER_API")
    RATE_LIMIT = 2
    MAX_RETRIES = 5

    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }

    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer"

    print(f"[⋆] QUERY CERT SPOTTER | {domain}")

    for i in range(MAX_RETRIES):
        time.sleep(RATE_LIMIT)

        try:
            req = requests.get(url, headers=headers, timeout=20)
        except Exception as e:
            print(f"[-] FAILED - {e}")
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")

            return req.json()

    print("[-] FAILED - MAX RETRIES")
    return []