import requests
import time

def fetch_crtsh(domain: str) -> list[dict[str, Any]] | list:
    MAX_RETRIES = 20
    RATE_LIMIT = 0.5

    url = f"https://crt.sh/?q={domain}&output=json"

    print(f"[⋆] QUERY CRT.SH | {domain}")

    for i in range (MAX_RETRIES):
        time.sleep(RATE_LIMIT)

        try:
            req = requests.get(url, timeout=60)
        except Exception as e:
            print(f"[-] FAILED - {e}")
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")

            return req.json()

    print("[-] FAILED - MAX RETRIES")
    return []