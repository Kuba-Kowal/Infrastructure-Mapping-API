import requests
import json
import time
import os
from dotenv import load_dotenv

# ----------------------------
# Data models
# ----------------------------

class CTLog:
    def __init__(self, domains, issuer, first_date, last_date):
        self.domains = tuple(domains)
        self.issuer = issuer
        self.first_date = first_date
        self.last_date = last_date

    def __repr__(self):
        return f"{self.domains} | {self.issuer} | [{self.first_date} → {self.last_date}]"



class CTCluster():
    def __init__(self, domain, issuer, first_seen, last_seen, sightings=1):
        self.domain = domains
        self.issuer = issuer
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.sightings = sightings



class rawIPs:
    def __init__(self, domain, IPs):
        self.domain = domain
        self.IPs = IPs

    def __repr__(self):
        return f"DOMAIN: {domain} | IPs: {IPs}"

# ----------------------------
# Networking layer
# ----------------------------

def fetch_crt_sh(domain):
    MAX_RETRIES = 20
    RATE_LIMIT = 0.5

    url = f"https://crt.sh/?q={domain}&output=json"

    print("[+] QUERY CRT.SH")

    for i in range (MAX_RETRIES):
        time.sleep(RATE_LIMIT)

        try:
            req = requests.get(url, timeout=60)
        except Exception as e:
            print(e)
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")
            return req.json()

    print("[-] FAILED")
    return None

def fetch_cert_spotter(domain):
    API_KEY = os.getenv("CERT_SPOTTER_API")
    RATE_LIMIT = 2
    MAX_RETRIES = 5

    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }

    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer"

    print("[+] QUERY CERT SPOTTER")

    for i in range(MAX_RETRIES):
        time.sleep(RATE_LIMIT)

        try:
            req = requests.get(url, headers=headers, timeout=20)
        except Exception as e:
            print(e)
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")
            return req.json()

    print("[-] FAILED")
    return None

def fetch_vt_crt(domain):
    API_KEY = os.getenv("VT_API_KEY")
    RATE_LIMIT = 3
    MAX_RETRIES = 3

    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={API_KEY}&domain={domain}"

    print("[+] QUERY VIRUSTOTAL")

    for i in range(MAX_RETRIES):
        time.sleep(RATE_LIMIT)
        try:
            req = requests.get(url, timeout=20)
        except Exception as e:
            print(e)
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")
            return {domain: req.json()}

    print("[-] FAILED")
    return None

# ----------------------------
# Normalisation layer
# ----------------------------

def normalise_cert_spotter(data):
    ct_logs = set()
    for result in data:
        for query in result:
            asn = query.get('dns_names')
            issuer = (query.get("issuer").get("friendly_name"))

            log = CTLog(asn, issuer, query.get('not_after'), query.get('not_before'))
            ct_logs.add(log)

    return ct_logs

def normalise_crt_sh(data):
    ct_logs = set()
    for result in data:
        for cert in result:
            asn = cert.get('name_value')
            temp_issuer = cert.get('issuer_name')

            try:
                issuer = next(
                    b.split("=", 1)[1].strip().strip('"')
                    for b in temp_issuer.split(",") 
                    if b.strip().startswith("O=")
                )
            except:
                issuer = ""

            log = CTLog(asn.split("\n"), issuer, cert.get('not_after'), cert.get('not_before'))
            ct_logs.add(log)

    return ct_logs

def normalise_vt(data):
    IP_OUTPUT = []
    SUBDOMAIN_OUTPUT = set()

    for query in data:
        for domain, values in query.items():
            if type(query) != dict:
                continue

            for res in values.get("resolutions", []):
                ip = res.get("ip_address")

                IP_OUTPUT.append({
                    "domain": domain,
                    "ip": ip,
                    "source": "VT"
                })

            for subdomain in values.get("subdomains", []):
                SUBDOMAIN_OUTPUT.add(subdomain)

    return IP_OUTPUT, SUBDOMAIN_OUTPUT

# ----------------------------
# Aggregation Layer
# ----------------------------
def aggregate_ct_logs(ct_logs):
    clusters = {}

    for log in ct_logs:
        key = (tuple(sorted(set(log.domains))), log.issuer)

        if key not in clusters:
            clusters[key] = {
                "domains": (tuple(sorted(set(log.domains)))),
                "issuer": log.issuer,
                "first_seen": log.first_date,
                "last_seen": log.last_date,
                "sightings": 1
            }

        else:
            cluster = clusters[key]
            cluster["sightings"] += 1
        
        cluster = clusters[key]
        if log.first_date and (cluster['first_seen'] is None or log.first_date < cluster["first_seen"]):
            cluster["first_seen"] = log.first_date

        if log.last_date and (cluster['last_seen'] is None or log.last_date < cluster["last_seen"]):
            cluster["last_seen"] = log.last_date
            
    return sorted(
        clusters.values(),
        key=lambda c: c["first_seen"],
        reverse=true
    )

# ----------------------------
# Main Pipeline
# ----------------------------

def __main__():
    load_dotenv()
    TARGET_DOMAIN = "example.com"

    vt_results = []
    crt_sh_results = []
    cert_spotter_results = []

    crt_sh_results.append(fetch_crt_sh(TARGET_DOMAIN))
    cert_spotter_results.append(fetch_cert_spotter(TARGET_DOMAIN))
    vt_results.append(fetch_vt_crt(TARGET_DOMAIN))

    normal_crt_sh = normalise_crt_sh(crt_sh_results)
    normal_cert_spotter = normalise_cert_spotter(cert_spotter_results)
    ips, subdomains = normalise_vt(vt_results)
    
    ct_logs_deduplicated = aggregate_ct_logs(normal_crt_sh | normal_cert_spotter)

    print(f"-- CT LOG OUTPUT --\n\n{ct_logs_deduplicated}")
    print(f"-- VT OUTPUT --\n\n{ips}\n\n{subdomains}")

__main__()
