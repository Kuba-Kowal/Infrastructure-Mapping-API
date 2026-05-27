import requests
import json
import time
import os
from dotenv import load_dotenv
from dataclasses import dataclass
from datetime import date

# ----------------------------
# Data models - Raw
# ----------------------------
@dataclass
class Queue:
    queue:list
    seen:set

    def next_item_in_queue(self):
        next_item = self.queue.pop(0)
        self.seen.add(next_item)

        return next_item

    def add_to_queue(self, domains):
        for domain in domains:
            if domain in self.seen or domain in self.queue:
                continue
            self.queue.append(domain)

        return None


@dataclass(frozen=True, slots=True)
class Certificate:
    id:str
    issuer:str
    not_before:date
    not_after:date

@dataclass(frozen=True, slots=True)
class FQDN:
    domain:str

@dataclass(frozen=True, slots=True)
class IPAddress:
    ip:str

@dataclass(frozen=True, slots=True)
class DNSRecord:
    record_type:str
    record:dict

@dataclass(frozen=True, slots=True)
class ASN:
    as_number:int
    as_name:str

@dataclass(frozen=True, slots=True)
class Prefix:
    prefix:str

# ----------------------------
# Data models - Relational
# ----------------------------

@dataclass(frozen=True, slots=True)
class CerttoFQDN:
    certificate:Certificate
    fqdn:FQDN
    observed_at:str

@dataclass(frozen=True, slots=True)
class IPtoPrefix:
    ip:IPAddress
    prefix:Prefix
    observed_at:str

@dataclass(frozen=True, slots=True)
class PrefixtoASN:
    prefix:Prefix
    asn:ASN
    observed_at:str

@dataclass(frozen=True, slots=True)
class FQDNtoDNS:
    fqdn:FQDN
    dns_record:DNSRecord
    observed_at:str

@dataclass(frozen=True, slots=True)
class FQDNtoPassiveDNS:
    fqdn:FQDN
    ip:IPAddress
    last_observed:date
    source:str

# ----------------------------
# Networking layer
# ----------------------------

def fetch_crt_sh(domain):
    MAX_RETRIES = 20
    RATE_LIMIT = 0.5

    url = f"https://crt.sh/?q={domain}&output=json"

    print(f"[⋆] QUERY CRT.SH | {domain}")

    for i in range (MAX_RETRIES):
        time.sleep(RATE_LIMIT)

        try:
            req = requests.get(url, timeout=60)
        except Exception as e:
            print(e)
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")

            data = req.json()
            all_domains = set()
            for certificate in data:
                new_domains = certificate["name_value"].split("\n")
                for domain in new_domains:
                    if domain.startswith("*"):
                        continue
                    all_domains.add(domain)

            return data, all_domains

    print("[-] FAILED - MAX RETRIES")
    return dict(), list()

def fetch_cert_spotter(domain):
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
            print(e)
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")

            data = req.json()
            all_domains = set()
            for certificate in data:
                new_domains = certificate["dns_names"]
                for domain in new_domains:
                    if domain.startswith("*"):
                        continue
                    all_domains.add(domain)

            return data, all_domains

    print("[-] FAILED - MAX RETRIES")
    return dict(), list()

def fetch_vt(domain):
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
            print(e)
            continue

        if req.status_code == 200:
            print("[+] SUCCESS")
            data = req.json()
            new_subdomains = []

            if data.get('subdomains') is not None:
                for inner_domain in data['subdomains']:
                    if inner_domain in new_subdomains:
                        continue
                    new_subdomains.append(inner_domain)

            return {domain: data}, new_subdomains

    print("[-] FAILED - MAX RETRIES")
    return {domain: "FAILED"}, []

# ----------------------------
# Data Collection Layer
# ----------------------------

def ct_log_fetch_pipeline(TARGET_DOMAIN):
    crt_sh_results = []
    crt_sh_seen_ids = set()

    cert_spotter_results = []
    cert_spotter_seen_ids = set()
    

    queue = Queue([TARGET_DOMAIN], set())

    while len(queue.queue) > 0:
        next_domain = queue.next_item_in_queue()

        crt_sh_data, crt_sh_new_domains = fetch_crt_sh(next_domain)
        for certificate in crt_sh_data:
            if certificate['id'] not in crt_sh_seen_ids:
                crt_sh_seen_ids.add(certificate['id'])
                crt_sh_results.append(certificate)

        cert_spotter_data, cert_spotter_new_domains = fetch_cert_spotter(next_domain)
        for certificate in cert_spotter_data:
            if certificate['id'] not in cert_spotter_seen_ids:
                cert_spotter_seen_ids.add(certificate['id'])
                cert_spotter_results.append(certificate)

        queue.add_to_queue(crt_sh_new_domains)
        queue.add_to_queue(cert_spotter_new_domains)

    return crt_sh_results, cert_spotter_results

def vt_fetch_pipeline(TARGET_DOMAIN):
    vt_results = []

    queue = Queue([TARGET_DOMAIN], set())

    while len(queue.queue) > 0:
        next_domain = queue.next_item_in_queue()

        data, new_domains = fetch_vt(next_domain)

        vt_results.append(data)

        queue.add_to_queue(new_domains)

    return vt_results

# ----------------------------
# Data Processing Layer (Object Creation)
# ----------------------------
def process_crt_sh_log_data(crt_sh_data):
    certificates = []
    FQDNs = []
    relationships = []
    crt_sh_FQDNs = set()

    for certificate in crt_sh_data:
        # Extract issuer name
        if certificate.get('issuer_name') is not None:
            if "O=" in certificate['issuer_name']:
                issuer = next(
                    field.strip().split("=", 1)[1]
                    for field in certificate['issuer_name'].split(",")
                    if field.strip().startswith("O=")
                )
        else:
            issuer = "Unknown"

        # Extract not before certificate field
        if certificate.get('not_before') is not None:
            date_field = certificate['not_before']
            not_before = date.fromisoformat(date_field[:10])
        else:
            not_before = None

        # Extract not after certificate field
        if certificate.get('not_after') is not None:
            date_field = certificate['not_after']
            not_after = date.fromisoformat(date_field[:10])
        else:
            not_after = None

        # Create certificate object utilising these fields
        cert_object = Certificate(certificate['id'], issuer, not_before, not_after)
        certificates.append(cert_object)

        # Create FQDN object based on SANs
        for domain in certificate['name_value'].split('\n'):
            fqdn_object = FQDN(domain)
            if domain not in crt_sh_FQDNs:
                crt_sh_FQDNs.add(domain)
                FQDNs.append(fqdn_object)

            # Create FQDN <-> Certificate Mapping Object
            relationships.append(CerttoFQDN(cert_object, fqdn_object, "Observed at Crt.sh"))

    return certificates, FQDNs, relationships

def process_cert_spotter_data(cert_spotter_data):
    certificates = []
    FQDNs = []
    relationships = []
    cert_spotter_FQDNs = set()

    for certificate in cert_spotter_data:
        # Extract issuer name
        if certificate.get('issuer') is not None:
            if certificate['issuer'].get('friendly_name') is not None:
                issuer = certificate['issuer']['friendly_name']
            else:
                issuer = "Unknown"
        else:
            issuer = "Unknown"

        # Extract not before certificate field
        if certificate.get('not_before') is not None:
            date_field = certificate['not_before']
            not_before = date.fromisoformat(date_field[:10])
        else:
            not_before = None

        # Extract not after certificate field
        if certificate.get('not_after') is not None:
            date_field = certificate['not_after']
            not_after = date.fromisoformat(date_field[:10])
        else:
            not_after = None

        # Create certificate object utilising these fields
        cert_object = Certificate(certificate['id'], issuer, not_before, not_after)
        certificates.append(cert_object)

        # Create FQDN object based on SANs
        if certificate.get('dns_names') is not None:
            for domain in certificate['dns_names']:
                fqdn_object = FQDN(domain)
                if domain not in cert_spotter_FQDNs:
                    cert_spotter_FQDNs.add(domain)
                    FQDNs.append(fqdn_object)

                # Create FQDN <-> Certificate Mapping Object
                relationships.append(CerttoFQDN(cert_object, fqdn_object, "Observed at CertSpotter"))

    return certificates, FQDNs, relationships

def process_vt_data(vt_data):
    FQDNs = []
    IPs = []
    relationships = []

    seen_FQDNs = set()

    # Itterate through dataset
    for entry in vt_data:
            for domain, report in entry.items():
                print(domain)
                print(report)
                fqdn_object = FQDN(domain)

                # Create FQDN Objects
                if domain not in seen_FQDNs:
                    seen_FQDNs.add(domain)
                    FQDNs.append(fqdn_object)
        
                
                if type(report) == str:
                    continue

                # Create IP Objects
                if report.get('resolutions') is not None:
                    for ip in report['resolutions']:
                        if ip.get('ip_address') is not None:
                            ip_addr = ip['ip_address']
                        else:
                            ip_addr = ""
                        if ip.get('last_resolved') is not None:
                            last_observed = ip['last_resolved']
                        else:
                            last_observed = "unkown"

                        ip_object = IPAddress(ip_addr)

                        if ip_object in IPs:
                            continue
                        IPs.append(ip_object)

                        # Create FQDN to pDNS Relationship Object
                        relationship_object = FQDNtoPassiveDNS(fqdn_object, ip_object, last_observed, "Observed at VirusTotal")
                        relationships.append(relationship_object)

    return FQDNs, IPs, relationships

def main(TARGET_DOMAIN):
    load_dotenv()
    vt_data = vt_fetch_pipeline(TARGET_DOMAIN)
    crt_sh_data, cert_spotter_data = ct_log_fetch_pipeline(TARGET_DOMAIN)

    crt_sh_certificates, crt_sh_FQDNs, crt_sh_relationships = process_crt_sh_log_data(crt_sh_data)
    cert_spotter_certificates, cert_spotter_FQDNs, cert_spotter_relationships = process_cert_spotter_data(cert_spotter_data)
    vt_FQDNs, vt_IPs, vt_relationships = process_vt_data(vt_data)

    print("\n\n\n VT - IPs \n\n")
    print(vt_IPs)
    print("\n\n\n VT - FQDNs \n\n")
    print(vt_FQDNs)
    print("\n\n\n VT - Relationships \n\n")
    print(vt_relationships)

    print("\n\n\n CRT.SH - Certificates \n\n")
    print(crt_sh_certificates)
    print("\n\n\n CRT.SH - FQDNs \n\n")
    print(crt_sh_FQDNs)
    print("\n\n\n CRT.SH - Relationships \n\n")
    print(crt_sh_relationships)

    print("\n\n\n CertSpotter - Certificates \n\n")
    print(cert_spotter_certificates)
    print("\n\n\n CertSpotter- FQDNs \n\n")
    print(cert_spotter_FQDNs)
    print("\n\n\n CertSpotter - Relationships \n\n")
    print(cert_spotter_relationships)

main("example.com")
