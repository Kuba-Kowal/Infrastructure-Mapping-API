import requests
import json
import time
import os
import dns.resolver
from dotenv import load_dotenv
from dataclasses import dataclass
from datetime import date
from itertools import chain
from collections import deque

# ----------------------------
# Data models - Raw
# ----------------------------
@dataclass
class Queue:
    queue: deque[str]
    seen: set[str]

    def next_item_in_queue(self) -> str:
        next_item = self.queue.popleft()
        self.seen.add(next_item)

        return next_item

    def add_to_queue(self, domains: list[str]) -> None:
        for domain in domains:
            if domain in self.seen or domain in self.queue:
                continue
            self.queue.append(domain)

        return None


@dataclass(frozen=True, slots=True)
class Certificate:
    id: str
    issuer: str
    not_before: date
    not_after: date

@dataclass(frozen=True, slots=True)
class FQDN:
    domain: str

@dataclass(frozen=True, slots=True)
class IPAddress:
    ip: str

@dataclass(frozen=True, slots=True)
class ASN:
    as_number: int
    as_name: str

@dataclass(frozen=True, slots=True)
class Prefix:
    prefix: str

# ----------------------------
# Data models - Relational
# ----------------------------

@dataclass(frozen=True, slots=True)
class CerttoFQDN:
    certificate: Certificate
    fqdn: FQDN
    observed_at: str

@dataclass(frozen=True, slots=True)
class IPtoPrefix:
    ip: IPAddress
    prefix: Prefix
    observed_at: str

@dataclass(frozen=True, slots=True)
class PrefixtoASN:
    prefix: Prefix
    asn: ASN
    observed_at: str

@dataclass(frozen=True, slots=True)
class FQDNtoDNS:
    domain: FQDN
    record_type: str
    record: list[str]

@dataclass(frozen=True, slots=True)
class FQDNtoPassiveDNS:
    fqdn: FQDN
    ip: IPAddress
    last_observed: ip['last_resolved']
    source: str

# ----------------------------
# Networking layer
# ----------------------------

def resolve_dns_query(domain: str, rtype: str) -> list[str]:
    answers = dns.resolver.resolve(domain, rtype)
    return [str(answer) for answer in answers]

def fetch_crt_sh(domain: str) -> tuple[list[dict[str, str]], list[str]]:
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
    return [], []

def fetch_cert_spotter(domain: str) -> tuple[list[dict], list[str]]:
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
    return [], []

def fetch_vt(domain: str) -> tuple[dict[str, dict[str, str]], list[str]]:
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

def ct_log_fetch_pipeline(TARGET_DOMAIN: str) -> tuple[list[dict[str: any]]]:
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

def vt_fetch_pipeline(TARGET_DOMAIN: str) -> list[dict[str, str]]:
    vt_results = []

    queue = Queue([TARGET_DOMAIN], set())

    while len(queue.queue) > 0:
        next_domain = queue.next_item_in_queue()

        data, new_domains = fetch_vt(next_domain)

        vt_results.append(data)

        queue.add_to_queue(new_domains)

    return vt_results

# ----------------------------
# Data Processing Layer (Certificate Objects)
# ----------------------------
def process_crt_sh_log_data(crt_sh_data: list[dict[str, str]]) -> tuple[list[Certificate], list[FQDN], list[CerttoFQDN]]:
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

def process_cert_spotter_data(cert_spotter_data: list[dict[str, str]]) -> tuple[list[Certificate], list[FQDN], list[CerttoFQDN]]:
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

def process_vt_data(vt_data: list[dict[str, str]]) -> tuple[list[FQDN], list[IPAddress], list[FQDNtoPassiveDNS]]:
    FQDNs = []
    IPs = []
    relationships = []

    seen_FQDNs = set()

    # Itterate through dataset
    for entry in vt_data:
            for domain, report in entry.items():
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

# ----------------------------
# Data Collection & Processing Layer (FQDNtoDNS Objects)
# ----------------------------

def cname_fetch_pipeline(FQDN_data: list[FQDN]) -> tuple[list[FQDNtoDNS], list[FQDN]]:
    results = []
    seen_domains = set()
    new_cnames = set()
    new_fqdns = []

    for domain in FQDN_data:
        domain_unpacked = domain.domain

        if domain_unpacked.startswith("*"):
            continue
        if domain_unpacked in seen_domains:
            continue
        seen_domains.add(domain_unpacked)

        print(f"[+] DNS TYPE: CNAME | {domain}")
        try:
            query_result = resolve_dns_query(domain_unpacked, "CNAME")

        except dns.resolver.NXDOMAIN:
            continue

        except dns.resolver.NoAnswer:
            continue

        for result in query_result:
            new_cnames.add(str(result))

        results.append(FQDNtoDNS(domain, "CNAME", query_result))
        
    while len(new_cnames) > 0:
        domain = new_cnames.pop()

        if domain.startswith("*"):
            continue
        if domain in seen_domains:
            continue
        seen_domains.add(domain)

        print(f"[+] DNS TYPE: CNAME | {domain}")
        new_fqdns.append(FQDN(domain))
        try:
            query_result = resolve_dns_query(domain, "CNAME")

        except dns.resolver.NXDOMAIN:
            continue

        except dns.resolver.NoAnswer:
            continue

        for result in query_result:
            new_cnames.add(str(result))

        results.append(FQDNtoDNS(FQDN(domain), "CNAME", query_result))

    return results, new_fqdns

def dns_record_pipeline(FQDN_data: list[FQDN]) -> list[FQDNtoDNS]:
    results = []
    seen_domains = set()

    infrastructure_mapping_records = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "SRV"]
    for record_type in infrastructure_mapping_records:
        for domain in FQDN_data:
            domain_unpacked = domain.domain
            if domain_unpacked.startswith("*"):
                continue
            print(f"[+] DNS TYPE: {record_type} | {domain_unpacked}")
            
            try:
                query_result = resolve_dns_query(domain_unpacked, record_type)

            except dns.resolver.NXDOMAIN:
                query_result = ["NXDOMAIN"]
                results.append(FQDNtoDNS(domain, record_type, query_result)) # NXDOMAIN: No such hostname
                continue

            except dns.resolver.NoAnswer:
                query_result = ["NOANSWER"]
                results.append(FQDNtoDNS(domain, record_type, query_result)) # NOANSWER: Domain exists, but record type doesn't
                continue 

            results.append(FQDNtoDNS(domain, record_type, query_result))

    return results

def main(TARGET_DOMAIN: str) -> None:
    load_dotenv()

    print("[+] BEGIN HISTORICAL DNS & SUBDOMAIN PIPELINE\n")
    # == Certificate & Subdomain Layer ==
    vt_data = vt_fetch_pipeline(TARGET_DOMAIN)

    print("\n[+] BEGIN CERTIFICATE LOG PIPELINE\n")
    crt_sh_data, cert_spotter_data = ct_log_fetch_pipeline(TARGET_DOMAIN)

    crt_sh_certificates, crt_sh_FQDNs, crt_sh_relationships = process_crt_sh_log_data(crt_sh_data)
    cert_spotter_certificates, cert_spotter_FQDNs, cert_spotter_relationships = process_cert_spotter_data(cert_spotter_data)
    vt_FQDNs, vt_IPs, vt_relationships = process_vt_data(vt_data)

    certificates = list(set(chain(crt_sh_certificates, cert_spotter_certificates)))
    FQDNs = list(chain(crt_sh_FQDNs, cert_spotter_FQDNs, vt_FQDNs))

    certificate_to_domain_relationships = list(set(chain(crt_sh_relationships, cert_spotter_relationships)))
    fqdn_to_historical_ip_relationships = list(set(vt_relationships))

    # == DNS Layer ==
    print("\n[+] BEGIN DNS PIPELINE\n")
    dns_relationships, dns_fqdns = cname_fetch_pipeline(FQDNs)

    FQDNs = list(set(chain(FQDNs, dns_fqdns)))

    temp_fqdn_to_dns_relationships = chain(dns_record_pipeline(FQDNs), dns_relationships)
    fqdn_to_dns_relationships = []

    for relationship in temp_fqdn_to_dns_relationships:
        if relationship.record[0] == "NXDOMAIN" or relationship.record[0] == "NOANSWER":
            continue
        fqdn_to_dns_relationships.append(relationship)
        

    # == Output Layer ==

    print("\n\n\n FQDNs \n\n")
    print(FQDNs)

    print("\n\n\n Certificates \n\n")
    print(certificates)

    print("\n\n\n FQDN <-> pDNS \n\n")
    print(fqdn_to_historical_ip_relationships)

    print("\n\n\n CERT <-> FQDN \n\n")
    print(certificate_to_domain_relationships)

    print("\n\n\n FQDN <-> DNS \n\n")
    print(fqdn_to_dns_relationships)

main("example.com")

# Next Steps Post ASN and BGP Implementation
# Async, Potential utilisation of databases to reduce memory usage
# Fix typehinting
# AI implementation for automated inference of data, operational groupings, managemental groupings etc.
