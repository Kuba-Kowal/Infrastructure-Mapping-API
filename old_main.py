import requests
import json
import time
import os
import dns.resolver
from dotenv import load_dotenv
from dataclasses import dataclass, field
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

@dataclass(slots=True)
class Graph:
    certificates: set[Certificate] = field(default_factory=set)
    fqdns: set[FQDN] = field(default_factory=set)
    ips: set[IPAddress] = field(default_factory=set)
    prefixes: set[Prefix] = field(default_factory=set)
    asns: set[ASN] = field(default_factory=set)
    organisations: set[Organisation] = field(default_factory=set)

    cert_to_fqdn: set[CertToFQDN] = field(default_factory=set)
    fqdn_to_dns: set[FQDNToDNS] = field(default_factory=set)
    fqdn_to_pdns: set[FQDNToPassiveDNS] = field(default_factory=set)
    ip_to_prefix: set[IPToPrefix] = field(default_factory=set)
    prefix_to_asn: set[PrefixToASN] = field(default_factory=set)
    asn_to_org: set[ASNToOrganisation] = field(default_factory=set)

class Source(str):
    CRT_SH = "crt.sh"
    CERT_SPOTTER = "certspotter"
    CYMRU = "cymru"
    VIRUSTOTAL = "virustotal"

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

@dataclass(frozen=True, slots=True)
class Prefix:
    prefix: str

@dataclass(frozen=True, slots=True)
class Organisation:
    organisation: str

# ----------------------------
# Data models - Relational
# ----------------------------

@dataclass(frozen=True, slots=True)
class CerttoFQDN:
    certificate: Certificate
    fqdn: FQDN
    observed_at: Soure

@dataclass(frozen=True, slots=True)
class IPtoPrefix:
    ip: IPAddress
    prefix: Prefix
    observed_at: Source

@dataclass(frozen=True, slots=True)
class PrefixtoASN:
    prefix: Prefix
    asn: ASN
    observed_at: Source

@dataclass(frozen=True, slots=True)
class ASToOrganisation:
    asn: ASN
    organisation: Organisation
    observed_at: Source

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
    observed_at: Source

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
    

    queue = Queue(deque([TARGET_DOMAIN]), set())

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

    queue = Queue(deque([TARGET_DOMAIN]), set())

    while len(queue.queue) > 0:
        next_domain = queue.next_item_in_queue()

        data, new_domains = fetch_vt(next_domain)

        vt_results.append(data)

        queue.add_to_queue(new_domains)

    return vt_results

# ----------------------------
# Data Processing Layer (Certificate Objects)
# ----------------------------
def process_crt_sh_log_data(crt_sh_data: list[dict[str, str]], graph: Graph) -> None:
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
        graph.certificates.add(cert_object)

        # Create FQDN object based on SANs
        for domain in certificate["name_value"].split('\n'):
            fqdn_object = FQDN(domain)
            if domain not in crt_sh_FQDNs:
                crt_sh_FQDNs.add(domain)
                graph.fqdns.add(fqdn_object)

            # Create FQDN <-> Certificate Mapping Object
            graph.cert_to_fqdn.add(CerttoFQDN(cert_object, fqdn_object, Source.CRT_SH))

def process_cert_spotter_data(cert_spotter_data: list[dict[str, str]], graph: Graph) ->  None:
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
        graph.certificates.add(cert_object)

        # Create FQDN object based on SANs
        if certificate.get('dns_names') is not None:
            for domain in certificate['dns_names']:
                fqdn_object = FQDN(domain)
                if domain not in cert_spotter_FQDNs:
                    cert_spotter_FQDNs.add(domain)
                    graph.fqdns.add(fqdn_object)

                # Create FQDN <-> Certificate Mapping Object
                graph.cert_to_fqdn.add(CerttoFQDN(cert_object, fqdn_object, Source.CERT_SPOTTER))

def process_vt_data(vt_data: list[dict[str, str]], graph: Graph) -> None:
    seen_FQDNs = set()

    # Itterate through dataset
    for entry in vt_data:
            for domain, report in entry.items():
                fqdn_object = FQDN(domain)

                # Create FQDN Objects
                if domain not in seen_FQDNs:
                    seen_FQDNs.add(domain)
                    graph.fqdns.add(fqdn_object)
        
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
                        graph.ips.add(ip_object)

                        # Create FQDN to pDNS Relationship Object
                        graph.fqdn_to_pdns.add(FQDNtoPassiveDNS(fqdn_object, ip_object, last_observed, Source.VIRUSTOTAL))

def fetch_asn_data_pipeline(list_of_ips: list[IPAddress]) -> list[dict[str, str]]:
    results = []
    seen = set()

    for ip in list_of_ips:
        ip = ip.ip

        if ip in seen:
            continue
        seen.add(ip)

        try:
            reversed_ip = ".".join(reversed(ip.split(".")))

            print(f"[⋆] QUERY CYMRU ORIGIN ASN | {ip}")
            query = f"{reversed_ip}.origin.asn.cymru.com"
            answer = dns.resolver.resolve(query, "TXT")

            for record in answer:
                txt = record.to_text().strip('"')
                asn, prefix, country, rir, date = [x.strip() for x in txt.split("|")]
                org = fetch_org_from_asn(asn)

                results.append({
                    "ip": ip,
                    "asn": asn,
                    "prefix": prefix,
                    "org": org,
                    "date": date
                })
                
        except dns.resolver.NXDOMAIN:
            continue

    return results

def fetch_org_from_asn(asn: str) -> str:
    print(f"[⋆] QUERY ASN ORGANISATION | {asn}")

    query = f"AS{asn}.asn.cymru.com"
    answer = dns.resolver.resolve(query, "TXT")

    for record in answer:
        txt = record.to_text().strip('"')
        _, _, _, _, org = [x.strip() for x in txt.split("|")]

    org = org.split(" ")
    org = org[0].strip()

    return org

# ----------------------------
# Data Collection & Processing Layer (FQDNtoDNS Objects)
# ----------------------------

def dns_record_pipeline(FQDN_data: list[FQDN], graph: Graph) -> list[FQDNtoDNS]:
    seen = set()
    domains = set()
    for domain in FQDN_data:
        domains.add(domain.domain)

    while len(domains) > 0:
        domain = domains.pop()
        if domain.startswith("*"):
            continue
        if domain in seen:
            continue

        print(f"[+] DNS TYPE: CNAME | {domain}")

        try:
            query_result = resolve_dns_query(domain, "CNAME")

        except dns.resolver.NXDOMAIN:
            continue

        except dns.resolver.NoAnswer:
            continue 

        for result in query_result:
            domains.add(str(result))
            query_result = result

        graph.fqdns.add(FQDN(domain))
        graph.fqdn_to_dns.add(FQDNtoDNS(FQDN(domain), "CNAME", query_result))

        infrastructure_mapping_records = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "SRV"]
        for record_type in infrastructure_mapping_records:
            if domain.startswith("*"):
                continue
            print(f"[+] DNS TYPE: {record_type} | {domain}")
            
            try:
                query_result = resolve_dns_query(domain, record_type)
                for query in query_result:
                    query_result = query

            except dns.resolver.NXDOMAIN:
                continue

            except dns.resolver.NoAnswer:
                continue 

            graph.fqdn_to_dns.add(FQDNtoDNS(domain, record_type, query_result))

def process_asn_data(data: list[dict[str: str]], graph: Graph) -> None:
    for record in data:
        asn = ASN(record["asn"])
        prefix = Prefix(record["prefix"])
        ip = IPAddress(record["ip"])
        org = Organisation(record["org"])

        graph.asns.add(asn)
        graph.prefixes.add(prefix)
        graph.organisations.add(org)
        
        graph.prefix_to_asn.add(PrefixtoASN(prefix, asn, Source.CYMRU))
        graph.ip_to_prefix.add(IPtoPrefix(ip, prefix, Source.CYMRU))
        graph.asn_to_org.add(ASToOrganisation(asn, org, Source.CYMRU))

def main(TARGET_DOMAIN: str) -> None:
    load_dotenv()
    graph = Graph()

    print("[+] BEGIN HISTORICAL DNS & SUBDOMAIN PIPELINE\n")
    # == Certificate & Subdomain Layer ==
    vt_data = vt_fetch_pipeline(TARGET_DOMAIN)

    print("\n[+] BEGIN CERTIFICATE LOG PIPELINE\n")
    crt_sh_data, cert_spotter_data = ct_log_fetch_pipeline(TARGET_DOMAIN)

    process_crt_sh_log_data(crt_sh_data, graph)
    process_cert_spotter_data(cert_spotter_data, graph)
    process_vt_data(vt_data, graph)

    # == DNS Layer ==
    print("\n[+] BEGIN DNS PIPELINE\n")
    dns_record_pipeline(graph.fqdns, graph)

    # == BGP Layer ==
    print("\n[+] BEGIN BGP PIPELINE\n")
    asn_data = fetch_asn_data_pipeline(graph.ips)
    process_asn_data(asn_data, graph)
        

    # == Output Layer ==
    print(graph)

main("example.com")
