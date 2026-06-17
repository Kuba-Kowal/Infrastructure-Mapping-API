from dataclasses import dataclass, field
from core.models import *

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

    def get_domains(self) -> list[str]:
        return [fqdn.domain for fqdn in self.fqdns]

    def get_ips(self) -> list[str]:
        return [ipaddress.ip for ipaddress in self.ips]
