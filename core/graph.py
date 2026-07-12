from dataclasses import dataclass, field, asdict
from core.models import *
from core.generate_hash import generate_hash
import tldextract

@dataclass(slots=True)
class Graph:
    apex_domain: str = field(default_factory=str)

    certificates: dict[str, Certificate] = field(default_factory=dict)
    fqdns: dict[str, FQDN] = field(default_factory=dict)
    ips: dict[str, IPAddress] = field(default_factory=dict)
    prefixes: dict[str, Prefix] = field(default_factory=dict)
    asns: dict[str, ASN] = field(default_factory=dict)
    organisations: dict[str, Organisation] = field(default_factory=dict)
    dns_records: dict[str, DNSRecord] = field(default_factory=dict)

    cert_to_fqdn: set[CerttoFQDN] = field(default_factory=set)
    fqdn_to_dns: set[FQDNtoDNS] = field(default_factory=set)
    fqdn_to_pdns: set[FQDNtoPassiveDNS] = field(default_factory=set)
    ip_to_prefix: set[IPToPrefix] = field(default_factory=set)
    prefix_to_asn: set[PrefixToASN] = field(default_factory=set)
    asn_to_org: set[AStoOrganisation] = field(default_factory=set)

    node_bucket_table = {
        "Certificate": "certificates",
        "FQDN": "fqdns",
        "IPAddress": "ips",
        "ASN": "asns",
        "Prefix": "prefixes",
        "Organisation": "organisations",
        "DNSRecord": "dns_records"
    }

    def extract_apex(self, domain) -> str:
        result = tldextract.extract(domain)

        return f"{result.domain}.{result.suffix}"

    def get_domains(self) -> list[str]:
        return [fqdn.data for fqdn in self.fqdns.values()]

    def get_ips(self) -> list[str]:
        return [ipaddress.data for ipaddress in self.ips.values()]

    def get_object_type(self, obj: Object) -> type(obj):
        try:
            return obj.__class__.__name__
        except:
            return "IPAddress"

    def add_node(self, obj: Object) -> None:
        object_type = self.get_object_type(obj)
        node_bucket = self.node_bucket_table[object_type]

        node_hash = generate_hash(obj)

        if node_hash in self.__getattribute__(node_bucket).values():
            pass
        else:
            self.__getattribute__(node_bucket)[node_hash] = obj

    def json_to_dict(self) -> [dict[str, [dict[str, str]]]]:
        return {
            "certificates": {cert_hash: {"id": cert.data, "properties": cert.properties} for cert_hash, cert in self.certificates.items()},
            "fqdns": {fqdn_hash: fqdn.data for fqdn_hash, fqdn in self.fqdns.items()},
            "ips": {ip_hash: ip_address.data for ip_hash, ip_address in self.ips.items()},
            "prefixes": {prefix_hash: prefix.data for prefix_hash, prefix in self.prefixes.items()},
            "asns": {asn_hash: asn.data for asn_hash, asn in self.asns.items()},
            "organisations": {org_hash: organisation.data for org_hash, organisation in self.organisations.items()},
            "dns_records": {dns_hash: {"data": dns_record.data, "rtype": dns_record.properties} for dns_hash, dns_record in self.dns_records.items()},

            "cert_to_fqdn": [asdict(r) for r in self.cert_to_fqdn],
            "fqdn_to_dns": [asdict(r) for r in self.fqdn_to_dns],
            "fqdn_to_pdns": [asdict(r) for r in self.fqdn_to_pdns],
            "ip_to_prefix": [asdict(r) for r in self.ip_to_prefix],
            "prefix_to_asn": [asdict(r) for r in self.prefix_to_asn],
            "asn_to_org": [asdict(r) for r in self.asn_to_org],
            
        }