from dataclasses import dataclass, field, asdict
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

    """
    graph_map = {
        Certificate: {self.certificates: Certificate.id},
        FQDN: {self.fqdns: FQDN.domain},
        IPAddress: self.ips,
        Prefix: self.prefixes,
        ASN: self.asns,
        Organisation: self.organisations
    }
    """

    def get_domains(self) -> list[str]:
        return [fqdn.domain for fqdn in self.fqdns]

    def get_ips(self) -> list[str]:
        return [ipaddress.ip for ipaddress in self.ips]

    def add_node(self, obj):
        """
        bucket = self.graph_map[type(obj)]

        data = f"{bucket}"


        generated_hash = hashlib.sha256(data).hexdigest()

        self.graph_map[type(obj)][generated_hash] = obj
        """
        pass

    def add_edge(self, src_obj, target_obj) -> None:
        pass


    def to_dict(self) -> [dict[str, [dict[str, str]]]]:
        return {
            "certificates": [asdict(c) for c in self.certificates],
            "fqdns": [asdict(f) for f in self.fqdns],
            "ips": [asdict(i) for i in self.ips],
            "prefixes": [asdict(p) for p in self.prefixes],
            "asns": [asdict(a) for a in self.asns],
            "organisations": [asdict(o) for o in self.organisations],

            "cert_to_fqdn": [asdict(r) for r in self.cert_to_fqdn],
            "fqdn_to_dns": [asdict(r) for r in self.fqdn_to_dns],
            "fqdn_to_pdns": [asdict(r) for r in self.fqdn_to_pdns],
            "ip_to_prefix": [asdict(r) for r in self.ip_to_prefix],
            "prefix_to_asn": [asdict(r) for r in self.prefix_to_asn],
            "asn_to_org": [asdict(r) for r in self.asn_to_org],
        }