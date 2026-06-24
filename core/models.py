from dataclasses import dataclass
# ----------------------------
# Data models - Raw
# ----------------------------
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