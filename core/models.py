from dataclasses import dataclass
# ----------------------------
# Data models - Raw
# ----------------------------
class Source(str):
    CRT_SH = "crt.sh"
    CERT_SPOTTER = "certspotter"
    CYMRU = "cymru"
    VIRUSTOTAL = "virustotal"

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
    data: str # Certificate id
    properties: dict[str, Any]
    """
    issuer: str
    not_before: date
    not_after: date
    """

@dataclass(frozen=True, slots=True)
class FQDN:
    data: str

@dataclass(frozen=True, slots=True)
class IPAddress:
    data: str

@dataclass(frozen=True, slots=True)
class ASN:
    data: int

@dataclass(frozen=True, slots=True)
class Prefix:
    data: str

@dataclass(frozen=True, slots=True)
class Organisation:
    data: str

@dataclass(frozen=True, slots=True)
class DNSRecord:
    data: list[str]
    properties: str

# ----------------------------
# Data models - Relational
# ----------------------------

@dataclass(frozen=True, slots=True)
class CerttoFQDN:
    source_data: str
    target_data: str
    observed_at: Source

@dataclass(frozen=True, slots=True)
class IPtoPrefix:
    source_data: str
    target_data: str
    observed_at: Source

@dataclass(frozen=True, slots=True)
class PrefixtoASN:
    source_data: str
    target_data: str
    observed_at: Source

@dataclass(frozen=True, slots=True)
class AStoOrganisation:
    source_data: str
    target_data: str
    observed_at: Source

@dataclass(frozen=True, slots=True)
class FQDNtoDNS:
    source_data: str
    target_data: str
    observed_at: Source

@dataclass(frozen=True, slots=True)
class FQDNtoPassiveDNS:
    source_data: str
    target_data: str
    observed_at: Source