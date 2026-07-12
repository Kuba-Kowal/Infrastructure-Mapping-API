from core.graph import Graph
from core.models import *
import json

def map_nodes(graph: Graph) -> tuple[str, str, Any, Any]:
    nodes = []

    for cert_hash, cert in graph.certificates.items():
        nodes.append(
            (
                cert_hash,
                "CERT",
                cert.data,
                json.dumps({x: str(y) for x, y in cert.properties.items()})
            )
        )

    for fqdn_hash, fqdn in graph.fqdns.items():
        nodes.append(
            (
                fqdn_hash,
                "FQDN",
                fqdn.data,
                None
            )
        )

    for ip_hash, ip in graph.ips.items():
        nodes.append(
            (
                ip_hash,
                "IP",
                ip.data,
                None
            )
        )

    for asn_hash, asn in graph.asns.items():
        nodes.append(
            (
                asn_hash,
                "ASN",
                asn.data,
                None
            )
        )

    for prefix_hash, prefix in graph.prefixes.items():
        nodes.append(
            (
                prefix_hash,
                "PREFIX",
                prefix.data,
                None
            )
        )

    for org_hash, org in graph.organisations.items():
        nodes.append(
            (
                org_hash,
                "ORG",
                org.data,
                None
            )
        )

    for record_hash, record in graph.dns_records.items():
        nodes.append(
            (
                record_hash,
                "DNS",
                ",".join(record.data),
                json.dumps({"properties": record.properties})
            )
        )

    return nodes