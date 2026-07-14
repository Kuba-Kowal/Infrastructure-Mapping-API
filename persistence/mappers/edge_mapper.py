from core.graph import Graph
from core.models import *
from datetime import datetime

def map_edges(graph: Graph) -> tuple[str, str, str]:
    edge_mappings = ["cert_to_fqdn", "fqdn_to_dns", "fqdn_to_pdns", "ip_to_prefix", "prefix_to_asn", "asn_to_org"]

    edges = []

    for bucket in edge_mappings:
        for obj in graph.__getattribute__(bucket):
            edges.append((obj.source_data, obj.target_data, bucket, obj.observed_at))

    return edges