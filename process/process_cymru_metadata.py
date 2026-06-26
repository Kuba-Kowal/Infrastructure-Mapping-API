from core.models import *
from core.generate_hash import generate_hash
import dns.resolver

def process_cymru_metadata(data: Answer, asn: str, graph: Graph) -> None:
    if data:
        for record in data:
            txt = record.to_text().strip('"')
            a, b, c, d, org = [x.strip() for x in txt.split("|")]

            org_object = Organisation(str(org))
            asn_object = ASN(asn)

            graph.add_node(org_object)
            
            graph.add_edge(AStoOrganisation(generate_hash(asn_object), generate_hash(org_object), Source.CYMRU))

    