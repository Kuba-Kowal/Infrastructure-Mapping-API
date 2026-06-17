from core.models import *
import dns.resolver

def process_cymru_metadata(data: Answer, asn: str, graph: Graph) -> None:
    if data:
        for record in data:
            txt = record.to_text().strip('"')
            a, b, c, d, org = [x.strip() for x in txt.split("|")]

            org_object = Organisation(str(org))
            asn_object = ASN(asn)

            graph.organisations.add(Organisation(org_object))
            
            graph.asn_to_org.add(ASToOrganisation(asn_object, org_object, Source.CYMRU))

    