from core.models import *
from core.generate_hash import generate_hash

def process_cymru_origin(data: dict[str, str], ip: str, graph: Graph) -> None:
    results = []
    if data:
        for record in data:
            txt = record.to_text().strip('"')
            asn, prefix, country, rir, date = [x.strip() for x in txt.split("|")]

            results.append({
                "ip": ip,
                "asn": asn,
                "prefix": prefix,
                "country": country,
                "date": date
            })

            if results:
                ip_object = IPAddress(ip)
                prefix_object = Prefix(prefix)

                graph.add_node(ip_object)
                graph.add_node(prefix_object)

                graph.ip_to_prefix.add(IPtoPrefix(generate_hash(ip_object), generate_hash(prefix_object), Source.CYMRU))

                if " " in asn:
                    asns = asn.split(" ")
                    for asn in asns:
                        asn_object = ASN(asn)
                        graph.add_node(asn_object)
                        graph.prefix_to_asn.add(PrefixtoASN(generate_hash(prefix_object), generate_hash(asn_object), Source.CYMRU))

                else:
                    asn_object = ASN(asn)
                    graph.add_node(asn_object)
                    graph.prefix_to_asn.add(PrefixtoASN(generate_hash(prefix_object), generate_hash(asn_object), Source.CYMRU))
