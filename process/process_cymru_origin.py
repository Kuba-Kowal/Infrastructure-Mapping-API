from core.models import *


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
                asn_object = ASN(asn)

                graph.ips.add(ip_object)
                graph.asns.add(asn_object)
                graph.prefixes.add(prefix_object)

                graph.ip_to_prefix.add(IPtoPrefix(ip_object, prefix_object, Source.CYMRU))
                graph.prefix_to_asn.add(PrefixtoASN(prefix_object, asn_object, Source.CYMRU))