from core.models import *
from core.generate_hash import generate_hash

def process_dns(dns_records: dict[str, dict[str, Any]], graph: Graph) -> None:
    for domain, properties in dns_records.items():
        for rtype, data in properties.items():
            dns_object = DNSRecord(data, rtype)
            graph.add_node(dns_object)

            if rtype == "CNAME":
                for extracted_domain in data:
                    fqdn_object = FQDN(extracted_domain.removesuffix("."))
                    graph.add_node(fqdn_object)
                    graph.fqdn_to_dns.add(FQDNtoDNS(generate_hash(fqdn_object), generate_hash(dns_object), Source.CYMRU))

            else:
                if rtype == "A" or rtype == "AAAA":
                    for ip in data:
                        graph.add_node(IPAddress(ip))

                graph.fqdn_to_dns.add(FQDNtoDNS(generate_hash(FQDN(domain.removesuffix("."))), generate_hash(dns_object), Source.CYMRU))