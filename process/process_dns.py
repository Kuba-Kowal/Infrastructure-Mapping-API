from core.models import *

def process_dns(data: iter[str], rtype: str, domain: str, graph: Graph) -> None:
    if rtype == "CNAME":
        for extracted_domain in data:
            graph.fqdns.add(FQDN(extracted_domain))
            graph.fqdn_to_dns.add(FQDNtoDNS(FQDN(domain), "CNAME", tuple(data)))

    elif rtype == "A" or rtype == "AAAA":
        for ip in data:
            graph.ips.add(IPAddress(ip))

        graph.fqdn_to_dns.add(FQDNtoDNS(domain, rtype, tuple(data)))
        
    else:
        graph.fqdn_to_dns.add(FQDNtoDNS(FQDN(domain), rtype, tuple(data)))