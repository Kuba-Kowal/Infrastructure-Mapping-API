from core.queue import *
from fetch.fetch_dns import resolve_dns_query
from expand.expand_cname import expand_cname
from process.process_dns import process_dns

DNS_RECORD_TYPES = (
    "A", 
    "AAAA", 
    "NS", 
    "MX", 
    "TXT", 
    "SOA", 
    "SRV"
)

def dns_pipeline(graph: Graph) -> None:
    queue = Queue(deque(graph.get_domains()), set())

    while len(queue.queue):
        domain = queue.next_item_in_queue()

        if domain.startswith("*"):
            continue

        dns_answer = resolve_dns_query(domain, "CNAME")

        if dns_answer:
            process_dns(dns_answer, "CNAME", domain, graph)

            new_domain = expand_cname(dns_answer)
            queue.add_to_queue([new_domain])

        for rtype in DNS_RECORD_TYPES:
            dns_answer = resolve_dns_query(domain, rtype)

            if dns_answer:
                process_dns(dns_answer, rtype, domain, graph)