from core.queue import *
from expand.expand_virustotal import expand_virustotal
from fetch.virustotal import fetch_vt
from process.process_virustotal import process_virustotal

def virustotal_pipeline(TARGET_DOMAIN: list[str], graph: Graph) -> None:
    queue = Queue(deque(TARGET_DOMAIN), set())

    while len(queue.queue) > 0:
        next_domain = queue.next_item_in_queue()

        raw_data = fetch_vt(next_domain)

        process_virustotal(raw_data, next_domain, graph)

        new_domains = expand_virustotal(raw_data)

        queue.add_to_queue(new_domains)