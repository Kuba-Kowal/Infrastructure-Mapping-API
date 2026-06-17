from core.queue import Queue
from core.graph import Graph
from fetch.crtsh import fetch_crtsh
from expand.expand_crtsh import expand_crtsh
from process.process_crtsh import process_crtsh
from collections import deque

def crtsh_pipeline(graph: Graph) -> None:
    queue = Queue(deque(graph.get_domains()), set())

    while len(queue.queue) > 0:
        domain = queue.next_item_in_queue()

        raw_data = fetch_crtsh(domain)

        process_crtsh(raw_data, graph)

        new_domains = expand_crtsh(raw_data)

        queue.add_to_queue(new_domains)