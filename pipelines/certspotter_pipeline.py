from core.queue import Queue
from core.graph import Graph
from fetch.certspotter import fetch_certspotter
from expand.expand_certspotter import expand_certspotter
from process.process_cerspotter import process_certspotter
from collections import deque

def certspotter_pipeline(graph: Graph) -> None:
    queue = Queue(deque(graph.get_domains()), set())

    while len(queue.queue) > 0:
        domain = queue.next_item_in_queue()

        raw_data = fetch_certspotter(domain)

        process_certspotter(raw_data, graph)

        new_domains = expand_certspotter(raw_data)
        
        queue.add_to_queue(new_domains)