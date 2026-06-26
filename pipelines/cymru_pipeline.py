from core.queue import Queue
from core.graph import Graph
from fetch.cymru import fetch_origin_asn
from fetch.cymru import fetch_asn_metadata
from process.process_cymru_origin import process_cymru_origin
from process.process_cymru_metadata import process_cymru_metadata
from collections import deque

def cymru_pipeline(graph: Graph) -> None:
    queue = Queue(deque(graph.get_ips()), set())

    while len(queue.queue) > 0:
        ip = queue.next_item_in_queue()

        cymru_origin = fetch_origin_asn(ip)

        process_cymru_origin(cymru_origin, ip, graph)

    for asn in graph.asns.values():
        asn = asn.as_number

        asn_metadata = fetch_asn_metadata(asn)

        if asn_metadata:
            asn_metadata = process_cymru_metadata(asn_metadata, asn, graph)

    