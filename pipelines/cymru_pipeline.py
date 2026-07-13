from core.graph import Graph
from fetch.cymru import fetch_origin_asn
from fetch.cymru import fetch_asn_metadata
from process.process_cymru_origin import process_cymru_origin
from process.process_cymru_metadata import process_cymru_metadata
import asyncio

async def cymru_pipeline(graph="hello") -> None:
    ips = graph.get_ips()

    origin_results = await asyncio.gather(
        *(fetch_origin_asn(ip) for ip in ips)
    )

    for ip, data in zip(ips, origin_results):
        process_cymru_origin(data, ip, graph)

    asns = [asn.data for asn in graph.asns.values()]

    asn_results = await asyncio.gather(
        *(fetch_asn_metadata(asn) for asn in asns)
    )

    for asn, data in zip(asns, asn_results):
        if data:
            process_cymru_metadata(data, asn, graph)

    