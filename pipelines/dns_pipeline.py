from fetch.fetch_dns import resolve_dns_query
from expand.expand_cname import expand_cname
from process.process_dns import process_dns
from collections import defaultdict
import asyncio

DNS_RECORD_TYPES = (
    "A", 
    "AAAA", 
    "NS", 
    "MX", 
    "TXT", 
    "SOA", 
    "SRV"
)

def seed_dns_tasks(domain, tasks):
    for rtype in DNS_RECORD_TYPES:
        task = asyncio.create_task(resolve_dns_query(domain, rtype))
        tasks[task] = (domain, rtype)

async def dns_pipeline(graph: Graph) -> None:
    queue = graph.get_domains()
    tasks = {}
    dns_records = defaultdict(dict) # The missing value for any dictionary is a dictionary.

    for domain in queue:
        if domain.startswith("*"):
            continue
        seed_dns_tasks(domain, tasks)

    while tasks:
        done, _ = await asyncio.wait(
            tasks.keys(),
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in done:
            domain, rtype = tasks.pop(task) # we pop the task, before we await it incase an exception is raised, and the task stays inside the dictionary.

            raw_data = await task

            if not raw_data:
                continue

            if rtype == "CNAME":
                for record in raw_data:
                    domain = record.removesuffix(".")

                    if domain.startswith("*"):
                        continue

                    seed_dns_tasks(domain, tasks)

                    dns_records[domain][rtype] = raw_data

            else:
                dns_records[domain][rtype] = raw_data

    process_dns(dns_records, graph)