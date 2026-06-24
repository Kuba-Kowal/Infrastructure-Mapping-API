from core.queue import *
from expand.expand_virustotal import expand_virustotal
from fetch.virustotal import fetch_virustotal
from process.process_virustotal import process_virustotal
import asyncio
import aiohttp

async def virustotal_pipeline(graph: Graph) -> None:
    seen = set()
    sem = asyncio.Semaphore(4)

    async with aiohttp.ClientSession() as session:
        tasks = {}

        for fqdn in graph.fqdns:
            domain = fqdn.domain

            seen.add(domain)

            task = asyncio.create_task(fetch_virustotal(domain, sem, session))
            tasks[task] = domain

        while tasks:
            done, _ = await asyncio.wait(
                tasks.keys(),
                return_when = asyncio.FIRST_COMPLETED
            )

            for task in done:
                domain = tasks.pop(task)

                raw_data = await task

                if raw_data:
                    process_virustotal(raw_data, domain, graph)

                    new_domains = expand_virustotal(raw_data)

                else:
                    new_domains = None

                if new_domains:
                    for new_domain in new_domains:
                        if new_domain in seen:
                            continue

                        seen.add(new_domain)

                        new_task = asyncio.create_task(fetch_virustotal(new_domain, sem, session))
                        tasks[new_task] = new_domain

    return