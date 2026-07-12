from core.queue import Queue
from core.graph import Graph
from fetch.crtsh import fetch_crtsh
from expand.expand_crtsh import expand_crtsh
from process.process_crtsh import process_crtsh
from collections import deque
import asyncio
import aiohttp

async def crtsh_pipeline(graph: Graph) -> None:
    seen = set()
    sem = asyncio.Semaphore(2)
    completed = 0

    async with aiohttp.ClientSession() as session:
        tasks = {}

        for fqdn in graph.fqdns:
            domain = fqdn.data

            seen.add(domain)

            task = asyncio.create_task(fetch_crtsh(domain, sem, session))
            tasks[task] = domain

        while tasks:
            done, _ = await asyncio.wait(
                tasks.keys(),
                return_when = asyncio.FIRST_COMPLETED
            )

            for task in done:
                tasks.pop(task)

                raw_data = await task

                if raw_data:
                    process_crtsh(raw_data, graph)

                    new_domains = expand_crtsh(raw_data)

                    completed += 1

                elif completed == 0:
                    raise ValueError("NO_RESULTS")

                else:
                    new_domains = None

                if new_domains:
                    for new_domain in new_domains:
                        if new_domain in seen:
                            continue

                        seen.add(new_domain)

                        new_task = asyncio.create_task(fetch_crtsh(new_domain, sem, session))
                        tasks[new_task] = new_domain