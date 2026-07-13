from core.graph import Graph
from fetch.certspotter import fetch_certspotter
from expand.expand_certspotter import expand_certspotter
from process.process_cerspotter import process_certspotter
import asyncio
import aiohttp

async def certspotter_pipeline(graph: Graph) -> None:
    seen = set()
    sem = asyncio.Semaphore(2)

    async with aiohttp.ClientSession() as session:
        tasks = {}

        # Seeding - create first group of tasks based on input graph
        for fqdn in graph.fqdns.values():
            domain = fqdn.data

            seen.add(domain)

            task = asyncio.create_task(fetch_certspotter(domain, sem, session))
            tasks[task] = domain

        # Run when tasks[str[asyncio.Task]] 
        while tasks:
            done, _ = await asyncio.wait(
                tasks.keys(),
                return_when = asyncio.FIRST_COMPLETED
            )

            for task in done:
                tasks.pop(task)

                raw_data = await task

                if raw_data:
                    process_certspotter(raw_data, graph)

                    new_domains = expand_certspotter(raw_data)

                else:
                    new_domains = None

                if new_domains:
                    for new_domain in new_domains:
                        if new_domain in seen:
                            continue

                        seen.add(new_domain)

                        new_task = asyncio.create_task(fetch_certspotter(new_domain, sem, session))
                        tasks[new_task] = new_domain

    return