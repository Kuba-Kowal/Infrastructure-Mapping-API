from pipelines.dns_pipeline import dns_pipeline
from pipelines.virustotal_pipeline import virustotal_pipeline
from pipelines.crtsh_pipeline import crtsh_pipeline
from pipelines.certspotter_pipeline import certspotter_pipeline
from pipelines.cymru_pipeline import cymru_pipeline
from core.graph import Graph
from core.models import *
from core.configuration import create_config
from core.write_to_json import write_to_json
import sys
import asyncio
import time

graph = Graph()

async def main(input_data, config):
    try:
        for domain in input_data:
            graph.fqdns.add(FQDN(domain))

        start = time.perf_counter()

        async with asyncio.TaskGroup() as tg:
            print("\n-- [+] BEGIN PASSIVE RECON --\n")
            if config["virustotal"]:
                tg.create_task(virustotal_pipeline(graph))

            if config["crtsh"]:
                while True:
                    try:
                        tg.create_task(crtsh_pipeline(graph))
                        break
                    except ValueError:
                        continue

            if config["certspotter"]:
                tg.create_task(certspotter_pipeline(graph))

        print("\n-- [+] BEGIN DNS RECON --\n")
        dns_pipeline(graph)

        print("\n-- [+] BEGIN BGP RECON --\n")
        cymru_pipeline(graph)

        end = time.perf_counter()

        write_to_json(graph, config)

        print(f"\n\n\n\nTotal runtime: {end - start:.2f} seconds\n\n\n\n")

    except asyncio.CancelledError:
        print("\nExiting.")
        sys.exit()

    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit()


config = create_config()
asyncio.run(main([domain for domain in config["domains"]], config))