from pipelines.dns_pipeline import dns_pipeline
from pipelines.virustotal_pipeline import virustotal_pipeline
from pipelines.crtsh_pipeline import crtsh_pipeline
from pipelines.certspotter_pipeline import certspotter_pipeline
from pipelines.cymru_pipeline import cymru_pipeline
from core.graph import Graph
from core.models import *

graph = Graph()

TARGET_DOMAINS = ["example.com"]

def main(TARGET_DOMAINS):
    print("\n-- [+] BEGIN VT RECON --\n")
    virustotal_pipeline(TARGET_DOMAINS, graph)

    print("\n-- [+] BEGIN CRTSH RECON --\n")
    crtsh_pipeline(graph)

    print("\n-- [+] BEGIN CERTSPOTTER RECON --\n")
    certspotter_pipeline(graph)


    print("\n-- [+] BEGIN DNS RECON --\n")
    dns_pipeline(graph)

    print("\n-- [+] BEGIN BGP RECON --\n")
    cymru_pipeline(graph)

main(TARGET_DOMAINS)

print(graph)
