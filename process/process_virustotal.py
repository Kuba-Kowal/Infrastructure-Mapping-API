from core.models import *
from core.generate_hash import generate_hash

def process_virustotal(vt_data: list[dict[str, str]], domain: str, graph: Graph) -> None:
    fqdn_object = FQDN(domain)

    # Create FQDN Objects
    graph.add_node(fqdn_object)

    # Create IP Objects
    if vt_data.get('resolutions') is not None:
        for ip in vt_data['resolutions']:
            if ip.get('ip_address') is not None:
                ip_addr = ip['ip_address']
            else:
                ip_addr = ""

            """
            if ip.get('last_resolved') is not None:     UNUSED LOGIC, grabs the last resolved time.
                last_observed = ip['last_resolved']
            else:
                last_observed = "unkown"
            """

            ip_object = IPAddress(ip_addr)
            graph.add_node(ip_object)

            # Create FQDN to pDNS Relationship Object
            graph.fqdn_to_pdns.add(FQDNtoPassiveDNS(generate_hash(fqdn_object), generate_hash(ip_object), Source.VIRUSTOTAL))