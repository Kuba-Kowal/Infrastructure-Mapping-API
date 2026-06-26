from core.models import *
from core.generate_hash import generate_hash
from datetime import date

def process_certspotter(cert_spotter_data: list[dict[str, str]], graph: Graph) ->  None:
    cert_spotter_FQDNs = set()

    for certificate in cert_spotter_data:
        # Extract issuer name
        if certificate.get('issuer') is not None:
            if certificate['issuer'].get('friendly_name') is not None:
                issuer = certificate['issuer']['friendly_name'].strip("\\")
            else:
                issuer = "Unknown"
        else:
            issuer = "Unknown"

        # Extract not before certificate field
        if certificate.get('not_before') is not None:
            date_field = certificate['not_before']
            not_before = date.fromisoformat(date_field[:10])
        else:
            not_before = None

        # Extract not after certificate field
        if certificate.get('not_after') is not None:
            date_field = certificate['not_after']
            not_after = date.fromisoformat(date_field[:10])
        else:
            not_after = None

        # Create certificate object utilising these fields
        cert_object = Certificate(str(certificate['id']), issuer, not_before, not_after)
        graph.add_node(cert_object)

        # Create FQDN object based on SANs
        if certificate.get('dns_names') is not None:
            for domain in certificate['dns_names']:
                fqdn_object = FQDN(domain)
                if domain not in cert_spotter_FQDNs:
                    cert_spotter_FQDNs.add(domain)
                    graph.add_node(fqdn_object)

                # Create FQDN <-> Certificate Mapping Object
                graph.add_edge(CerttoFQDN(generate_hash(cert_object), generate_hash(fqdn_object), Source.CERT_SPOTTER))