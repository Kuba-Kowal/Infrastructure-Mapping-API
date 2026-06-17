from core.models import *
from datetime import date

def process_certspotter(cert_spotter_data: list[dict[str, str]], graph: Graph) ->  None:
    cert_spotter_FQDNs = set()

    for certificate in cert_spotter_data:
        # Extract issuer name
        if certificate.get('issuer') is not None:
            if certificate['issuer'].get('friendly_name') is not None:
                issuer = certificate['issuer']['friendly_name']
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
        cert_object = Certificate(certificate['id'], issuer, not_before, not_after)
        graph.certificates.add(cert_object)

        # Create FQDN object based on SANs
        if certificate.get('dns_names') is not None:
            for domain in certificate['dns_names']:
                fqdn_object = FQDN(domain)
                if domain not in cert_spotter_FQDNs:
                    cert_spotter_FQDNs.add(domain)
                    if domain.startswith("*"):
                        continue
                    graph.fqdns.add(fqdn_object)

                # Create FQDN <-> Certificate Mapping Object
                graph.cert_to_fqdn.add(CerttoFQDN(cert_object, fqdn_object, Source.CERT_SPOTTER))