from core.models import *
from core.generate_hash import generate_hash
from datetime import date

def process_crtsh(crt_sh_data: list[dict[str, str]], graph: Graph) -> None:
    crt_sh_FQDNs = set()

    for certificate in crt_sh_data:
        # Extract issuer name
        if certificate.get('issuer_name') is not None:
            if "O=" in certificate['issuer_name']:
                issuer = next(
                    field.strip().split("=", 1)[1]
                    for field in certificate['issuer_name'].split(",")
                    if field.strip().startswith("O=")
                )
                issuer = issuer.strip("\\").strip('"')
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
        cert_id = str(certificate["id"])

        cert_object = Certificate(cert_id, {
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after
        })
        
        graph.add_node(cert_object)

        # Create FQDN object based on SANs
        for domain in certificate["name_value"].split('\n'):
            fqdn_object = FQDN(domain)
            if domain not in crt_sh_FQDNs:
                crt_sh_FQDNs.add(domain)
                graph.fqdns.add(fqdn_object)

            # Create FQDN <-> Certificate Mapping Object
            graph.cert_to_fqdn.add(CerttoFQDN(generate_hash(cert_object), generate_hash(fqdn_object), Source.CRT_SH))