import dns.resolver

def fetch_origin_asn(ip: str) -> dns.resolver.Answer | None:
    print(f"[⋆] QUERY ASN ORIGIN | {ip}")
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"

        return dns.resolver.resolve(query, "TXT")
                
    except(
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
    ):
        return None
    

def fetch_asn_metadata(asn: str) -> dns.resolver.Answer | None:
    print(f"[⋆] QUERY ASN ORGANISATION | {asn}")
    try:
        query = f"AS{asn}.asn.cymru.com"

        return dns.resolver.resolve(query, "TXT")

    except(
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
    ):
        return None

