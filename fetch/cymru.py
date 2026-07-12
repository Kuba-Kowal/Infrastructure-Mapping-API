import dns.asyncresolver
import asyncio

async def fetch_origin_asn(ip: str) -> dns.resolver.Answer | None:
    resolver = dns.asyncresolver.Resolver()

    print(f"[⋆] QUERY ASN ORIGIN | {ip}")
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"

        result = await(resolver.resolve(query, "TXT"))
        return result
                
    except(
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ):
        return None
    

async def fetch_asn_metadata(asn: str) -> dns.resolver.Answer | None:
    resolver = dns.asyncresolver.Resolver()

    print(f"[⋆] QUERY ASN ORGANISATION | {asn}")
    try:
        query = f"AS{asn}.asn.cymru.com"

        result = await(resolver.resolve(query, "TXT"))
        return result

    except(
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ):
        return None

