import dns.asyncresolver
import asyncio

async def resolve_dns_query(domain: str, rtype: str) -> dns.resolver.Answer | None:
    resolver = dns.asyncresolver.Resolver()

    print(f"[⋆] QUERY DNS - {rtype} | {domain}")
    try:
        result = await resolver.resolve(domain, rtype)
        return [str(r) for r in result]

    except(
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ):
        return None