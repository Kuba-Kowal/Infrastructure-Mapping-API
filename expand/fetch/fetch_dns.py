import dns.resolver

def resolve_dns_query(domain: str, rtype: str) -> dns.resolver.Answer | None:
    print(f"[⋆] QUERY DNS - {rtype} | {domain}")
    try:
        return [r.to_text() for r in dns.resolver.resolve(domain, rtype)]

    except(
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
    ):
        return None