from typing import Any

def expand_certspotter(raw_data: list[dict[str, Any]]):
    new_domains = set()

    try:
        for log in raw_data:
            for domain in log['dns_names']:
                if domain.startswith("*"):
                    continue
                new_domains.add(domain)

        return list(new_domains)

    except:
        return None