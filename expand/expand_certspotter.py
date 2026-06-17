from typing import Any

def expand_certspotter(raw_data: list[dict[str, Any]]):
    new_domains = []

    try:
        for log in raw_data:
            for domain in log['dns_names']:
                if domain.startswith("*"):
                    continue
                new_domains.append(domain)

        return new_domains

    except:
        return None
