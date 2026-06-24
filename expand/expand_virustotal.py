from typing import Any

def expand_virustotal(raw_data: dict[str, Any]):
    new_domains = set()

    try:
        for domain in raw_data['subdomains']:
            if domain.startswith("*"):
                continue
            new_domains.add(domain)

        return list(new_domains)
            
    except:
        return None