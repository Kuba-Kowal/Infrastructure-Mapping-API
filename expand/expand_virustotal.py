from typing import Any

def expand_virustotal(raw_data: dict[str, Any]):
    new_domains = []

    try:
        for domain in raw_data['subdomains']:
            if domain.startswith("*"):
                continue
            new_domains.append(domain)

        return new_domains
            
    except:
        return None