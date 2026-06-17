from typing import Any

def expand_crtsh(raw_data: list[dict[str, Any]]):
    new_domains = []

    try:
        for domain in log["name_value"].split("\n"):
            if domain.startswith("*"):
                continue

            new_domains.append(domain)

            print("ADDING THESE HOES TO THE QUEUE CRTSH")
            print(new_domains)
            return new_domains
                
    except:
        return None
