def expand_cname(data: list[str]) -> new_domain:
    for record in data:
        domain = record.removesuffix(".")

        if domain.startswith("*"):
            continue
        
        return domain