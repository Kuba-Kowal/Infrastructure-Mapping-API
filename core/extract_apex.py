import tldextract

def extract_apex(domain) -> str:
    result = tldextract.extract(domain)

    if result.suffix == "":
        return None

    return f"{result.domain}.{result.suffix}"