import tldextract

def extract_apex(domain):
    result = tldextract.extract(domain)

    return f"{result.domain}.{result.suffix}"

print(extract_apex("www.example.com"))
