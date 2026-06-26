from hashlib import sha256

def generate_hash(obj: Object) -> str:
    node_attribute_table = {
        "Certificate": "id",
        "FQDN": "domain",
        "IPAddress": "ip",
        "ASN": "as_number",
        "Prefix": "prefix",
        "Organisation": "organisation",
        "DNSRecord": "data"
    }

    object_type = obj.__class__.__name__

    data = f"{object_type}|{getattr(obj, node_attribute_table[object_type])}".encode("utf-8")
    hashed_data = (sha256(data)).hexdigest()

    return hashed_data