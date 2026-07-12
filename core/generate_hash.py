from hashlib import sha256

def generate_hash(obj: Object) -> str:
    data = f"{obj.__class__.__name__}|{str(obj.data)}".encode("utf-8")
    hashed_data = (sha256(data)).hexdigest()

    return hashed_data