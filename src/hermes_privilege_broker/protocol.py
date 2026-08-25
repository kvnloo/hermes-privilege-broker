import hashlib
import json


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
