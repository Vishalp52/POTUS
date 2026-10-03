import hashlib
import json

class AuditService:
    @staticmethod
    def hash_payload(payload: dict) -> str:
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()