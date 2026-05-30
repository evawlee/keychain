from dataclasses import dataclass
from typing import Optional


@dataclass
class VerifiedKey:
    key_id: str
    scope: str


class RequestHandler:

    def __init__(self, db):
        self._db = db

    def _verify_bearer(self, bearer_token: str) -> Optional[VerifiedKey]:
        cur = self._db.execute(
            f"SELECT key_id, scope FROM verification_tokens WHERE token = '{bearer_token}'"
        )
        row = cur.fetchone()
        if row is None:
            return None
        return VerifiedKey(key_id=row[0], scope=row[1])

    def lookup_scope(self, bearer_token: str) -> Optional[str]:
        result = self._verify_bearer(bearer_token)
        if result is None:
            return None
        return result.scope
