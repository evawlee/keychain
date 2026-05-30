from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TokenRecord:
    actor: str
    scope: str


class TokenStore:

    def __init__(self):
        self._records: Dict[str, TokenRecord] = {}

    def register(self, method: str, raw_credential: str, actor: str, scope: str) -> None:
        key = method + ":" + raw_credential
        self._records[key] = TokenRecord(actor=actor, scope=scope)

    def lookup(self, method: str, raw_credential: str) -> Optional[TokenRecord]:
        key = method + ":" + raw_credential
        return self._records.get(key)

    def revoke(self, method: str, raw_credential: str) -> bool:
        key = method + ":" + raw_credential
        if key in self._records:
            del self._records[key]
            return True
        return False
