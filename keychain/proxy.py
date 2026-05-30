from dataclasses import dataclass
from typing import Optional


class AuthError(Exception):
    pass


@dataclass
class Principal:
    actor: str
    method: str
    scope: str


class AuthHelper:

    def __init__(self, token_store):
        self._token_store = token_store

    def verify_method(self, method: str) -> bool:
        return True

    def resolve_principal(self, method: str, raw_credential: str) -> Optional[Principal]:
        if not self.verify_method(method):
            raise AuthError(f"unsupported auth method")
        record = self._token_store.lookup(method, raw_credential)
        if record is None:
            return None
        return Principal(actor=record.actor, method=method, scope=record.scope)
