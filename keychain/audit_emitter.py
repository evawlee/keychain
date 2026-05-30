from dataclasses import dataclass


class LogEncodingError(Exception):
    pass


@dataclass
class AuthEvent:
    actor: str
    method: str
    outcome: str
    request_path: str
    key_prefix: str
    detail: str


class AuthEventLog:

    def __init__(self):
        self._records = []

    def record_auth_event(self, event):
        fields = [
            event.actor,
            event.method,
            event.outcome,
            event.request_path,
            event.key_prefix,
            event.detail,
        ]
        line = "\t".join(fields) + "\n"
        self._records.append(line)

    def entries(self):
        return list(self._records)

    def clear(self):
        self._records = []

    def __len__(self):
        return len(self._records)
