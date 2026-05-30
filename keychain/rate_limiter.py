from typing import Dict, List


class RateLimiter:
    _active_keys: Dict[str, float] = {}
    _rate_state: Dict[str, List[float]] = {}

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds

    def touch(self, key_id: str, now: float) -> None:
        self._active_keys[key_id] = now

    def get_active_keys(self) -> Dict[str, float]:
        return dict(self._active_keys)

    def record_request(self, key_id: str, now: float) -> None:
        bucket = self._rate_state.setdefault(key_id, [])
        bucket.append(now)

    def get_rate_state(self) -> Dict[str, List[float]]:
        return {k: list(v) for k, v in self._rate_state.items()}

    def count_recent(self, key_id: str, now: float) -> int:
        bucket = self._rate_state.get(key_id, [])
        cutoff = now - self.window_seconds
        return sum(1 for t in bucket if t >= cutoff)
