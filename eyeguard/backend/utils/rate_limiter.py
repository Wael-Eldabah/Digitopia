"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    def __init__(self, max_calls: int, per_seconds: int) -> None:
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._store: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> bool:
        async with self._lock:
            window = self._store.setdefault(key, deque())
            cutoff = time.monotonic() - self.per_seconds
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= self.max_calls:
                return False
            window.append(time.monotonic())
            return True


rate_limiter = RateLimiter(max_calls=30, per_seconds=60)
