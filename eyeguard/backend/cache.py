"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from .config import get_settings

settings = get_settings()


@dataclass
class CacheResult:
    value: Any
    ttl: int | None


class MemoryCache:
    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float | None]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            value = self._store.get(key)
            if not value:
                return None
            payload, expires_at = value
            if expires_at and expires_at < asyncio.get_event_loop().time():
                self._store.pop(key, None)
                return None
            return payload

    async def set(self, key: str, value: Any, ex: int | None = None) -> None:
        async with self._lock:
            expires_at = None
            if ex:
                expires_at = asyncio.get_event_loop().time() + ex
            self._store[key] = (value, expires_at)


class CacheProvider:
    def __init__(self) -> None:
        self._redis: Redis | None = None
        self._fallback = MemoryCache()

    async def init(self) -> None:
        if self._redis:
            return
        try:
            self._redis = Redis.from_url(str(settings.redis_url), encoding="utf-8", decode_responses=True)
            await self._redis.ping()
        except Exception:
            self._redis = None

    async def get(self, key: str) -> Any | None:
        await self.init()
        if self._redis:
            try:
                value = await self._redis.get(key)
                if value is not None:
                    return CacheResult(value=value, ttl=await self._redis.ttl(key))
            except Exception:
                pass
        payload = await self._fallback.get(key)
        if payload is None:
            return None
        return CacheResult(value=payload, ttl=None)

    async def set(self, key: str, value: Any, ex: int | None = None) -> None:
        await self.init()
        if self._redis:
            try:
                await self._redis.set(key, value, ex=ex)
                return
            except Exception:
                pass
        await self._fallback.set(key, value, ex)


cache_provider = CacheProvider()
