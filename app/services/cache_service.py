import json
import hashlib
from typing import Any, Optional
import redis.asyncio as aioredis


class CacheService:
    """
    Wrapper Redis dengan helper method yang lebih ekspresif.
    """

    def __init__(self, redis: aioredis.Redis):
        self.redis = redis
        self.DEFAULT_TTL = 3600  # 1 jam

    async def get_json(self, key: str) -> Optional[Any]:
        value = await self.redis.get(key)
        return json.loads(value) if value else None

    async def set_json(self, key: str, value: Any, ttl: int = None) -> None:
        await self.redis.setex(
            key,
            ttl or self.DEFAULT_TTL,
            json.dumps(value, default=str)
        )

    async def invalidate_pattern(self, pattern: str) -> int:
        keys = await self.redis.keys(pattern)
        if keys:
            return await self.redis.delete(*keys)
        return 0

    @staticmethod
    def make_key(*parts: str) -> str:
        combined = ":".join(str(p) for p in parts)
        return f"app:{hashlib.md5(combined.encode()).hexdigest()}"
