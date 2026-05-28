from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import redis.asyncio as aioredis
from app.config.settings import settings
from app.core.base import Base


# ── PostgreSQL ────────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,  # postgresql+asyncpg://user:pass@host/dbname
    pool_size=10,
    max_overflow=20,
    echo=False  # Set True untuk debug query SQL
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_db():
    """Dependency injection untuk FastAPI route handlers."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# ── Redis ──────────────────────────────────────────────────────────────────────
redis_client = aioredis.from_url(
    settings.REDIS_URL,  # redis://localhost:6379/0
    encoding="utf-8",
    decode_responses=True,
    max_connections=20
)


async def get_redis():
    """Dependency injection Redis untuk route handlers."""
    return redis_client
