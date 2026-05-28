# Pastikan compat.py di-import PALING AWAL sebelum module lain yang mungkin bergantung pada experta/collections
import app.compat

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.database import engine, Base
from app.api import endpoints, attacks, history, auth, datasets
from app.config.settings import settings

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Inisialisasi limiter global — identifikasi user berdasarkan IP
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle handler — dijalankan sekali saat startup dan shutdown.
    Gunakan ini untuk inisialisasi resource yang berat.
    """
    logger.info("🚀 Starting up Cybersecurity Expert System...")

    # Tabel dikelola oleh Alembic. Tidak menggunakan create_all lagi.
    # async with engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Alembic migrations handles database schema")

    # Load dataset serangan dari CSV ke PostgreSQL dilakukan via API endpoint /api/v1/datasets/load
    logger.info("✅ Dataset will be loaded manually via API if needed")

    yield  # Aplikasi berjalan di sini

    # Cleanup saat shutdown
    await engine.dispose()
    logger.info("👋 Shutdown complete")


app = FastAPI(
    title="Cybersecurity Expert System API",
    description="Sistem pakar deteksi serangan siber dan rekomendasi defense berbasis Experta.",
    version="1.0.0",
    lifespan=lifespan
)

# Daftarkan limiter ke state app & exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS untuk koneksi dari Next.js / file:// lokal
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.FRONTEND_URL,
        "http://localhost:3000",
        "http://localhost:8080",
        "http://localhost:8081",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8081",
        "null",   # untuk file:// (browser kirim Origin: null)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(endpoints.router, prefix="/api/v1", tags=["diagnosis"])
app.include_router(attacks.router, prefix="/api/v1/attacks", tags=["attacks"])
app.include_router(history.router, prefix="/api/v1/history", tags=["history"])
app.include_router(datasets.router, prefix="/api/v1/datasets", tags=["datasets"])
