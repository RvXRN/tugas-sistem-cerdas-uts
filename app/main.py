# Pastikan compat.py di-import PALING AWAL sebelum module lain yang mungkin bergantung pada experta/collections
import app.compat

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import engine, Base
from app.api import endpoints, attacks, history, auth, datasets
from app.config.settings import settings

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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

# CORS untuk koneksi dari Next.js
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(endpoints.router, prefix="/api/v1", tags=["diagnosis"])
app.include_router(attacks.router, prefix="/api/v1", tags=["attacks"])
app.include_router(history.router, prefix="/api/v1", tags=["history"])
app.include_router(datasets.router, prefix="/api/v1/datasets", tags=["datasets"])
