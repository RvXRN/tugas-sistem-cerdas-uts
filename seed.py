import asyncio
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# Patch compatibilitas untuk Experta agar tidak gagal load
import app.compat

from app.core.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def seed_users():
    async with SessionLocal() as db:
        logger.info("Mengecek data seeder...")

        # Daftar user yang akan di-seed
        users_to_seed = [
            {
                "username": "admin",
                "email": "admin@example.com",
                "password": "adminpassword",
                "role": "admin"
            },
            {
                "username": "user",
                "email": "user@example.com",
                "password": "userpassword",
                "role": "user"
            }
        ]

        for user_data in users_to_seed:
            # Cek apakah user sudah ada
            stmt = select(User).where(User.username == user_data["username"])
            result = await db.execute(stmt)
            existing_user = result.scalars().first()

            if not existing_user:
                logger.info(f"Membuat akun {user_data['username']} (Role: {user_data['role']})...")
                new_user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    hashed_password=get_password_hash(user_data["password"]),
                    role=user_data["role"]
                )
                db.add(new_user)
            else:
                logger.info(f"Akun {user_data['username']} sudah ada di database. Lewati.")

        await db.commit()
        logger.info("✅ Seeder selesai dieksekusi!")

if __name__ == "__main__":
    asyncio.run(seed_users())
