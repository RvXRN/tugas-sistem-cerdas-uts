from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.models.user import User
from typing import Optional

class UserRepository:
    @staticmethod
    async def get_by_username_or_email(db: AsyncSession, username: str, email: str) -> Optional[User]:
        result = await db.execute(select(User).where(or_(User.username == username, User.email == email)))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_username(db: AsyncSession, username: str) -> Optional[User]:
        result = await db.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> Optional[User]:
        result = await db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_reset_token(db: AsyncSession, token: str) -> Optional[User]:
        result = await db.execute(select(User).where(User.reset_token == token))
        return result.scalar_one_or_none()

    @staticmethod
    async def create(db: AsyncSession, user: User) -> User:
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user
