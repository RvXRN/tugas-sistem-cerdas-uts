from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.attack import Attack

class AttackRepository:
    @staticmethod
    async def get_all_attacks(db: AsyncSession) -> list[Attack]:
        result = await db.execute(select(Attack))
        return result.scalars().all()

    @staticmethod
    async def get_attack_by_type(db: AsyncSession, attack_type: str) -> Attack | None:
        result = await db.execute(select(Attack).where(Attack.attack_type == attack_type))
        return result.scalars().first()
