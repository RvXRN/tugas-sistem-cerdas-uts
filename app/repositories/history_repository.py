from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.models.history import ConsultationHistory

class HistoryRepository:
    @staticmethod
    async def create_consultation_history(
        db: AsyncSession,
        session_id: str,
        symptoms: list,
        target_system: str,
        detected_attacks: list,
        duration_ms: float
    ) -> ConsultationHistory:
        history_entry = ConsultationHistory(
            session_id=session_id,
            symptoms=symptoms,
            target_system=target_system,
            detected_attacks=detected_attacks,
            duration_ms=duration_ms
        )
        db.add(history_entry)
        await db.commit()
        await db.refresh(history_entry)
        return history_entry

    @staticmethod
    async def get_history(
        db: AsyncSession,
        limit: int = 20,
        offset: int = 0
    ) -> list[ConsultationHistory]:
        result = await db.execute(
            select(ConsultationHistory)
            .order_by(desc(ConsultationHistory.id))
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()

    @staticmethod
    async def get_history_by_session(
        db: AsyncSession,
        session_id: str
    ) -> ConsultationHistory | None:
        result = await db.execute(
            select(ConsultationHistory).where(ConsultationHistory.session_id == session_id)
        )
        return result.scalars().first()
