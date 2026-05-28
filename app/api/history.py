from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.repositories.history_repository import HistoryRepository

router = APIRouter(tags=["History"])


@router.get("/")
async def get_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ambil riwayat konsultasi terakhir.
    Diurutkan dari yang paling baru.
    """
    histories = await HistoryRepository.get_history(db, limit=limit, offset=offset)
    return {
        "total": len(histories),
        "limit": limit,
        "offset": offset,
        "data": [
            {
                "id": h.id,
                "session_id": h.session_id,
                "symptoms": h.symptoms,
                "target_system": h.target_system,
                "detected_attacks": h.detected_attacks,
                "duration_ms": h.duration_ms,
            }
            for h in histories
        ]
    }


@router.get("/{session_id}")
async def get_history_by_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Ambil detail satu riwayat konsultasi berdasarkan session_id."""
    history = await HistoryRepository.get_history_by_session(db, session_id)
    if not history:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' tidak ditemukan."
        )
    return {
        "id": history.id,
        "session_id": history.session_id,
        "symptoms": history.symptoms,
        "target_system": history.target_system,
        "detected_attacks": history.detected_attacks,
        "duration_ms": history.duration_ms,
    }
