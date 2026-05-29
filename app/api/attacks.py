from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel

from app.core.database import get_db
from app.repositories.attack_repository import AttackRepository

router = APIRouter(tags=["Attacks"])

class AttackResponse(BaseModel):
    id: int
    attack_type: str
    symptoms: dict | list
    severity: str
    mitre_id: Optional[str] = None
    description: str

    class Config:
        from_attributes = True

@router.get("/", response_model=List[AttackResponse])
async def get_attacks(db: AsyncSession = Depends(get_db)):
    """
    Mengambil semua data referensi serangan dari database.
    (Data ini juga diisi oleh seeder).
    """
    attacks = await AttackRepository.get_all_attacks(db)
    return attacks
