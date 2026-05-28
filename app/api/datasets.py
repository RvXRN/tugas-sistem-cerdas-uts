from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.api.deps import get_current_user
from app.services.dataset_service import load_all_datasets
from app.repositories.dataset_repository import DatasetRepository
from app.models.user import User

router = APIRouter()

@router.post("/load", response_model=dict, status_code=status.HTTP_200_OK)
async def load_datasets_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Endpoint untuk meload/memperbarui dataset dari file CSV ke database.
    Hanya bisa diakses oleh user yang sudah login (membawa JWT Token).
    """
    try:
        results = await load_all_datasets(db)
        return {
            "message": "Datasets loaded successfully",
            "data": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats", response_model=dict)
async def get_dataset_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Mendapatkan statistik jumlah data yang ada di database saat ini.
    """
    return await DatasetRepository.get_stats(db)
