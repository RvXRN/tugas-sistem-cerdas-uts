from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/v1/history", tags=["History"])

@router.get("/")
async def get_history(current_user: User = Depends(get_current_user)):
    return {"message": f"Consultation history for {current_user.username}"}
