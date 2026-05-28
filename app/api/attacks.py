from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/attacks", tags=["Attacks"])

@router.get("/")
async def get_attacks():
    return {"message": "List of attacks"}
