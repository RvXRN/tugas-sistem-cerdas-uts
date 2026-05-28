from fastapi import APIRouter

router = APIRouter(tags=["Attacks"])

@router.get("/")
async def get_attacks():
    return {"message": "List of attacks"}
