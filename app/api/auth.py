from datetime import timedelta
from typing import Any
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, Token, ForgotPasswordRequest, ResetPasswordRequest
from app.core.security import get_password_hash, verify_password, create_access_token
from app.api.deps import get_current_user
from app.repositories.user_repository import UserRepository
from app.config.settings import settings

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    
    existing_user = await UserRepository.get_by_username_or_email(db, user.username, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    hashed_pwd = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_pwd)
    
    await db.commit()
    new_user = await UserRepository.create(db, new_user)
    return new_user

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    remember_me: bool = False, # Parameter khusus untuk remember me 
    db: AsyncSession = Depends(get_db)
):
    
    user = await UserRepository.get_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Jika remember_me True, token aktif sesuai REMEMBER_ME_EXPIRE_DAYS (misal 30 hari), jika False pakai ACCESS_TOKEN_EXPIRE_MINUTES (misal 60 menit)
    if remember_me:
        access_token_expires = timedelta(days=settings.REMEMBER_ME_EXPIRE_DAYS)
    else:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    
    user = await UserRepository.get_by_username(db, form_data.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    reset_token = str(uuid.uuid4())
    user.reset_token = reset_token
    await db.commit()
    # Dalam implementasi nyata, kirim token ini ke email
    return {"message": "Reset token generated. Send this token via email in real app.", "reset_token": reset_token}

@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    
    user = await UserRepository.get_by_username(db, form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    
    user.hashed_password = get_password_hash(request.new_password)
    user.reset_token = None
    await db.commit()
    return {"message": "Password reset successful"}
