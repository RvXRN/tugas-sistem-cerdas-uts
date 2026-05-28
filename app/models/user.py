from sqlalchemy import Column, Integer, String, Boolean
from app.core.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    reset_token = Column(String, nullable=True, index=True)
    role = Column(String, default="user", nullable=False)
    is_active = Column(Boolean, default=True)
