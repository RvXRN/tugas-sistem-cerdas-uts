from sqlalchemy import Column, Integer, String, Float, JSON
from app.core.base import Base

class ConsultationHistory(Base):
    __tablename__ = "consultation_history"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    symptoms = Column(JSON)
    target_system = Column(String, nullable=True)
    target_url = Column(String, nullable=True)
    detected_attacks = Column(JSON)
    duration_ms = Column(Float)
