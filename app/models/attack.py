from sqlalchemy import Column, Integer, String, JSON
from app.core.base import Base

class Attack(Base):
    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True, index=True)
    attack_type = Column(String, index=True)
    symptoms = Column(JSON)
    severity = Column(String)
    mitre_id = Column(String, nullable=True)
    description = Column(String)
