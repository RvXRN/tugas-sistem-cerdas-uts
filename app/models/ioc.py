from sqlalchemy import Column, Integer, String, Float
from app.core.base import Base

class IoC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String, unique=True, index=True) # Domain or IP
    indicator_type = Column(String, index=True) # "domain" or "ip"
    reputation_score = Column(Float, nullable=True)
    threat_label = Column(String, nullable=True)
    threat_severity = Column(String, nullable=True)
    data_source = Column(String, nullable=True)
