from sqlalchemy import Column, Integer, String, Date, Text
from app.core.base import Base

class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    vendor_project = Column(String, index=True)
    product = Column(String, index=True)
    vulnerability_name = Column(String)
    date_added = Column(Date, nullable=True)
    short_description = Column(Text)
    required_action = Column(Text)
    due_date = Column(Date, nullable=True)
    cwes = Column(String, nullable=True)
