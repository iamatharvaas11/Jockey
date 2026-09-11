import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Integer, ForeignKey
from app.db.base import Base

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    ioc_type = Column(String, nullable=False) # IP, DOMAIN, SHA256, URL, REGEX
    value = Column(String, nullable=False)
    threat_level = Column(String, default="UNKNOWN")
    description = Column(String)
    mitre_tactics = Column(JSON, default=list)
    matched_events_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
