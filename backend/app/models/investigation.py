import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from app.db.base import Base

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String)
    status = Column(String, default="OPEN") # OPEN, ACTIVE, CONTAINED, CLOSED
    severity = Column(String, default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    lead_user_id = Column(String, ForeignKey("users.id"))
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
