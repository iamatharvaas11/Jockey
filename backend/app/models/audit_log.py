import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from app.db.base import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    entity_type = Column(String)
    entity_id = Column(String)
    ip_address = Column(String)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=datetime.utcnow)
