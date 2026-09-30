import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Text
from app.db.base import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=True, index=True)
    host = Column(String, nullable=False, index=True)
    timestamp = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False, index=True)  # process, file, network, event, registry
    source = Column(String, default="unknown")
    collector = Column(String, default="unknown")
    status = Column(String, default="success")
    data_json = Column(JSON, default=dict)
    hash = Column(String(64), nullable=True)
    limitations_json = Column(JSON, default=list)
    errors_json = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

