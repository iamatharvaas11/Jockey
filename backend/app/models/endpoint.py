import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from app.db.base import Base

class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    hostname = Column(String, nullable=False)
    ip_address = Column(String)
    os_type = Column(String)
    agent_status = Column(String, default="OFFLINE")
    system_info = Column(JSON, default=dict)
    last_seen = Column(DateTime, default=datetime.utcnow)
