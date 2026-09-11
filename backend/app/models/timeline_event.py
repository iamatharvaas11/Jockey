import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Boolean, ForeignKey
from app.db.base import Base

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    endpoint_id = Column(String, ForeignKey("endpoints.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    event_source = Column(String)
    event_type = Column(String)
    title = Column(String, nullable=False)
    description = Column(String)
    severity = Column(String, default="INFO")
    is_bookmarked = Column(Boolean, default=False)
    raw_payload = Column(JSON, default=dict)
