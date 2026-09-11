import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, JSON, ForeignKey
from app.db.base import Base


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=True, index=True)
    source_evidence_id = Column(String, nullable=False, index=True)
    target_evidence_id = Column(String, nullable=False, index=True)
    relationship_type = Column(String, nullable=False, index=True)
    confidence = Column(Float, default=1.0)
    reason = Column(String)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

