import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from app.db.base import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=True, index=True)
    case_id = Column(String, nullable=False, index=True)
    examiner = Column(String, default="JOCKY Forensic Framework")
    integrity_status = Column(String, default="unverified")  # verified, unverified, failed
    root_hash = Column(String(64), nullable=True)
    report_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

