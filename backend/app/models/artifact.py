import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer, JSON, ForeignKey
from app.db.base import Base

class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    endpoint_id = Column(String, ForeignKey("endpoints.id"), nullable=True)
    file_name = Column(String, nullable=False)
    artifact_type = Column(String)
    storage_path = Column(String, nullable=False)
    file_size_bytes = Column(Integer)
    sha256_hash = Column(String)
    md5_hash = Column(String)
    processing_status = Column(String, default="PENDING")
    parsed_summary = Column(JSON, default=dict)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
