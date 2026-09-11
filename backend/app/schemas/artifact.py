from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class ArtifactBase(BaseModel):
    file_name: str
    artifact_type: Optional[str] = None
    file_size_bytes: Optional[int] = None
    sha256_hash: Optional[str] = None
    md5_hash: Optional[str] = None
    processing_status: Optional[str] = "PENDING"
    parsed_summary: Optional[Dict[str, Any]] = {}

class ArtifactResponse(ArtifactBase):
    id: str
    investigation_id: str
    endpoint_id: Optional[str] = None
    uploaded_at: datetime
    
    class Config:
        from_attributes = True

class ArtifactUploadResponse(BaseModel):
    id: str
    file_name: str
    message: str
