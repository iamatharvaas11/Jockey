from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


class RelationshipBase(BaseModel):
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: str
    confidence: Optional[float] = 1.0
    reason: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = {}


class RelationshipCreate(RelationshipBase):
    investigation_id: Optional[str] = None


class RelationshipResponse(RelationshipBase):
    id: str
    investigation_id: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

