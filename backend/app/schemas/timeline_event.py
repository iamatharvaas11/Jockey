from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class TimelineEventBase(BaseModel):
    timestamp: datetime
    event_source: Optional[str] = None
    event_type: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "INFO"
    raw_payload: Optional[Dict[str, Any]] = {}

class TimelineEventCreate(TimelineEventBase):
    endpoint_id: Optional[str] = None

class TimelineEventResponse(TimelineEventBase):
    id: str
    investigation_id: str
    endpoint_id: Optional[str] = None
    is_bookmarked: bool
    
    class Config:
        from_attributes = True
