from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class IOCBase(BaseModel):
    ioc_type: str
    value: str
    threat_level: Optional[str] = "UNKNOWN"
    description: Optional[str] = None
    mitre_tactics: Optional[List[str]] = []

class IOCCreate(IOCBase):
    pass

class IOCResponse(IOCBase):
    id: str
    investigation_id: str
    matched_events_count: int
    created_at: datetime
    
    class Config:
        from_attributes = True
