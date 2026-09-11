from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class AuditLogBase(BaseModel):
    action: str
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[Dict[str, Any]] = {}

class AuditLogResponse(AuditLogBase):
    id: str
    user_id: Optional[str] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True
