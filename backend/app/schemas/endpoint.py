from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class EndpointBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    agent_status: Optional[str] = "OFFLINE"
    system_info: Optional[Dict[str, Any]] = {}

class EndpointCreate(EndpointBase):
    pass

class EndpointResponse(EndpointBase):
    id: str
    investigation_id: str
    last_seen: datetime
    
    class Config:
        from_attributes = True
