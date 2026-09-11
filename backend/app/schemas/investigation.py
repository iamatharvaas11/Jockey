from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class InvestigationBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: Optional[str] = "OPEN"
    severity: Optional[str] = "MEDIUM"
    tags: Optional[List[str]] = []

class InvestigationCreate(InvestigationBase):
    lead_user_id: Optional[str] = None

class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None

class InvestigationResponse(InvestigationBase):
    id: str
    case_number: str
    lead_user_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class InvestigationList(InvestigationResponse):
    endpoints_count: Optional[int] = 0
    artifacts_count: Optional[int] = 0
    iocs_count: Optional[int] = 0
    events_count: Optional[int] = 0
