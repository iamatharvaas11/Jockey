from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from app.models.audit_log import AuditLog
from datetime import datetime

async def log_action(
    db: AsyncSession, 
    user_id: Optional[str], 
    action: str, 
    entity_type: Optional[str] = None, 
    entity_id: Optional[str] = None, 
    ip_address: Optional[str] = None, 
    details: Optional[dict] = None
):
    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        ip_address=ip_address,
        details=details or {},
        timestamp=datetime.utcnow()
    )
    db.add(audit_entry)
    await db.commit()
    await db.refresh(audit_entry)
    return audit_entry
