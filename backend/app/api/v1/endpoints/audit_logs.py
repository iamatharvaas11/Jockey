from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogResponse

router = APIRouter()

@router.get("", response_model=List[AuditLogResponse])
async def list_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    query = select(AuditLog)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
        
    query = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()
