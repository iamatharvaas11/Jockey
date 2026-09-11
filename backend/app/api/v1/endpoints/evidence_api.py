from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_current_user, require_roles
from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.user import User

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("")
async def list_evidence(
    investigation_id: Optional[str] = None,
    evidence_type: Optional[str] = None,
    host: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Evidence)
    if investigation_id:
        query = query.filter(Evidence.investigation_id == investigation_id)
    if evidence_type:
        query = query.filter(Evidence.type == evidence_type.lower())
    if host:
        query = query.filter(Evidence.host == host)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    items = result.scalars().all()
    return [
        {
            "id": it.id,
            "investigation_id": it.investigation_id,
            "host": it.host,
            "timestamp": it.timestamp,
            "type": it.type,
            "source": it.source,
            "collector": it.collector,
            "status": it.status,
            "hash": it.hash,
            "data": it.data_json,
            "limitations": it.limitations_json,
            "errors": it.errors_json,
            "created_at": it.created_at.isoformat() if it.created_at else None,
        }
        for it in items
    ]


@router.get("/{id}")
async def get_evidence(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Evidence).filter(Evidence.id == id))
    it = result.scalars().first()
    if not it:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return {
        "id": it.id,
        "investigation_id": it.investigation_id,
        "host": it.host,
        "timestamp": it.timestamp,
        "type": it.type,
        "source": it.source,
        "collector": it.collector,
        "status": it.status,
        "hash": it.hash,
        "data": it.data_json,
        "limitations": it.limitations_json,
        "errors": it.errors_json,
        "created_at": it.created_at.isoformat() if it.created_at else None,
    }

