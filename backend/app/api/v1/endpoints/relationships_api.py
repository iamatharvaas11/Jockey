from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.relationship import Relationship
from app.models.user import User
from app.schemas.relationship import RelationshipResponse, RelationshipCreate

router = APIRouter(prefix="/relationships", tags=["relationships"])


@router.get("", response_model=List[RelationshipResponse])
async def list_relationships(
    investigation_id: Optional[str] = None,
    relationship_type: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Relationship)
    if investigation_id:
        query = query.filter(Relationship.investigation_id == investigation_id)
    if relationship_type and relationship_type != "ALL":
        query = query.filter(Relationship.relationship_type == relationship_type)
    if search:
        query = query.filter(
            (Relationship.reason.ilike(f"%{search}%"))
            | (Relationship.source_evidence_id.ilike(f"%{search}%"))
            | (Relationship.target_evidence_id.ilike(f"%{search}%"))
        )
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{id}", response_model=RelationshipResponse)
async def get_relationship(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Relationship).filter(Relationship.id == id))
    rel = result.scalars().first()
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found")
    return rel

