from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.db.session import get_db
from app.models.timeline_event import TimelineEvent
from app.models.investigation import Investigation
from app.schemas.timeline_event import TimelineEventCreate, TimelineEventResponse

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/timeline", response_model=List[TimelineEventResponse])
async def list_all_timeline_events(
    investigation_id: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(TimelineEvent)
    if investigation_id:
        query = query.filter(TimelineEvent.investigation_id == investigation_id)
    if source and source != "ALL":
        query = query.filter(TimelineEvent.event_source == source)
    if severity and severity != "ALL":
        query = query.filter(TimelineEvent.severity == severity)
    if search:
        query = query.filter(
            (TimelineEvent.title.ilike(f"%{search}%")) | (TimelineEvent.description.ilike(f"%{search}%"))
        )
    query = query.order_by(TimelineEvent.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/timeline/{event_id}", response_model=TimelineEventResponse)
async def get_timeline_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(TimelineEvent).filter(TimelineEvent.id == event_id))
    event = result.scalars().first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/investigations/{investigation_id}/timeline", response_model=List[TimelineEventResponse])
async def list_events(
    investigation_id: str, 
    source: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(TimelineEvent).filter(TimelineEvent.investigation_id == investigation_id)
    if source:
        query = query.filter(TimelineEvent.event_source == source)
    if severity:
        query = query.filter(TimelineEvent.severity == severity)
        
    query = query.order_by(TimelineEvent.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/investigations/{investigation_id}/timeline", response_model=TimelineEventResponse)
async def create_event(investigation_id: str, event_in: TimelineEventCreate, db: AsyncSession = Depends(get_db)):
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    if not inv_result.scalars().first():
        raise HTTPException(status_code=404, detail="Investigation not found")

    new_event = TimelineEvent(
        investigation_id=investigation_id,
        endpoint_id=event_in.endpoint_id,
        timestamp=event_in.timestamp,
        event_source=event_in.event_source or "MANUAL",
        event_type=event_in.event_type or "NOTE",
        title=event_in.title,
        description=event_in.description,
        severity=event_in.severity,
        raw_payload=event_in.raw_payload
    )
    db.add(new_event)
    await db.commit()
    await db.refresh(new_event)
    return new_event

@router.patch("/timeline/{event_id}/bookmark", response_model=TimelineEventResponse)
async def toggle_bookmark(event_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TimelineEvent).filter(TimelineEvent.id == event_id))
    event = result.scalars().first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
        
    event.is_bookmarked = not event.is_bookmarked
    await db.commit()
    await db.refresh(event)
    return event
