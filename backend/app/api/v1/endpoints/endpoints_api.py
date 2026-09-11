from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.models.investigation import Investigation
from app.schemas.endpoint import EndpointCreate, EndpointResponse

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/endpoints", response_model=List[EndpointResponse])
async def list_all_endpoints(
    investigation_id: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Endpoint)
    if investigation_id:
        query = query.filter(Endpoint.investigation_id == investigation_id)
    if status and status != "ALL":
        query = query.filter(Endpoint.agent_status == status.upper())
    if search:
        query = query.filter(
            (Endpoint.hostname.ilike(f"%{search}%")) | (Endpoint.ip_address.ilike(f"%{search}%"))
        )
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/endpoints/{endpoint_id}", response_model=EndpointResponse)
async def get_endpoint(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Endpoint).filter(Endpoint.id == endpoint_id))
    ep = result.scalars().first()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return ep


@router.get("/investigations/{investigation_id}/endpoints", response_model=List[EndpointResponse])
async def list_endpoints(investigation_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Endpoint).filter(Endpoint.investigation_id == investigation_id))
    return result.scalars().all()

@router.post("/investigations/{investigation_id}/endpoints", response_model=EndpointResponse)
async def create_endpoint(investigation_id: str, ep_in: EndpointCreate, db: AsyncSession = Depends(get_db)):
    # Verify investigation exists
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    if not inv_result.scalars().first():
        raise HTTPException(status_code=404, detail="Investigation not found")

    new_ep = Endpoint(
        investigation_id=investigation_id,
        hostname=ep_in.hostname,
        ip_address=ep_in.ip_address,
        os_type=ep_in.os_type,
        agent_status=ep_in.agent_status,
        system_info=ep_in.system_info
    )
    db.add(new_ep)
    await db.commit()
    await db.refresh(new_ep)
    return new_ep

@router.patch("/endpoints/{endpoint_id}", response_model=EndpointResponse)
async def update_endpoint_status(endpoint_id: str, status: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Endpoint).filter(Endpoint.id == endpoint_id))
    ep = result.scalars().first()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
        
    ep.agent_status = status
    await db.commit()
    await db.refresh(ep)
    return ep
