from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete
from typing import List, Optional
import uuid

from app.db.session import get_db
from app.models.investigation import Investigation
from app.models.endpoint import Endpoint
from app.models.artifact import Artifact
from app.models.ioc import IOC
from app.models.timeline_event import TimelineEvent
from app.schemas.investigation import InvestigationCreate, InvestigationUpdate, InvestigationResponse, InvestigationList
from app.api.deps import get_current_user, require_roles
from app.models.user import User

router = APIRouter()

def generate_case_number():
    return f"CAS-{str(uuid.uuid4())[:8].upper()}"

@router.get("", response_model=List[InvestigationList])
async def list_investigations(
    skip: int = 0, limit: int = 100, status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Investigation)
    if status:
        query = query.filter(Investigation.status == status)
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    investigations = result.scalars().all()
    
    response = []
    for inv in investigations:
        inv_dict = InvestigationList.model_validate(inv)
        inv_dict.endpoints_count = 0
        inv_dict.artifacts_count = 0
        inv_dict.iocs_count = 0
        inv_dict.events_count = 0
        response.append(inv_dict)
    
    return response

@router.post("", response_model=InvestigationResponse)
async def create_investigation(
    inv_in: InvestigationCreate, 
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    case_number = generate_case_number()
    new_inv = Investigation(
        case_number=case_number,
        title=inv_in.title,
        description=inv_in.description,
        status=inv_in.status,
        severity=inv_in.severity,
        lead_user_id=inv_in.lead_user_id or current_user.id,
        tags=inv_in.tags
    )
    db.add(new_inv)
    await db.commit()
    await db.refresh(new_inv)
    return new_inv

@router.get("/{id}", response_model=InvestigationList)
async def get_investigation(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Investigation).filter(Investigation.id == id))
    inv = result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    ep_count = await db.execute(select(func.count(Endpoint.id)).filter(Endpoint.investigation_id == id))
    art_count = await db.execute(select(func.count(Artifact.id)).filter(Artifact.investigation_id == id))
    ioc_count = await db.execute(select(func.count(IOC.id)).filter(IOC.investigation_id == id))
    evt_count = await db.execute(select(func.count(TimelineEvent.id)).filter(TimelineEvent.investigation_id == id))
    
    inv_dict = InvestigationList.model_validate(inv)
    inv_dict.endpoints_count = ep_count.scalar()
    inv_dict.artifacts_count = art_count.scalar()
    inv_dict.iocs_count = ioc_count.scalar()
    inv_dict.events_count = evt_count.scalar()
    
    return inv_dict

@router.patch("/{id}", response_model=InvestigationResponse)
async def update_investigation(
    id: str,
    inv_in: InvestigationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    result = await db.execute(select(Investigation).filter(Investigation.id == id))
    inv = result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    update_data = inv_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(inv, key, value)
        
    await db.commit()
    await db.refresh(inv)
    return inv

@router.delete("/{id}")
async def delete_investigation(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    result = await db.execute(select(Investigation).filter(Investigation.id == id))
    inv = result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    await db.execute(delete(Endpoint).filter(Endpoint.investigation_id == id))
    await db.execute(delete(Artifact).filter(Artifact.investigation_id == id))
    await db.execute(delete(IOC).filter(IOC.investigation_id == id))
    await db.execute(delete(TimelineEvent).filter(TimelineEvent.investigation_id == id))
    
    await db.delete(inv)
    await db.commit()
    return {"message": "Investigation and related data deleted successfully"}


@router.post("/ingest", response_model=InvestigationList)
async def ingest_investigation(
    data: dict,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    from app.services.investigation_ingestion import ingest_investigation_payload
    client_ip = request.client.host if request.client else None
    inv = await ingest_investigation_payload(
        db, data, user_id=current_user.id, source_ip=client_ip
    )
    inv_dict = InvestigationList.model_validate(inv)
    return inv_dict


@router.get("/{id}/export-report")
async def export_investigation_report(
    id: str,
    format: str = "html",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.models.report import Report
    from engine.report_generator import ReportGenerator
    from fastapi.responses import HTMLResponse, JSONResponse

    inv_res = await db.execute(select(Investigation).filter(Investigation.id == id))
    inv = inv_res.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    rep_res = await db.execute(
        select(Report).filter(
            (Report.investigation_id == id) | (Report.case_id == inv.case_number)
        ).order_by(Report.created_at.desc())
    )
    rep = rep_res.scalars().first()
    gen = ReportGenerator(case_id=inv.case_number)

    if rep:
        rep_data = rep.report_json
    else:
        rep_data = gen.generate()

    if format.lower() == "json":
        return JSONResponse(content=rep_data)
    html_content = gen.render_html(rep_data)
    return HTMLResponse(content=html_content)

