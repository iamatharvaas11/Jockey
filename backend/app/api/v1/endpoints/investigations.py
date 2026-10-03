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
from app.models.evidence import Evidence
from app.models.relationship import Relationship
from app.models.report import Report
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
    await db.execute(delete(Evidence).filter(Evidence.investigation_id == id))
    await db.execute(delete(Relationship).filter(Relationship.investigation_id == id))
    await db.execute(delete(Report).filter(Report.investigation_id == id))
    
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
    token: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    from app.models.report import Report
    from engine.report_generator import ReportGenerator
    from fastapi.responses import HTMLResponse, JSONResponse
    from app.core.security import decode_access_token

    # Authenticate via Header, query parameter, or cookie
    user = None
    auth_header = request.headers.get("Authorization") if request else None
    raw_token = None
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ", 1)[1]
    elif token:
        raw_token = token
    elif request and "jocky_token" in request.cookies:
        raw_token = request.cookies.get("jocky_token")

    if raw_token:
        payload = decode_access_token(raw_token)
        if payload and "sub" in payload:
            res = await db.execute(select(User).filter(User.email == payload["sub"]))
            user = res.scalars().first()

    if not user:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

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
    examiner_name = user.full_name or user.email or "JOCKY Forensic Framework"
    gen = ReportGenerator(case_id=inv.case_number, examiner=examiner_name)

    if rep and rep.report_json and (rep.report_json.get("evidence_items") or rep.report_json.get("evidence_inventory")):
        rep_data = rep.report_json
    else:
        from app.services.report_assembly import assemble_investigation_report_data
        rep_data = await assemble_investigation_report_data(db, id, examiner=examiner_name)
        if not rep_data:
            rep_data = rep.report_json if rep and rep.report_json else gen.generate()

    if format.lower() == "json":
        return JSONResponse(content=rep_data)
    html_content = gen.render_html(rep_data)
    return HTMLResponse(content=html_content)


@router.get("/{id}/process-graph")
async def get_case_process_graph(
    id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve dynamic case-specific parent-child process tree and socket correlation graph
    for the specified investigation.
    """
    from app.services.process_correlation_service import get_investigation_process_graph
    return await get_investigation_process_graph(db, id)


@router.post("/{id}/correlate-live")
async def correlate_live_endpoint(
    id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Acquire live host process & socket telemetry, attach to the specified investigation,
    and return the updated case process graph.
    """
    from app.services.process_correlation_service import correlate_live_for_investigation
    return await correlate_live_for_investigation(db, id)


@router.get("/{id}/summary-report")
async def get_investigation_summary_report(
    id: str,
    token: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    """
    Retrieve executive DFIR forensic summary report data for the given investigation.
    """
    from app.services.investigation_summary_service import get_investigation_summary_data
    from app.core.security import decode_access_token

    user = None
    auth_header = request.headers.get("Authorization") if request else None
    raw_token = None
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ", 1)[1]
    elif token:
        raw_token = token
    elif request and "jocky_token" in request.cookies:
        raw_token = request.cookies.get("jocky_token")

    if raw_token:
        payload = decode_access_token(raw_token)
        if payload and "sub" in payload:
            res = await db.execute(select(User).filter(User.email == payload["sub"]))
            user = res.scalars().first()

    examiner_name = user.full_name if user else "JOCKY Forensic Analyst"
    data = await get_investigation_summary_data(db, id, examiner=examiner_name)
    if not data:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return data


