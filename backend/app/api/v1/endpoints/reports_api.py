from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_current_user, require_roles
from app.db.session import get_db
from app.models.report import Report
from app.models.investigation import Investigation
from app.models.user import User
from engine.report_generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
async def list_reports(
    investigation_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Report)
    if investigation_id:
        stmt = stmt.filter(Report.investigation_id == investigation_id)
    result = await db.execute(stmt)
    reports = result.scalars().all()
    return [
        {
            "id": r.id,
            "investigation_id": r.investigation_id,
            "case_id": r.case_id,
            "examiner": r.examiner,
            "integrity_status": r.integrity_status,
            "root_hash": r.root_hash,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


@router.get("/{id}")
async def get_report(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Report).filter(Report.id == id))
    r = result.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": r.id,
        "investigation_id": r.investigation_id,
        "case_id": r.case_id,
        "examiner": r.examiner,
        "integrity_status": r.integrity_status,
        "root_hash": r.root_hash,
        "report": r.report_json,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.post("/generate")
async def generate_report_endpoint(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ANALYST"])),
):
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    inv = inv_result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    gen = ReportGenerator(case_id=inv.case_number, examiner=current_user.full_name or current_user.email)
    report_dict = gen.generate()

    rep = Report(
        investigation_id=investigation_id,
        case_id=inv.case_number,
        examiner=gen.examiner,
        integrity_status=report_dict.get("summary", {}).get("integrity_status", "unverified"),
        root_hash=report_dict.get("integrity_manifest", {}).get("root_hash"),
        report_json=report_dict,
    )
    db.add(rep)
    await db.commit()
    await db.refresh(rep)

    return {
        "id": rep.id,
        "investigation_id": rep.investigation_id,
        "case_id": rep.case_id,
        "integrity_status": rep.integrity_status,
        "report": report_dict,
    }


@router.get("/{id}/export")
async def export_report_by_id(
    id: str,
    format: str = "html",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Report).filter(Report.id == id))
    r = result.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    gen = ReportGenerator(case_id=r.case_id)
    if format.lower() == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse(content=r.report_json)
    from fastapi.responses import HTMLResponse
    html_content = gen.render_html(r.report_json)
    return HTMLResponse(content=html_content)


@router.get("/export/case/{case_number}")
async def export_report_by_case(
    case_number: str,
    format: str = "html",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Report).filter(Report.case_id == case_number).order_by(Report.created_at.desc())
    )
    r = result.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail=f"No report found for case {case_number}")
    gen = ReportGenerator(case_id=r.case_id)
    if format.lower() == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse(content=r.report_json)
    from fastapi.responses import HTMLResponse
    html_content = gen.render_html(r.report_json)
    return HTMLResponse(content=html_content)


