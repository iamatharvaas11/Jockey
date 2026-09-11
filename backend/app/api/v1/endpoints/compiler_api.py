from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from app.db.session import get_db
from app.models.investigation import Investigation
from app.models.timeline_event import TimelineEvent
from app.services.compiler_service import compile_script, execute_script
from app.core.ws_manager import ws_manager

router = APIRouter()

class ScriptRequest(BaseModel):
    source: str

@router.post("/investigations/{investigation_id}/compile")
async def compile_jocky_script(investigation_id: str, req: ScriptRequest, db: AsyncSession = Depends(get_db)):
    # Verify investigation exists
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    if not inv_result.scalars().first():
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    result = compile_script(req.source)
    return result

@router.post("/investigations/{investigation_id}/execute")
async def execute_jocky_script(investigation_id: str, req: ScriptRequest, db: AsyncSession = Depends(get_db)):
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    inv = inv_result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    exec_result = execute_script(req.source)
    
    # Save a timeline event for the execution
    new_event = TimelineEvent(
        investigation_id=investigation_id,
        timestamp=datetime.utcnow(),
        event_source="JOCKY_ENGINE",
        event_type="SCRIPT_EXECUTION",
        title="JOCKY Script Executed",
        description=f"Script executed with {exec_result['results']['evidence_collected']} evidence collected.",
        severity="INFO",
        raw_payload={"source": req.source, "result": exec_result}
    )
    db.add(new_event)
    await db.commit()
    
    # Broadcast to websocket
    await ws_manager.broadcast(investigation_id, "script_executed", exec_result)
    
    return exec_result

@router.get("/investigations/{investigation_id}/report")
async def generate_report(investigation_id: str, db: AsyncSession = Depends(get_db)):
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    inv = inv_result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    return {
        "report_title": f"Forensic Report for {inv.case_number}",
        "investigation": {
            "title": inv.title,
            "status": inv.status,
            "severity": inv.severity
        },
        "content": "Full report content generated from evidence and timeline events."
    }

@router.get("/investigations/{investigation_id}/export-report")
async def export_investigation_report(
    investigation_id: str, 
    format: str = "html", 
    db: AsyncSession = Depends(get_db)
):
    from fastapi.responses import Response
    import os, tempfile, json
    from engine.report_generator import ReportGenerator

    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    inv = inv_result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    t_result = await db.execute(select(TimelineEvent).filter(TimelineEvent.investigation_id == investigation_id))
    events = t_result.scalars().all()
    tline = [{
        "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
        "severity": ev.severity or "INFO",
        "title": ev.title or "Event",
        "description": ev.description or ""
    } for ev in events]
    
    generator = ReportGenerator(case_id=inv.case_number, examiner="Admin User")
    rep_data = generator.generate(
        timeline=tline,
        correlations={"status": inv.status, "severity": inv.severity}
    )
    
    if format.lower() == "json":
        return Response(
            content=json.dumps(rep_data, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="JOCKY_{inv.case_number}_Forensics.json"'}
        )
    else:
        temp_path = os.path.join(tempfile.gettempdir(), f"report_{inv.case_number}.html")
        generator.to_html(rep_data, temp_path)
        with open(temp_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="JOCKY_{inv.case_number}_Forensic_Report.html"'}
        )

@router.post("/compiler/compile")
async def compile_standalone_script(req: ScriptRequest):
    return compile_script(req.source)

@router.post("/compiler/execute")
async def execute_standalone_script(req: ScriptRequest):
    return execute_script(req.source)

