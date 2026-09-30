from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix='/security', tags=['security'])

class BinaryScanRequest(BaseModel):
    file_path: Optional[str] = None
    target_path: Optional[str] = None

class ProcessScanRequest(BaseModel):
    pid: int

@router.post('/scan/live')
async def run_live_scan(db: AsyncSession = Depends(get_db)):
    from app.services.security_scan_service import run_live_host_scan
    return await run_live_host_scan(db)

@router.post('/scan/binary')
async def run_binary_scan(req: BinaryScanRequest, db: AsyncSession = Depends(get_db)):
    import os
    path = req.file_path or req.target_path
    if not path or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f'File not found: {path}')
    from app.services.security_scan_service import scan_binary_file
    return await scan_binary_file(db, path)

@router.post('/scan/process')
async def run_process_scan_body(req: ProcessScanRequest, db: AsyncSession = Depends(get_db)):
    from app.services.security_scan_service import scan_single_process
    return await scan_single_process(db, req.pid)

@router.post('/scan/process/{pid}')
async def run_process_scan(pid: int, db: AsyncSession = Depends(get_db)):
    from app.services.security_scan_service import scan_single_process
    return await scan_single_process(db, pid)

@router.get('/scan/results')
async def get_results(db: AsyncSession = Depends(get_db)):
    from app.services.security_scan_service import get_scan_results
    return await get_scan_results(db)

@router.get('/scan/results/{scan_id}')
async def get_result(scan_id: str, db: AsyncSession = Depends(get_db)):
    from app.services.security_scan_service import get_scan_by_id
    result = await get_scan_by_id(db, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan not found')
    return result
