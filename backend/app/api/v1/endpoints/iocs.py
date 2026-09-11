from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from app.api.deps import get_current_user
from app.models.user import User
from app.db.session import get_db
from app.models.ioc import IOC
from app.schemas.ioc import IOCResponse, IOCCreate

router = APIRouter()


@router.get("/iocs", response_model=List[IOCResponse])
async def list_all_iocs(
    investigation_id: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(IOC)
    if investigation_id:
        query = query.filter(IOC.investigation_id == investigation_id)
    if severity and severity != "ALL":
        query = query.filter(IOC.threat_level == severity.upper())
    if search:
        query = query.filter(
            (IOC.value.ilike(f"%{search}%")) | (IOC.description.ilike(f"%{search}%")) | (IOC.ioc_type.ilike(f"%{search}%"))
        )
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/iocs/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(IOC).filter(IOC.id == ioc_id))
    ioc = result.scalars().first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.get("/investigations/{investigation_id}/iocs", response_model=List[IOCResponse])
async def list_iocs(investigation_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(IOC).filter(IOC.investigation_id == investigation_id))
    return result.scalars().all()

@router.post("/investigations/{investigation_id}/iocs", response_model=IOCResponse)
async def create_ioc(investigation_id: str, ioc_in: IOCCreate, db: AsyncSession = Depends(get_db)):
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    if not inv_result.scalars().first():
        raise HTTPException(status_code=404, detail="Investigation not found")

    new_ioc = IOC(
        investigation_id=investigation_id,
        ioc_type=ioc_in.ioc_type,
        value=ioc_in.value,
        threat_level=ioc_in.threat_level,
        description=ioc_in.description,
        mitre_tactics=ioc_in.mitre_tactics
    )
    db.add(new_ioc)
    await db.commit()
    await db.refresh(new_ioc)
    return new_ioc

@router.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOC).filter(IOC.id == ioc_id))
    ioc = result.scalars().first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    await db.delete(ioc)
    await db.commit()
    return {"message": "IOC deleted"}
