from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import os

from app.db.session import get_db
from app.models.artifact import Artifact
from app.models.investigation import Investigation
from app.schemas.artifact import ArtifactResponse, ArtifactUploadResponse
from app.services.artifact_storage import store_evidence_file
from app.core.config import settings

from app.api.deps import get_current_user, require_roles
from app.models.user import User

router = APIRouter()

@router.post("/investigations/{investigation_id}/artifacts", response_model=ArtifactUploadResponse)
async def upload_artifact(
    investigation_id: str, 
    file: UploadFile = File(...), 
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    if not inv_result.scalars().first():
        raise HTTPException(status_code=404, detail="Investigation not found")

    dest_dir = os.path.join(settings.STORAGE_DIR, investigation_id)
    file_info = await store_evidence_file(file, dest_dir)
    
    new_artifact = Artifact(
        investigation_id=investigation_id,
        file_name=file_info["file_name"],
        storage_path=file_info["storage_path"],
        file_size_bytes=file_info["file_size_bytes"],
        sha256_hash=file_info["sha256_hash"],
        md5_hash=file_info["md5_hash"],
        artifact_type=file.content_type
    )
    db.add(new_artifact)
    await db.commit()
    await db.refresh(new_artifact)
    
    return ArtifactUploadResponse(
        id=new_artifact.id,
        file_name=new_artifact.file_name,
        message="Upload successful"
    )

@router.get("/investigations/{investigation_id}/artifacts", response_model=List[ArtifactResponse])
async def list_artifacts(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Artifact).filter(Artifact.investigation_id == investigation_id))
    return result.scalars().all()

@router.get("/artifacts/{artifact_id}/download")
async def download_artifact(
    artifact_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Artifact).filter(Artifact.id == artifact_id))
    artifact = result.scalars().first()
    if not artifact or not os.path.exists(artifact.storage_path):
        raise HTTPException(status_code=404, detail="Artifact not found")

    def file_iterator():
        with open(artifact.storage_path, "rb") as file:
            while chunk := file.read(1024 * 1024):
                yield chunk

    return StreamingResponse(
        file_iterator(), 
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={artifact.file_name}"}
    )

@router.delete("/artifacts/{artifact_id}")
async def delete_artifact(artifact_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Artifact).filter(Artifact.id == artifact_id))
    artifact = result.scalars().first()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
        
    if os.path.exists(artifact.storage_path):
        os.remove(artifact.storage_path)
        
    await db.delete(artifact)
    await db.commit()
    return {"message": "Artifact deleted"}
