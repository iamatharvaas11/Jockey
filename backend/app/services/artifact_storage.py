import os
import uuid
import hashlib
import aiofiles
from fastapi import UploadFile, HTTPException

CHUNK_SIZE = 1024 * 1024

def secure_filename(filename: str) -> str:
    if not filename:
        return str(uuid.uuid4())
    
    basename = os.path.basename(filename.replace("\\", "/"))
    
    if ".." in basename or basename.startswith(".") or not basename:
        return str(uuid.uuid4())
        
    return basename

sanitize_filename = secure_filename

async def store_evidence_file(file: UploadFile, dest_dir: str) -> dict:
    os.makedirs(dest_dir, exist_ok=True)
    
    safe_filename = secure_filename(file.filename)
    file_path = os.path.join(dest_dir, safe_filename)
    
    real_dest = os.path.realpath(dest_dir)
    real_path = os.path.realpath(file_path)
    
    if not real_path.startswith(real_dest):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    file_size = 0
    
    async with aiofiles.open(real_path, 'wb') as out_file:
        while chunk := await file.read(CHUNK_SIZE):
            file_size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
            await out_file.write(chunk)
            
    return {
        "file_name": safe_filename,
        "storage_path": real_path,
        "file_size_bytes": file_size,
        "sha256_hash": sha256.hexdigest(),
        "md5_hash": md5.hexdigest()
    }
