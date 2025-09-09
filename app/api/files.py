from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from app.db import models
from app.db.database import SessionLocal
from app.api.auth import get_db, get_current_user # We can reuse the get_db dependency
from app.services import file_service
from app.schemas import file_schemas
from typing import List
import os
from starlette.responses import FileResponse
from app.tasks import scan_file_task

router = APIRouter()

@router.post("/upload", response_model=List[file_schemas.FileResponse])
async def upload_file( 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
    files: List[UploadFile] = File(...)
):
    """
    Uploads one or more files for the currently authenticated user.
    """
    uploaded_db_files = []
    for file in files:
    # We will add logic here to get the current user and save the file.
        db_file = file_service.save_upload_file(db=db, file=file, user=current_user)
        uploaded_db_files.append(db_file)
        scan_file_task.delay(db_file.id)
    return uploaded_db_files

@router.get("/", response_model=List[file_schemas.FileResponse])
async def list_files_for_user(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lists all files for the currently authenticated user.
    """
    return current_user.files


@router.get("/{file_id}/download")
async def download_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Downloads a specific file for the currently authenticated user.
    """
    db_file = db.query(models.File).filter(models.File.id == file_id).first()

    # Check 1: Does the file exist?
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    # Check 2: Does the current user own this file? (CRITICAL SECURITY CHECK)
    if db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to download this file")

    return FileResponse(path=db_file.filepath, filename=db_file.filename)


@router.delete("/{file_id}")
async def delete_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Deletes a specific file for the currently authenticated user.
    """
    db_file = db.query(models.File).filter(models.File.id == file_id).first()

    # Check 1: Does the file exist?
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
        
    # Check 2: Does the current user own this file? (CRITICAL SECURITY CHECK)
    if db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this file")

    # Delete the physical file from disk
    try:
        if os.path.exists(db_file.filepath):
            os.remove(db_file.filepath)
    except OSError as e:
        # Log this error but continue, as we still want to remove the DB record
        print(f"Error removing file from disk: {e}")

    # Delete the record from the database
    db.delete(db_file)
    db.commit()

    return {"detail": f"Successfully deleted file: {db_file.filename}"}