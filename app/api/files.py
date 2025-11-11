from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from app.db import models
from app.db.database import SessionLocal
from app.api.auth import get_db, get_current_user 
from app.services import file_service
from app.schemas import file_schemas
from typing import List
import os
from starlette.responses import FileResponse
from app.tasks import scan_file_task
from fastapi import Request 
from app.core import policy_engine
from app.schemas.policy_schemas import AccessContext, Action, Decision
from datetime import datetime
from app.services import log_service
from pydantic import BaseModel
from fastapi.responses import StreamingResponse
from app.services import watermark_service
import io

class ShareRequest(BaseModel):
    username: str
    permission: models.Permission

router = APIRouter()

@router.post("/upload", response_model=List[file_schemas.FileResponse])
async def upload_file( 
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
    files: List[UploadFile] = File(...)
):
    """
    Uploads one or more files for the currently authenticated user.
    """
    uploaded_db_files = []
    user_agent = request.headers.get("user-agent", "unknown")
    for file in files:
        db_file = file_service.save_upload_file(db=db, file=file, user=current_user)
        uploaded_db_files.append(db_file)
        scan_file_task.delay(db_file.id)
        is_attack = request.headers.get("X-Sim-Mode") == "attack"
        log_service.log_activity(
            db=db,
            username=current_user.username,
            action="UPLOAD",
            status="SUCCESS",
            user_agent=user_agent,
            resource_id=db_file.id,
            details=f"Filename: {db_file.filename}",
            is_simulated_attack=is_attack
        ) 
    return uploaded_db_files


@router.get("/", response_model=List[file_schemas.FileResponse])
async def list_files_for_user(
    limit: int = 20, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role == "admin":
        return db.query(models.File).order_by(models.File.created_at.desc()).limit(limit).all()

    owned_files = current_user.files
    shared_records = db.query(models.FileShare).filter(models.FileShare.user_id == current_user.id).all()
    shared_files = [record.file for record in shared_records]
    
    all_files = list(set(owned_files + shared_files))
    all_files.sort(key=lambda x: x.created_at, reverse=True)
    return all_files[:limit]


@router.get("/{file_id}/download")
async def download_file(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Downloads a file, subject to ADVANCED Zero-Trust policy checks via OPA.
    """
    db_file = db.query(models.File).filter(models.File.id == file_id).first()

    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    if current_user.role == "admin":
        permission = "ADMIN_OVERRIDE"
    else:
    # Check if user is owner OR has a share record
        is_owner = (db_file.owner_id == current_user.id)
        share_record = db.query(models.FileShare).filter(
            models.FileShare.file_id == file_id,
            models.FileShare.user_id == current_user.id
        ).first()

        if not is_owner and not share_record:
            raise HTTPException(status_code=404, detail="File not found") 
        permission = "OWNER" if is_owner else share_record.permission
    
    client_ip = request.client.host if request.client else "unknown"
    current_hour = datetime.now().hour

    context = AccessContext(
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,        
        ip_address=client_ip,
        resource_sensitivity=db_file.sensitivity_level,
        user_permission=permission,
        action=Action.DOWNLOAD,
        current_hour=current_hour     
    )

    # Ask OPA for the decision
    decision = policy_engine.evaluate_request(context)
    is_attack = request.headers.get("X-Sim-Mode") == "attack"

    if not decision["allow"]:
        reasons_str = "; ".join(decision["reasons"])
    
        # LOG OPA DENIAL
        log_service.log_activity(
            db=db,
            username=current_user.username,
            action="DOWNLOAD_ATTEMPT",
            status="DENIED_BY_POLICY",
            ip=client_ip,
            resource_id=file_id,
            details=f"Role: {context.user_role}. Reasons: {reasons_str}",
            is_simulated_attack=is_attack
        )
        
        raise HTTPException(
            status_code=403, 
            detail=f"Access Denied by Policy. Reasons: {reasons_str}"
        )

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
        
    # Check 2: Does the current user own this file?
    if current_user.role != "admin" and db_file.owner_id != current_user.id:
        # LOG UNAUTHORIZED DELETE ATTEMPT
        log_service.log_activity(
            db=db,
            username=current_user.username,
            action="DELETE_ATTEMPT",
            status="FAILURE",
            resource_id=file_id,
            details="User is not the owner."
        )
        raise HTTPException(status_code=403, detail="Not authorized to delete this file")

    # Delete the physical file from disk
    try:
        if os.path.exists(db_file.filepath):
            os.remove(db_file.filepath)
    except OSError as e:
        # LOG DISK ERROR
        log_service.log_activity(
            db=db,
            username=current_user.username,
            action="DELETE_ERROR",
            status="PARTIAL_FAILURE",
            resource_id=file_id,
            details=f"Database record deleted, but disk file remained: {e}"
        )

    # Delete the record from the database
    db.delete(db_file)
    db.commit()

    # LOG SUCCESSFUL DELETE
    log_service.log_activity(
        db=db,
        username=current_user.username,
        action="DELETE",
        status="SUCCESS",
        resource_id=file_id,
        details=f"Filename: {db_file.filename}"
    )

    return {"detail": f"Successfully deleted file: {db_file.filename}"}


@router.post("/{file_id}/share")
def share_file(
    file_id: int,
    share_data: ShareRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_file = db.query(models.File).filter(models.File.id == file_id).first()
    if not db_file or db_file.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")

    if current_user.role != "admin" and db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to share")
    
    target = db.query(models.User).filter(models.User.username == share_data.username).first()
    if not target:
         raise HTTPException(status_code=404, detail="Target user not found")

    share = db.query(models.FileShare).filter(models.FileShare.file_id==file_id, models.FileShare.user_id==target.id).first()
    if share: 
        share.permission = share_data.permission
    else:
        db.add(models.FileShare(file_id=file_id, user_id=target.id, permission=share_data.permission))
    db.commit()
    
    log_service.log_activity(db, current_user.username, "SHARE", "SUCCESS", resource_id=file_id, details=f"Shared with {target.username} as {share_data.permission.value}")
    
    return {"status": "ok"}


@router.get("/{file_id}/view")
async def view_file(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Securely views a file with dynamic watermarking.
    """
    db_file = db.query(models.File).filter(models.File.id == file_id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    # Check Ownership or Share
    if current_user.role == "admin":
        permission = "ADMIN_OVERRIDE"
    else:
        is_owner = (db_file.owner_id == current_user.id)
        share_record = db.query(models.FileShare).filter(models.FileShare.file_id == file_id, models.FileShare.user_id == current_user.id).first()

        if not is_owner and not share_record:
        # LOG UNAUTHORIZED VIEW ATTEMPT
            log_service.log_activity(
                db=db,
                username=current_user.username,
                action="VIEW_ATTEMPT",
                status="FAILURE",
                resource_id=file_id,
                details="User has no rights to this file."
            )
            raise HTTPException(status_code=403, detail="Not authorized")

        permission = "OWNER" if is_owner else share_record.permission.value

    # --- OPA CHECK FOR 'VIEW' ACTION ---
    client_ip = request.client.host if request.client else "unknown"
    # Capture User-Agent for the log
    user_agent = request.headers.get("user-agent", "unknown")
    
    context = AccessContext(
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role, 
        user_permission=permission,
        ip_address=client_ip,
        resource_sensitivity=db_file.sensitivity_level,
        action=Action.READ,
        current_hour=datetime.now().hour
    )
    decision = policy_engine.evaluate_request(context)
    is_attack = request.headers.get("X-Sim-Mode") == "attack"
    if not decision["allow"]:
         reasons_str = "; ".join(decision["reasons"])
         
         # LOG OPA DENIAL
         log_service.log_activity(
            db=db,
            username=current_user.username,
            action="VIEW_ATTEMPT",
            status="DENIED_BY_POLICY",
            ip=client_ip,
            user_agent=user_agent,
            resource_id=file_id,
            details=f"Reasons: {reasons_str}",
            is_simulated_attack=is_attack
        )
         raise HTTPException(status_code=403, detail="Access Denied by Policy")

    # Generate Watermark
    watermark_text = f"{current_user.username} | {client_ip} | {db_file.sensitivity_level.upper()}"
    watermarked_io = watermark_service.create_watermarked_file(db_file.filepath, watermark_text)

    if not watermarked_io:
        # LOG TECHNICAL FAILURE
        log_service.log_activity(
            db=db,
            username=current_user.username,
            action="VIEW_ERROR",
            status="FAILURE",
            resource_id=file_id,
            details="File type not supported for watermarking",
            is_simulated_attack=is_attack
        )
        raise HTTPException(status_code=400, detail="File type not supported for secure viewing")

    # LOG SUCCESSFUL VIEW
    log_service.log_activity(
        db=db,
        username=current_user.username,
        action="VIEW",
        status="SUCCESS",
        ip=client_ip,
        user_agent=user_agent,
        resource_id=file_id, 
        details="Successfully viewed the file", 
        is_simulated_attack=is_attack
    )

    return StreamingResponse(watermarked_io, media_type="image/jpeg")