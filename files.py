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
        
        # LOG SUCCESSFUL UPLOAD
        log_service.log_activity(
            db=db,
            username=current_user.username,
            action="UPLOAD",
            status="SUCCESS",
            user_agent=user_agent,
            resource_id=db_file.id,
            details=f"Filename: {db_file.filename}"
        ) 
    return uploaded_db_files


@router.get("/", response_model=List[file_schemas.FileResponse])
async def list_files_for_user(
    limit: int = 20, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # ADMIN BYPASS: Admins see ALL files in the system
    if current_user.role == "admin":
        # Admins get the latest N files across the whole system
        return db.query(models.File).order_by(models.File.created_at.desc()).limit(limit).all()

    # Normal users: Get owned + shared, then sort and limit in Python
    # (Slightly less efficient than pure SQL but easier given our current schema structure)
    owned_files = current_user.files
    shared_records = db.query(models.FileShare).filter(models.FileShare.user_id == current_user.id).all()
    shared_files = [record.file for record in shared_records]
    
    all_files = list(set(owned_files + shared_files))
    # Sort by newest first and apply limit
    all_files.sort(key=lambda x: x.created_at, reverse=True)
    return all_files[:limit]

# @router.get("/", response_model=List[file_schemas.FileResponse])
# async def list_files_for_user(
#     db: Session = Depends(get_db),
#     current_user: models.User = Depends(get_current_user)
# ):
#     """
#     Lists all files owned by OR shared with the currently authenticated user.
#     """
#     # 1. Get files owned by the user
#     owned_files = current_user.files
    
#     # 2. Get files shared with the user
#     # We query the FileShare table to find records for this user, then join with File
#     shared_records = db.query(models.FileShare).filter(models.FileShare.user_id == current_user.id).all()
#     shared_files = [record.file for record in shared_records]
    
#     # 3. Combine them (using a set to avoid potential duplicates if logic changes later)
#     all_files = list(set(owned_files + shared_files))
    
#     return all_files


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
            raise HTTPException(status_code=404, detail="File not found") # 404 is safer than 403 to avoid enumeration
        permission = "OWNER" if is_owner else share_record.permission.value

    # Determine their permission level
    # if current_user.role == "admin":
    #     permission = "ADMIN_OVERRIDE" # Special flag for admin
    # elif is_owner:
    #     permission = "OWNER"
    # elif share_record:
    #     permission = share_record.permission.value
    # else:
    #     # Not admin, not owner, no share -> BLOCK
    #     raise HTTPException(status_code=403, detail="Not authorized")
    
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
            details=f"Role: {context.user_role}. Reasons: {reasons_str}"
        )
        
        raise HTTPException(
            status_code=403, 
            detail=f"Access Denied by Policy. Reasons: {reasons_str}"
        )
    # ---------------------------------

    # user_agent = request.headers.get("user-agent", "unknown")
    # # LOG SUCCESSFUL DOWNLOAD
    # log_service.log_activity(
    #     db=db,
    #     username=current_user.username,
    #     action="DOWNLOAD",
    #     status="SUCCESS",
    #     ip=client_ip,
    #     user_agent=user_agent,
    #     resource_id=file_id,
    #     details=f"Role: {context.user_role}"
    # )

    return FileResponse(path=db_file.filepath, filename=db_file.filename)

# @router.get("/{file_id}/download")
# async def download_file(
#     file_id: int,
#     request: Request, # <--- NEW: Capture the raw incoming request
#     db: Session = Depends(get_db),
#     current_user: models.User = Depends(get_current_user)
# ):
#     """
#     Downloads a specific file for the currently authenticated user,
#     subject to Zero-Trust policy checks.
#     """
#     db_file = db.query(models.File).filter(models.File.id == file_id).first()

#     # Check 1: Does the file exist?
#     if not db_file:
#         raise HTTPException(status_code=404, detail="File not found")

#     # Check 2: Ownership (Basic Authorization)
#     # In a real app, you might allow sharing, but for now, strictly owner-only.
#     if db_file.owner_id != current_user.id:
#         raise HTTPException(status_code=403, detail="Not authorized to access this file")

#     # --- ZERO-TRUST POLICY CHECK (NEW) ---
#     # 1. Build the context for the request
#     # Docker often masks the real IP. request.client.host gives the immediate caller's IP.
#     # For a real production app behind a proxy (like Nginx), you'd check X-Forwarded-For headers.
#     client_ip = request.client.host if request.client else "unknown"
    
#     context = AccessContext(
#         user_id=current_user.id,
#         username=current_user.username,
#         ip_address=client_ip,
#         resource_sensitivity=db_file.sensitivity_level,
#         action=Action.DOWNLOAD
#     )

#     # 2. Ask the Policy Engine for a decision
#     decision = policy_engine.evaluate_request(context)

#     # 3. Enforce the decision
#     if decision == Decision.DENY:
#         # Log this security event (we'll add proper database logging in Phase 4)
#         print(f"SECURITY ALERT: Policy DENY for user {current_user.username} accessing file {file_id} from IP {client_ip}")
#         raise HTTPException(
#             status_code=403, 
#             detail=f"Access denied by Zero-Trust policy. Reason: Cannot download {db_file.sensitivity_level} file from current network."
#         )
#     # -------------------------------------

#     return FileResponse(path=db_file.filepath, filename=db_file.filename)



# @router.get("/{file_id}/download")
# async def download_file(
#     file_id: int,
#     db: Session = Depends(get_db),
#     current_user: models.User = Depends(get_current_user)
# ):
#     """
#     Downloads a specific file for the currently authenticated user.
#     """
#     db_file = db.query(models.File).filter(models.File.id == file_id).first()

#     # Check 1: Does the file exist?
#     if not db_file:
#         raise HTTPException(status_code=404, detail="File not found")

#     # Check 2: Does the current user own this file? (CRITICAL SECURITY CHECK)
#     if db_file.owner_id != current_user.id:
#         raise HTTPException(status_code=403, detail="Not authorized to download this file")

#     return FileResponse(path=db_file.filepath, filename=db_file.filename)


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

    # Create or update share record
    share = db.query(models.FileShare).filter(models.FileShare.file_id==file_id, models.FileShare.user_id==target.id).first()
    if share: 
        share.permission = share_data.permission
    else:
        db.add(models.FileShare(file_id=file_id, user_id=target.id, permission=share_data.permission))
    # db.merge(share) # merge handles both insert and update based on primary key if we had one, but here we might need to be careful about duplicates.
    # Better way for simple Many-to-Many without unique constraint on (file_id, user_id) yet:
    # Check if exists first, then update or add.
    
    # existing_share = db.query(models.FileShare).filter(models.FileShare.file_id==file_id, models.FileShare.user_id==target_user.id).first()
    # if existing_share:
    #     existing_share.permission = share_data.permission
    # else:
    #     db.add(share)
        
    db.commit()
    
    # LOG IT!
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
        user_role=current_user.role, # Keeping this as manager for your testing right now
        user_permission=permission,
        ip_address=client_ip,
        resource_sensitivity=db_file.sensitivity_level,
        action=Action.READ,
        current_hour=datetime.now().hour
    )
    decision = policy_engine.evaluate_request(context)
    
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
            details=f"Reasons: {reasons_str}"
        )
         raise HTTPException(status_code=403, detail="Access Denied by Policy")
    # -----------------------------------

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
            details="File type not supported for watermarking"
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
        resource_id=file_id
    )

    return StreamingResponse(watermarked_io, media_type="image/jpeg")


# @router.get("/{file_id}/view")
# async def view_file(
#     file_id: int,
#     request: Request,
#     db: Session = Depends(get_db),
#     current_user: models.User = Depends(get_current_user)
# ):
#     """
#     Securely views a file with dynamic watermarking.
#     """
#     db_file = db.query(models.File).filter(models.File.id == file_id).first()
#     if not db_file:
#         raise HTTPException(status_code=404, detail="File not found")

#     # Check Ownership or Share (similar to download)
#     is_owner = (db_file.owner_id == current_user.id)
#     share_record = db.query(models.FileShare).filter(models.FileShare.file_id == file_id, models.FileShare.user_id == current_user.id).first()

#     if not is_owner and not share_record:
#         raise HTTPException(status_code=403, detail="Not authorized")

#     permission = "OWNER" if is_owner else share_record.permission.value

#     # --- OPA CHECK FOR 'VIEW' ACTION ---
#     client_ip = request.client.host if request.client else "unknown"
#     context = AccessContext(
#         user_id=current_user.id,
#         username=current_user.username,
#         user_role="manager",
#         user_permission=permission,
#         ip_address=client_ip,
#         resource_sensitivity=db_file.sensitivity_level,
#         action=Action.READ, # We use READ for viewing
#         current_hour=datetime.now().hour
#     )
#     decision = policy_engine.evaluate_request(context)
#     if not decision["allow"]:
#          raise HTTPException(status_code=403, detail="Access Denied by Policy")
#     # -----------------------------------

#     # Generate Watermark
#     watermark_text = f"{current_user.username} | {client_ip} | {db_file.sensitivity_level.upper()}"
#     watermarked_io = watermark_service.create_watermarked_file(db_file.filepath, watermark_text)

#     if not watermarked_io:
#         raise HTTPException(status_code=400, detail="File type not supported for secure viewing")

#     return StreamingResponse(watermarked_io, media_type="image/jpeg")