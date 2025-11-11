from fastapi import UploadFile, HTTPException
from sqlalchemy.orm import Session
from app.db import models
import os
import uuid
from pathlib import Path

UPLOAD_DIRECTORY = "/app/uploads"

def save_upload_file(db: Session, file: UploadFile, user: models.User) -> models.File:
    # Ensure the upload directory exists
    Path(UPLOAD_DIRECTORY).mkdir(parents=True, exist_ok=True)
    
    # Generate a unique filename to prevent overwrites
    file_extension = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIRECTORY, unique_filename)
    
    # Save the file to disk
    try:
        with open(file_path, "wb") as buffer:
            buffer.write(file.file.read())
    except Exception:
        raise HTTPException(status_code=500, detail="Could not save file.")
    
    # Create a record in the database
    db_file = models.File(
        filename=file.filename,
        filepath=file_path,
        owner_id=user.id
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    
    return db_file