from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
import json

from app.db.database import SessionLocal
from app.services import auth_service
from app.schemas import user_schemas
from app.core import security
from app.db import models
from webauthn.helpers import options_to_json
from app.core import security, config

router = APIRouter()

# Dependency to get a DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

http_bearer_scheme = HTTPBearer()
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer_scheme), 
    db: Session = Depends(get_db)):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = security.jwt.decode(
            token, config.settings.SECRET_KEY, algorithms=[config.settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# In-memory challenge store (for simplicity in this PoC)
# In a real app, use Redis or your database for this.
challenge_store = {}

@router.post("/generate-registration-options")
def registration_options(user_create: user_schemas.UserCreate):
    options = auth_service.get_registration_options(username=user_create.username)
    
    # Store the challenge to verify it later
    challenge_store[user_create.username] = options.challenge
    
    return json.loads(options_to_json(options))

@router.post("/verify-registration/{username}")
def registration_verification(
    username: str, 
    credential: dict = Body(...),
    db: Session = Depends(get_db)
):
    challenge = challenge_store.pop(username, None)
    if not challenge:
        raise HTTPException(status_code=400, detail="Challenge not found or expired")

    new_user = auth_service.verify_registration(
        credential=credential, 
        username=username,
        challenge=challenge, 
        db=db
    )

    if not new_user:
        raise HTTPException(status_code=400, detail="Could not verify registration")
        
    return user_schemas.UserResponse.model_validate(new_user)


@router.post("/generate-authentication-options")
def authentication_options(
    user_create: user_schemas.UserCreate, 
    db: Session = Depends(get_db)
):
    db_user = db.query(models.User).filter(models.User.username == user_create.username).first()
    if not db_user or not db_user.passkey_credential_id:
        raise HTTPException(status_code=404, detail="User not found or not registered for passkey")

    options = auth_service.get_authentication_options(user=db_user)
    challenge_store[user_create.username] = options.challenge
    
    return json.loads(options_to_json(options))

@router.post("/verify-authentication/{username}", response_model=user_schemas.Token)
def authentication_verification(
    username: str, 
    credential: dict = Body(...),
    db: Session = Depends(get_db)
):
    challenge = challenge_store.pop(username, None)
    if not challenge:
        raise HTTPException(status_code=400, detail="Challenge not found or expired")

    db_user = db.query(models.User).filter(models.User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    verified_user = auth_service.verify_authentication(
        user=db_user,
        credential=credential,
        challenge=challenge
    )

    if not verified_user:
        raise HTTPException(status_code=401, detail="Could not verify authentication")

    db_user.last_login = func.now()
    db.commit()
    access_token = security.create_access_token(
        data={"sub": verified_user.username, "role": db_user.role} 
    )
    return {"access_token": access_token, "token_type": "bearer"}


# TEMPORARY endpoint for data generation
@router.post("/dev-login")
def dev_login(username: str = Body(..., embed=True), db: Session = Depends(get_db)):
    """TEMPORARY BACKDOOR FOR DATA GENERATION SCRIPT"""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        # Auto-create user if they don't exist yet for the script
        user = models.User(username=username)
        db.add(user)
        db.commit()
        db.refresh(user)
    
    access_token = security.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}