from sqlalchemy.orm import Session
from app.db import models

def log_activity(
        db: Session, username: str, 
        action: str, status: str, ip: str = None, 
        user_agent: str = None, resource_id: str = None, 
        details: str = None, is_simulated_attack: bool = False):
    
    if is_simulated_attack:
        details = f"{details or ''} [SIM_ATTACK]".strip()
    new_log = models.ActivityLog(
        username=username,
        action=action,
        status=status,
        ip_address=ip,
        user_agent=user_agent,
        resource_id=str(resource_id) if resource_id else None,
        details=details
    )
    db.add(new_log)
    db.commit()