from pydantic import BaseModel
from enum import Enum
from typing import Optional

class Action(str, Enum):
    READ = "read"
    DOWNLOAD = "download"
    DELETE = "delete"

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"

class AccessContext(BaseModel):
    user_id: int
    username: str
    user_role: str
    ip_address: str
    resource_sensitivity: str # e.g., "Clean", "Confidential"
    user_permission: str
    action: Action
    current_hour: int