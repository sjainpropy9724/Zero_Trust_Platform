from pydantic import BaseModel
from datetime import datetime

class FileResponse(BaseModel):
    id: int
    filename: str
    created_at: datetime
    owner_id: int
    sensitivity_level: str

    class Config:
        from_attributes = True