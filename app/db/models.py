from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import Enum as SQLEnum # Import SQLEnum
import enum
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, default="employee", nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # store the raw ID and public key from the passkey credential
    passkey_credential_id = Column(LargeBinary, unique=True, nullable=True)
    passkey_public_key = Column(LargeBinary, nullable=True)

    files = relationship("File", back_populates="owner")
    shared_files = relationship("FileShare", back_populates="user")

class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    filepath = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    sensitivity_level = Column(String, default="pending")
    
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="files")
    shares = relationship("FileShare", back_populates="file", cascade="all, delete-orphan")


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    username = Column(String, index=True, nullable=False)
    user_agent = Column(String, nullable=True)
    action = Column(String, nullable=False)    # e.g., "LOGIN", "DOWNLOAD_ATTEMPT"
    resource_id = Column(String, nullable=True) # e.g., File ID "29"
    ip_address = Column(String, nullable=True)
    status = Column(String, nullable=False)    # "SUCCESS", "FAILURE", "DENIED_BY_POLICY"
    details = Column(String, nullable=True)    # e.g., "Insufficient clearance level"


class Permission(str, enum.Enum):
    VIEW = "view"
    DOWNLOAD = "download"

class FileShare(Base):
    __tablename__ = "file_shares"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permission = Column(SQLEnum(Permission), nullable=False)

    # Relationships for easy access
    file = relationship("File", back_populates="shares")
    user = relationship("User", back_populates="shared_files")
