import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON, Enum as SAEnum, UniqueConstraint
)

from sqlalchemy.orm import relationship
import enum 

from backend.db.database import Base

# Generate UUID as primary key on the Python side before inserting into database to avoid async post-insert round-trips. Helps with performance.
def _uuid() -> str:
    return str(uuid.uuid4())

# Create a callable function to pass to sqlalchemy to capture the current UTC timestamp at insert time, not definition time.
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    # Set index=True to speed up lookups by email.
    email = Column(String, unique=True, nullable=False, index=True)

    # Password must have nullable=True to support OAuth providers and ensure that we are not forcing users to have a password (if they are using OAuth).
    # Must make sure auth logic validates this later and does not allow empty passwords.
    hashed_password = Column(String, nullable=True)
    auth_provider = Column(String, default="email")
    created_at = Column(DateTime, default=_utcnow)

    # Connect projects table to users table via the 'owner' relationship.
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")

class Project(Base):
    __tablename__ = "projects"

    # Enforce idempotency of project names per owner at the database layer.
    __table_args__ = (UniqueConstraint("name", "owner_id", name="unique_project_name_owner"),)

    id = Column(String, primary_key=True, default=_uuid)
    # Set length to 50 characters to avoid bloating the database with long project names.
    name = Column(String(50), nullable=False)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=_utcnow)

    # Connect projects table to users table via the 'owner' relationship.
    owner = relationship("User", back_populates="projects")
    # Connect projects table to connections table via the 'connections' relationship.
    connections = relationship("Connection", back_populates="project", cascade="all, delete-orphan")

class Connection(Base):
    __tablename__ = "connections"

    id = Column(String, primary_key=True, default=_uuid)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    database_name = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    username = Column(String, nullable=False)

    # Allow role and warehouse to be nullable because Snowflake can often fallback to user defaults if not specified.
    # Look into this more - it is possible that we can enforce these to be not nullable in production.
    role = Column(String, nullable=True)
    warehouse = Column(String, nullable=True)

    # This is currently a placeholder variable. It does not store a real vault path. It stores the internal connection ID instead.
    # MUST DO: Change this to store a real vault path before deploying to production.
    vault_secret_path = Column(String, nullable=False)

    # Critical vulnerability here: variable name says "password_hash", but it stores plaintext Snowflake passwords.
    # MUST DO: Implement something like the cryptography library to encrypt Snowflake passwords before deploying to production.
    password_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    # Connect projects table to connections table via the 'connections' relationship.
    project = relationship("Project", back_populates="connections")
    # Connect connections table to scans table via the 'scans' relationship.
    scans = relationship("Scan", back_populates="connection", cascade="all, delete-orphan")

# Pass in 'str' and 'enum.Enum' to allow direct string comparisons without extra serialization config.
class ScanStatus(str, enum.Enum): 
    QUEUED = "QUEUED" # The scan is queued and waiting to be run.
    RUNNING = "RUNNING" # The scan is running.
    COMPLETED = "COMPLETED" # The scan is completed.
    FAILED = "FAILED" # The scan failed.
    CANCELLED = "CANCELLED" # The scan was cancelled.

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    connection_id = Column(String, ForeignKey("connections.id"), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)

    # Real-time progress tracking columns for frontend UI display.
    current_step = Column(Integer, default=0)
    current_step_name = Column(String, default="")
    progress_pct = Column(Float, default=0.0)

    # Error handling columns. Logs should go to dedicated service later..
    log_messages = Column(JSON, default=list) # JSON 'log_messages' are overwritten entirely on update - logs should go to dedicated service later..
    error_message = Column(Text, nullable=True)
    error_trace = Column(Text, nullable=True)

    # Scope configuration column. Stores the scope configuration for the scan.
    scope_config = Column(JSON, nullable=True)

    # Denormalized counter columns to store final scan stats
    # Note: no 'updated_at' exists to track refresh timing - we will need to handle this manually.
    total_tables_scanned = Column(Integer, default=0)
    total_columns_indexed = Column(Integer, default=0)
    total_schemas_scanned = Column(Integer, default=0)
    total_queries_parsed = Column(Integer, default=0)
    total_relationships = Column(Integer, default=0)
    total_columns_contexted = Column(Integer, default=0)
    total_columns_disambiguated = Column(Integer, default=0)
    total_concepts_clustered = Column(Integer, default=0)
    total_concepts_finalized = Column(Integer, default=0)

    # Storing multi-MB graph results directly in the DB - SQLite can handle this for now, but makes database huge and makes migrations and backups slow.
    # Consider moving 'result_payload' to object storage (S3/GCS) later.
    result_summary = Column(JSON, nullable=True)
    result_concepts = Column(JSON, nullable=True)
    result_unmapped = Column(JSON, nullable=True)
    result_payload = Column(JSON, nullable=True)

    # Timestamps for tracking the scan lifecycle.
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    # Connect connections table to scans table via the 'scans' relationship.
    connection = relationship("Connection", back_populates="scans")

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    # No need to index this column and set unique=True because unique creates B-tree index
    token = Column(String, unique=True, nullable=False)

    # Never store reset tokens longer than necessary.
    expires_at = Column(DateTime, nullable=False)

    # Track if tokens have been used to prevent reuse by attackers.
    used = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=_utcnow)