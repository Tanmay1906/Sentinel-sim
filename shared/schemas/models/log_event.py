from datetime import datetime
from uuid import UUID, uuid4
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from shared.schemas.ecs.base import Host, User, Process, Network, File

class LogEvent(BaseModel):
    """The central ECS-compliant telemetry model."""
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
    
    # ECS Nested Models
    host: Optional[Host] = None
    user: Optional[User] = None
    process: Optional[Process] = None
    network: Optional[Network] = None
    file: Optional[File] = None
    
    # Metadata
    event_category: str  # e.g., "process", "network", "authentication"
    event_type: str      # e.g., "creation", "connection", "login_failed"
    log_source: str      # e.g., "windows_event_security"
    
    raw_log: str
    custom_fields: Dict[str, Any] = Field(default_factory=dict)