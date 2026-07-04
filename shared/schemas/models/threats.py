from shared.constants.enums import IOCReferenceType, Severity, AlertStatus

class IOC(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    type: IOCReferenceType
    value: str
    description: Optional[str] = None
    added_at: datetime = Field(default_factory=lambda: datetime.now())
    source: str = "Internal"

class TimelineEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    event_type: str
    summary: str
    severity: Severity
    related_id: Optional[UUID] = None # Link to Alert or Log