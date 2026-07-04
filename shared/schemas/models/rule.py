from typing import List, Optional, Dict, Any
from shared.schemas.base import TraceableModel # Assumed from previous foundation
from shared.constants.enums import Severity, RuleStatus

class DetectionRule(BaseModel):
    """Sigma-inspired Rule Schema."""
    id: str = Field(..., description="Unique rule identifier (UUID or Sluggified Name)")
    title: str
    description: str
    status: RuleStatus = RuleStatus.STABLE
    author: str
    date_created: datetime
    
    # Sigma Logic
    severity: Severity
    tags: List[str] = Field(default_factory=list, description="MITRE Tactic/Technique Tags")
    false_positives: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    
    # Detection logic
    log_source_category: str
    detection: Dict[str, Any] = Field(..., description="The logic block (Selection/Condition)")
    time_window: int = 300 # Seconds
    aggregation: Optional[str] = None # e.g. "count() > 5"