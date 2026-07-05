"""
Pydantic API models and validation schemas for the Sentinel-Sim API.
"""
from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field

class SimulationRequest(BaseModel):
    """Request schema to trigger a new threat simulation run."""
    scenario: str = Field(..., description="ID of the attack scenario to simulate", example="brute_force")
    seed: int = Field(default=42, description="RNG seed to ensure determinism")
    replay: bool = Field(default=False, description="Whether to execute in replay mode with frozen timeline logs")

class SimulationResponse(BaseModel):
    """Response schema summarizing the execution of a threat simulation run."""
    simulation_id: UUID = Field(..., description="Unique run identifier")
    scenario: str = Field(..., description="Scenario executed")
    status: str = Field(..., description="Status of simulation run (e.g., completed, failed)")
    events_generated: int = Field(..., description="Total events generated")
    execution_time_ms: int = Field(..., description="Execution time in milliseconds")

class ScenarioListResponse(BaseModel):
    """List of all registered threat scenarios."""
    scenarios: List[str] = Field(..., description="List of scenario IDs")

class SimulationStatusResponse(BaseModel):
    """Response schema summarizing a simulation run's metadata status."""
    simulation_id: UUID = Field(..., description="Unique run identifier")
    scenario: str = Field(..., description="Scenario executed")
    status: str = Field(..., description="Status of simulation run")
    events_generated: int = Field(..., description="Total events generated")
    execution_time_ms: int = Field(..., description="Execution time in milliseconds")
    seed: int = Field(..., description="RNG seed used")
    replay: bool = Field(..., description="Replay mode flag")
    error: Optional[str] = Field(None, description="Error message if run failed")

class EventSearchRequest(BaseModel):
    """Filters to query generated host/network telemetry event logs."""
    host_name: Optional[str] = Field(None, description="Filter by hostname")
    user_name: Optional[str] = Field(None, description="Filter by username")
    event_id: Optional[int] = Field(None, description="Filter by Windows security event ID")
    limit: int = Field(default=100, ge=1, le=1000, description="Max results to return")
    offset: int = Field(default=0, ge=0, description="Pagination offset count")

class DetectionAlert(BaseModel):
    """Schema representing a threat detection alert trigger."""
    id: UUID = Field(..., description="Unique alert identifier")
    rule_name: str = Field(..., description="Name of the triggered Sigma rule")
    severity: str = Field(..., description="Severity level of the rule (e.g. low, medium, high, critical)")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    timestamp: datetime = Field(..., description="Alert generation timestamp")
    host_name: str = Field(..., description="Target hostname where rule was triggered")
    trigger_event: Dict[str, Any] = Field(default_factory=dict, description="Metadata of event which triggered alert")

class DetectionsResponse(BaseModel):
    """Response schema wrapping list of detection alerts."""
    alerts: List[DetectionAlert] = Field(default_factory=list)
    total_alerts: int = Field(..., description="Total detection alerts matching criteria")
    limit: int = Field(..., description="Results query limit")
    offset: int = Field(..., description="Query pagination offset")

class StatisticsResponse(BaseModel):
    """Dashboard statistics and aggregate metrics summary."""
    total_events: int = Field(..., description="Overall event logs indexed")
    total_alerts: int = Field(..., description="Overall alert logs indexed")
    events_by_platform: Dict[str, int] = Field(..., description="Aggregate event counts grouped by platform family")
    events_by_category: Dict[str, int] = Field(..., description="Aggregate event counts grouped by ECS category")
    top_hosts: Dict[str, int] = Field(..., description="Top hosts by event volume")
    top_users: Dict[str, int] = Field(..., description="Top users by event volume")
    top_mitre_techniques: Dict[str, int] = Field(..., description="Top MITRE techniques by alert match counts")
    alerts_by_severity: Dict[str, int] = Field(..., description="Alert volume grouped by severity rating")
    alerts_by_rule: Dict[str, int] = Field(..., description="Alert volume grouped by detector rule name")
    daily_timeline: Dict[str, int] = Field(..., description="Chronological timeline bucketed daily")

class EventResponse(BaseModel):
    """Schema representing an ECS-compliant log event."""
    id: UUID = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="Telemetry event timestamp")
    host: Optional[Dict[str, Any]] = Field(None, description="ECS Host context")
    user: Optional[Dict[str, Any]] = Field(None, description="ECS User context")
    process: Optional[Dict[str, Any]] = Field(None, description="ECS Process context")
    network: Optional[Dict[str, Any]] = Field(None, description="ECS Network context")
    file: Optional[Dict[str, Any]] = Field(None, description="ECS File context")
    event_category: str = Field(..., description="ECS Event Category")
    event_type: str = Field(..., description="ECS Event Type")
    log_source: str = Field(..., description="Agent or engine log source")
    raw_log: str = Field(..., description="Raw string log payload")
    custom_fields: Dict[str, Any] = Field(default_factory=dict, description="Metadata and custom parameters")

class EventSearchResponse(BaseModel):
    """Response schema wrapping query results of log events."""
    events: List[EventResponse] = Field(..., description="List of events matched")
    total: int = Field(..., description="Total matching logs count")
    limit: int = Field(..., description="Limit of search results query")

class DeleteResponse(BaseModel):
    """Response schema for resources deletion operations."""
    simulation_id: UUID = Field(..., description="Simulation ID deleted")
    deleted: bool = Field(..., description="Whether execution was deleted")
    message: str = Field(..., description="Detailed status message")

class AlertResponse(BaseModel):
    """Response schema representing a generated threat alert."""
    alert_id: UUID = Field(..., description="Unique alert identifier")
    simulation_id: UUID = Field(..., description="Unique simulation run identifier")
    timestamp: datetime = Field(..., description="Alert generation timestamp")
    title: str = Field(..., description="Summary title of the alert")
    description: str = Field(..., description="Detailed description of matched rule parameters")
    severity: str = Field(..., description="Target alert severity level")
    status: str = Field(..., description="Current analyst tracking status")
    confidence: str = Field(..., description="Confidence score indicators")
    host: Optional[Dict[str, Any]] = Field(None, description="ECS Host target")
    user: Optional[Dict[str, Any]] = Field(None, description="ECS User identity")
    source_event_ids: List[UUID] = Field(default_factory=list, description="Associated source event document IDs")
    mitre_tactic: str = Field(..., description="Target matched MITRE ATT&CK tactic name")
    mitre_technique: str = Field(..., description="Target matched MITRE ATT&CK technique ID")
    rule_name: str = Field(..., description="Triggered detection rule name")
    rule_id: str = Field(..., description="Internal detector rule ID")
    raw_matches: List[Dict[str, Any]] = Field(default_factory=list, description="Raw matches snippet metadata logs")

class AlertSearchResponse(BaseModel):
    """Response schema wrapping list of threat alerts."""
    alerts: List[AlertResponse] = Field(default_factory=list, description="List of matched alerts")
    total: int = Field(..., description="Total alerts count matching query")
    limit: int = Field(..., description="Results limit")
