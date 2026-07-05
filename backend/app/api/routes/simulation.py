"""
API routes for launching threat simulations and querying active runs.
"""
from uuid import UUID
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
# pyrefly: ignore [missing-import]
from loguru import logger

from app.api.dependencies import get_simulation_service, get_event_service
from app.services.simulation_service import SimulationService
from app.services.event_service import EventService
from app.models.api_models import (
    SimulationRequest, 
    SimulationResponse, 
    SimulationStatusResponse,
    EventResponse,
    EventSearchResponse,
    DeleteResponse
)

router = APIRouter()

@router.post("/simulate", response_model=SimulationResponse, summary="Trigger a new threat scenario simulation")
async def run_scenario(
    request: SimulationRequest,
    sim_service: SimulationService = Depends(get_simulation_service)
):
    """
    Triggers the execution of a specified MITRE ATT&CK scenario,
    generating host and network events and saving them to storage.
    """
    if not sim_service.validate_scenario(request.scenario):
        raise HTTPException(
            status_code=400, 
            detail={
                "error": "Invalid Scenario",
                "message": f"Scenario '{request.scenario}' is not recognized. Check /scenarios for list of supported scenarios."
            }
        )
    
    try:
        result = await sim_service.execute_simulation(
            scenario_id=request.scenario,
            seed=request.seed,
            replay_mode=request.replay
        )
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Simulator Failure",
                "message": f"Simulator failed during scenario execution: {str(exc)}"
            }
        )

@router.get("/scenarios", response_model=List[str], summary="List all available threat scenarios")
async def list_scenarios(
    sim_service: SimulationService = Depends(get_simulation_service)
):
    """
    Returns a list of all threat simulation scenarios supported by the engine.
    """
    return sim_service.list_available_scenarios()

@router.get("/simulation/{simulation_id}", response_model=SimulationStatusResponse, summary="Get simulation metadata details")
async def get_simulation_status(
    simulation_id: UUID,
    sim_service: SimulationService = Depends(get_simulation_service)
):
    """
    Retrieves simulation metadata details (excluding event logs) for the specified execution ID.
    """
    metadata = sim_service.get_simulation_metadata(simulation_id)
    if not metadata:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No simulation run found with ID '{simulation_id}'"
            }
        )
    return metadata

@router.get("/events", response_model=EventSearchResponse, summary="Query, search, and filter generated log events")
async def get_events(
    simulation_id: Optional[UUID] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    event_id: Optional[int] = None,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    event_service: EventService = Depends(get_event_service)
):
    """
    Query, search, and filter generated LogEvent telemetry records using various criteria.
    """
    try:
        events = event_service.search_events(
            simulation_id=simulation_id,
            host=host,
            user=user,
            event_id=event_id,
            platform=platform,
            severity=severity,
            limit=limit
        )
        return {
            "events": events,
            "total": len(events),
            "limit": limit
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail={"error": "Bad Request", "message": str(exc)})

@router.get("/events/{simulation_id}", response_model=List[EventResponse], summary="Get every event generated during a simulation run")
async def get_simulation_events(
    simulation_id: UUID,
    event_service: EventService = Depends(get_event_service)
):
    """
    Loads and returns all events associated with a specific simulation run.
    """
    try:
        return event_service.load_events(simulation_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No events found for simulation run '{simulation_id}'"
            }
        )

@router.get("/events/{simulation_id}/{event_id}", response_model=EventResponse, summary="Get details of a single event")
async def get_single_event(
    simulation_id: UUID,
    event_id: UUID,
    event_service: EventService = Depends(get_event_service)
):
    """
    Retrieves a single specific event within a simulation run by its ID.
    """
    try:
        # Verify simulation exists first
        event_service.load_events(simulation_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No simulation run found with ID '{simulation_id}'"
            }
        )

    event = event_service.get_event(simulation_id, event_id)
    if not event:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No event found with ID '{event_id}' inside simulation run '{simulation_id}'"
            }
        )
    return event

@router.delete("/events/{simulation_id}", response_model=DeleteResponse, summary="Delete stored events for a simulation run")
async def delete_simulation_events(
    simulation_id: UUID,
    event_service: EventService = Depends(get_event_service)
):
    """
    Permanently deletes all stored event files for the specified simulation run.
    """
    deleted = event_service.delete_events(simulation_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No simulation events file found for ID '{simulation_id}' to delete"
            }
        )
    return {
        "simulation_id": simulation_id,
        "deleted": True,
        "message": f"Stored events for simulation '{simulation_id}' deleted successfully."
    }
