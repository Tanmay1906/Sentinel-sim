"""
API routes for retrieving and managing generated detection alerts.
"""
from uuid import UUID
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
# pyrefly: ignore [missing-import]
from loguru import logger

from app.api.dependencies import get_detection_service
from app.services.detection_service import DetectionService
from app.models.api_models import AlertResponse, AlertSearchResponse, DeleteResponse

router = APIRouter()

@router.get("/alerts", response_model=AlertSearchResponse, summary="Query and filter threat alerts")
async def get_alerts(
    simulation_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    limit: int = 50,
    detection_service: DetectionService = Depends(get_detection_service)
):
    """
    Queries, searches, and filters generated threat alerts using MITRE technique name or severity indicators.
    """
    try:
        alerts = detection_service.search_alerts(
            simulation_id=simulation_id,
            severity=severity,
            rule_name=rule_name,
            limit=limit
        )
        return {
            "alerts": alerts,
            "total": len(alerts),
            "limit": limit
        }
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Bad Request",
                "message": f"Invalid filters or search parameters: {str(exc)}"
            }
        )

@router.get("/alerts/{simulation_id}", response_model=List[AlertResponse], summary="Get every alert generated during a simulation run")
async def get_simulation_alerts(
    simulation_id: UUID,
    detection_service: DetectionService = Depends(get_detection_service)
):
    """
    Loads and returns all threat detection alerts generated during a specific simulation run.
    """
    alerts = detection_service.load_alerts(simulation_id)
    if not alerts:
        # Check if simulation exists or alert file is just missing / empty
        # If the folder has no matching json alert file, return 404
        import os
        file_path = detection_service.data_dir / f"{simulation_id}.json"
        if not file_path.exists():
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "Not Found",
                    "message": f"No alerts found for simulation run '{simulation_id}'"
                }
            )
    return alerts

@router.get("/alerts/{simulation_id}/{alert_id}", response_model=AlertResponse, summary="Get details of a single alert")
async def get_single_alert(
    simulation_id: UUID,
    alert_id: UUID,
    detection_service: DetectionService = Depends(get_detection_service)
):
    """
    Retrieves details of a single threat alert within a simulation run.
    """
    # Verify simulation alerts file exists
    file_path = detection_service.data_dir / f"{simulation_id}.json"
    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No alerts file found for simulation run '{simulation_id}'"
            }
        )

    alert = detection_service.get_alert(simulation_id, alert_id)
    if not alert:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No alert found with ID '{alert_id}' inside simulation run '{simulation_id}'"
            }
        )
    return alert

@router.delete("/alerts/{simulation_id}", response_model=DeleteResponse, summary="Delete stored alerts for a simulation run")
async def delete_simulation_alerts(
    simulation_id: UUID,
    detection_service: DetectionService = Depends(get_detection_service)
):
    """
    Permanently deletes all stored detection alert files for the specified simulation run.
    """
    deleted = detection_service.delete_alerts(simulation_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Not Found",
                "message": f"No simulation alerts file found for ID '{simulation_id}' to delete"
            }
        )
    return {
        "simulation_id": simulation_id,
        "deleted": True,
        "message": f"Stored alerts for simulation '{simulation_id}' deleted successfully."
    }
