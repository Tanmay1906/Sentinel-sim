"""
Endpoints to inspect system and infrastructure services status.
"""
from fastapi import APIRouter, Depends
from app.api.dependencies import get_elasticsearch_service
from app.services.elasticsearch_service import ElasticsearchService

router = APIRouter()

@router.get("/health", summary="Get application and database health status")
async def health_check(
    es_service: ElasticsearchService = Depends(get_elasticsearch_service)
):
    """
    Performs connectivity tests to the Elasticsearch database cluster
    and returns the overall status of the Sentinel-Sim control plane.
    """
    es_health = es_service.health()
    
    # The API is considered healthy if the database connection is green/yellow,
    # or if we are gracefully running in JSON storage fallback mode.
    status = "healthy"
    if es_health.get("status") == "red":
        status = "degraded"
    elif not es_health.get("connected") and es_health.get("storage_mode") != "json":
        status = "unhealthy"

    return {
        "status": status,
        "api_alive": True,
        "elasticsearch": es_health
    }
