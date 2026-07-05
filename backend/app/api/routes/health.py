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
    Performs quick connectivity and latency tests to Elasticsearch database cluster
    and returning overall status of the Sentinel-Sim services.
    """
    es_health = await es_service.check_health()
    return {
        "status": "healthy",
        "api_alive": True,
        "elasticsearch": es_health
    }
