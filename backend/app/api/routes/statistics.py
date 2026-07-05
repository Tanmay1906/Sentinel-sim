"""
API endpoints for computing dashboard statistics and visualization data.
"""
from fastapi import APIRouter, Depends
from app.api.dependencies import get_elasticsearch_service
from app.services.elasticsearch_service import ElasticsearchService
from app.models.api_models import StatisticsResponse

router = APIRouter()

@router.get("/statistics", response_model=StatisticsResponse, summary="Get summary statistics of logs and alerts")
async def get_statistics(
    es_service: ElasticsearchService = Depends(get_elasticsearch_service)
):
    """
    Computes dashboard telemetry summary metrics, including event/alert counts,
    distributions by techniques, target hosts, and users.
    """
    return es_service.statistics()
