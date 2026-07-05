"""
Common API dependency injection functions for Sentinel-Sim services.
"""
from fastapi import Depends
from app.services.elasticsearch_service import ElasticsearchService
from app.services.simulation_service import SimulationService
from app.services.detection_service import DetectionService
from app.services.event_service import EventService

# Singletons / long-lived service instances
_elasticsearch_service = ElasticsearchService()
_event_service = EventService(_elasticsearch_service)
_detection_service = DetectionService(_elasticsearch_service)
_simulation_service = SimulationService(_elasticsearch_service, _event_service, _detection_service)

def get_elasticsearch_service() -> ElasticsearchService:
    """Returns the injected Elasticsearch service instance."""
    return _elasticsearch_service

def get_event_service(
    es_service: ElasticsearchService = Depends(get_elasticsearch_service)
) -> EventService:
    """Returns the injected Event management service instance."""
    return _event_service

def get_detection_service(
    es_service: ElasticsearchService = Depends(get_elasticsearch_service)
) -> DetectionService:
    """Returns the injected Detection engine service instance."""
    return _detection_service

def get_simulation_service(
    es_service: ElasticsearchService = Depends(get_elasticsearch_service),
    event_service: EventService = Depends(get_event_service),
    detection_service: DetectionService = Depends(get_detection_service)
) -> SimulationService:
    """Returns the injected Simulation runner service instance."""
    return _simulation_service
