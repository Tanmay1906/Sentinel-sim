"""
Service layer for managing and retrieving generated LogEvent telemetry records.
"""
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from loguru import logger
from app.services.elasticsearch_service import ElasticsearchService

class EventService:
    """
    Service responsible for saving, loading, deleting, and searching simulation log events.
    Uses Elasticsearch as the primary store and local JSON files as fallback.
    """
    def __init__(self, es_service: ElasticsearchService):
        self.es_service = es_service
        # Local file storage directory under backend/data/events
        self.data_dir = Path(__file__).resolve().parents[2] / "data" / "events"

    def save_events(self, simulation_id: uuid.UUID, events: List[Any]) -> None:
        """Persists every generated LogEvent for a simulation to local JSON (fallback) and Elasticsearch (primary)."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        file_path = self.data_dir / f"{simulation_id}.json"
        
        # Serialize events using Pydantic model serialization if available
        serialized_events = []
        for event in events:
            if hasattr(event, "model_dump_json"):
                serialized_events.append(json.loads(event.model_dump_json()))
            elif hasattr(event, "dict"):
                serialized_events.append(json.loads(json.dumps(event.dict(), default=str)))
            else:
                serialized_events.append(json.loads(json.dumps(event, default=str)))
                
        # 1. Always write to local JSON storage first (as a reliable fallback)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(serialized_events, f, indent=4)
            logger.bind(simulation_id=str(simulation_id)).info(f"Local JSON fallback: Stored {len(serialized_events)} events to file {file_path.name}")
        except Exception as exc:
            logger.error(f"Failed to write local JSON fallback file: {exc}")
            
        # 2. Try to index in Elasticsearch if active
        if self.es_service.is_active:
            try:
                self.es_service.bulk_index_events(simulation_id, serialized_events)
            except Exception as exc:
                logger.error(f"Failed to index events in Elasticsearch: {exc}")

    def load_events(self, simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Loads events for a specific simulation_id (using Elasticsearch if active, else local JSON)."""
        if self.es_service.is_active:
            try:
                return self.es_service.search_events(simulation_id=simulation_id, limit=1000)
            except Exception as exc:
                logger.warning(f"Elasticsearch load_events failed: {exc}. Falling back to local JSON.")
        
        # Fallback reading
        file_path = self.data_dir / f"{simulation_id}.json"
        if not file_path.exists():
            raise FileNotFoundError(f"No events found for simulation: {simulation_id}")
            
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def delete_events(self, simulation_id: uuid.UUID) -> bool:
        """Deletes stored events for a specific simulation_id from both Elasticsearch and local fallback files."""
        deleted = False
        
        # 1. Delete from Elasticsearch if active
        if self.es_service.is_active:
            try:
                res = self.es_service.delete_simulation(simulation_id)
                if res.get("deleted"):
                    deleted = True
            except Exception as exc:
                logger.error(f"Failed to delete simulation events from Elasticsearch: {exc}")
                
        # 2. Clean up local JSON fallback file if it exists
        file_path = self.data_dir / f"{simulation_id}.json"
        if file_path.exists():
            try:
                file_path.unlink()
                deleted = True
            except Exception as exc:
                logger.error(f"Failed to delete local JSON fallback file: {exc}")
                
        if deleted:
            logger.bind(simulation_id=str(simulation_id)).info("Delete Requests: Simulation events deleted from storage")
        return deleted

    def list_simulations(self) -> List[uuid.UUID]:
        """Lists all simulation IDs that have stored events (using local directory as fallback index)."""
        if not self.data_dir.exists():
            return []
        simulations = []
        for file in self.data_dir.glob("*.json"):
            try:
                simulations.append(uuid.UUID(file.stem))
            except ValueError:
                pass
        return simulations

    def get_event(self, simulation_id: uuid.UUID, event_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Retrieves a single specific event within a simulation run."""
        try:
            events = self.load_events(simulation_id)
            for event in events:
                if event.get("id") == str(event_id):
                    return event
        except Exception:
            pass
        return None

    def search_events(
        self,
        simulation_id: Optional[uuid.UUID] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        event_id: Optional[int] = None,
        platform: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Searches events across stored simulations using Elasticsearch (or local JSON files as fallback)."""
        if self.es_service.is_active:
            try:
                return self.es_service.search_events(
                    simulation_id=simulation_id,
                    host=host,
                    user=user,
                    event_id=event_id,
                    platform=platform,
                    severity=severity,
                    limit=limit,
                    offset=offset
                )
            except Exception as exc:
                logger.warning(f"Elasticsearch search_events failed: {exc}. Trying JSON fallback search.")

        # Local JSON Fallback Search
        logger.bind(
            simulation_id=str(simulation_id) if simulation_id else None,
            host=host,
            user=user,
            event_id=event_id,
            platform=platform,
            severity=severity,
            limit=limit
        ).info("Search Requests: Querying local event JSON files fallback")

        # Resolve simulations to inspect
        sim_ids = [simulation_id] if simulation_id else self.list_simulations()
        
        matches = []
        for sim_id in sim_ids:
            try:
                # Bypass es_service lookup logic and read file directly during fallback search
                file_path = self.data_dir / f"{sim_id}.json"
                if not file_path.exists():
                    continue
                with open(file_path, "r", encoding="utf-8") as f:
                    events = json.load(f)
                    
                for event in events:
                    # Apply filters
                    if host:
                        event_host = event.get("host", {})
                        if event_host:
                            hostname = event_host.get("hostname", "")
                            ips = event_host.get("ip", [])
                            if host.lower() not in hostname.lower() and not any(host in ip for ip in ips):
                                continue
                        else:
                            continue
                            
                    if user:
                        event_user = event.get("user", {})
                        if event_user:
                            username = event_user.get("name", "")
                            if user.lower() not in username.lower():
                                continue
                        else:
                            continue
                            
                    if event_id is not None:
                        custom = event.get("custom_fields", {})
                        winlog_id = custom.get("winlog_event_id")
                        if winlog_id is None:
                            continue
                        if int(winlog_id) != event_id:
                            continue
                            
                    if platform:
                        event_host = event.get("host", {})
                        if event_host:
                            os_family = event_host.get("os_family", "")
                            if platform.lower() not in os_family.lower():
                                continue
                        else:
                            continue
                            
                    if severity:
                        event_host = event.get("host", {})
                        if event_host:
                            criticality = event_host.get("criticality", "")
                            if severity.lower() not in criticality.lower():
                                continue
                        else:
                            continue
                            
                    matches.append(event)
                    if len(matches) >= limit:
                        return matches
            except Exception:
                continue
                
        return matches
