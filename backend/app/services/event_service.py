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
    Service responsible for saving, loading, deleting, and searching simulation log events using local storage.
    """
    def __init__(self, es_service: ElasticsearchService):
        self.es_service = es_service
        # Local file storage directory under backend/data/events
        self.data_dir = Path(__file__).resolve().parents[2] / "data" / "events"

    def save_events(self, simulation_id: uuid.UUID, events: List[Any]) -> None:
        """Persists every generated LogEvent for a simulation to a local JSON file."""
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
                
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(serialized_events, f, indent=4)
            
        logger.bind(
            simulation_id=str(simulation_id),
            events_stored=len(events)
        ).info(f"Simulation Saved: Stored {len(events)} events to file {file_path.name}")

    def load_events(self, simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Loads events for a specific simulation_id."""
        file_path = self.data_dir / f"{simulation_id}.json"
        if not file_path.exists():
            raise FileNotFoundError(f"No events found for simulation: {simulation_id}")
            
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def delete_events(self, simulation_id: uuid.UUID) -> bool:
        """Deletes stored events for a specific simulation_id."""
        file_path = self.data_dir / f"{simulation_id}.json"
        if not file_path.exists():
            return False
        file_path.unlink()
        logger.bind(simulation_id=str(simulation_id)).info("Delete Requests: Simulation events deleted from storage")
        return True

    def list_simulations(self) -> List[uuid.UUID]:
        """Lists all simulation IDs that have stored events."""
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
        except FileNotFoundError:
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
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Searches events across stored simulations based on provided criteria."""
        logger.bind(
            simulation_id=str(simulation_id) if simulation_id else None,
            host=host,
            user=user,
            event_id=event_id,
            platform=platform,
            severity=severity,
            limit=limit
        ).info("Search Requests: Querying event logs")

        # Resolve simulations to inspect
        sim_ids = [simulation_id] if simulation_id else self.list_simulations()
        
        matches = []
        for sim_id in sim_ids:
            try:
                events = self.load_events(sim_id)
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
            except FileNotFoundError:
                continue
                
        return matches
