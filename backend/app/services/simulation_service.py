"""
Service layer that coordinates threat scenario execution and log generation pipelines.
"""
import uuid
import time
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from loguru import logger
from app.services.elasticsearch_service import ElasticsearchService
from app.services.event_service import EventService
from app.services.detection_service import DetectionService
from simulator.main import run_simulation, SCENARIOS

class SimulationService:
    """
    Handles orchestrating, running, and capturing logs of Sentinel-Sim scenarios.
    """
    def __init__(self, es_service: ElasticsearchService, event_service: EventService, detection_service: DetectionService):
        self.es = es_service
        self.event_service = event_service
        self.detection_service = detection_service
        # In-memory store for simulation metadata (since database is excluded for now)
        self._simulations_metadata: Dict[uuid.UUID, Dict[str, Any]] = {}

    def generate_simulation_id(self) -> uuid.UUID:
        """Generates a unique simulation identifier."""
        return uuid.uuid4()

    def list_available_scenarios(self) -> List[str]:
        """Lists IDs of all currently registered scenarios."""
        return list(SCENARIOS.keys())

    def validate_scenario(self, scenario_id: str) -> bool:
        """Verifies if a scenario exists in the simulator registry."""
        return scenario_id in SCENARIOS

    def get_simulation_metadata(self, simulation_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Retrieves metadata of a previously executed simulation run."""
        return self._simulations_metadata.get(simulation_id)

    def _get_config_path(self) -> str:
        """Dynamically locates the simulator/config directory relative to application runtime path."""
        from pathlib import Path
        if Path("simulator/config").exists():
            return "simulator/config"
        if Path("../simulator/config").exists():
            return "../simulator/config"
        
        current_file = Path(__file__).resolve()
        # Navigate up from backend/app/services/simulation_service.py to Sentinel-sim root
        workspace_root = current_file.parents[3]
        config_dir = workspace_root / "simulator" / "config"
        if config_dir.exists():
            return str(config_dir)
        return "simulator/config"

    async def execute_simulation(
        self,
        scenario_id: str,
        seed: int = 42,
        replay_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a threat simulation scenario using the underlying simulator,
        tracks metadata, and returns a structured API response.
        """
        if not self.validate_scenario(scenario_id):
            raise ValueError(f"Unknown scenario: {scenario_id}")

        simulation_id = self.generate_simulation_id()
        config_path = self._get_config_path()

        logger.bind(
            scenario=scenario_id,
            seed=seed,
            replay=replay_mode,
            simulation_id=str(simulation_id)
        ).info("Simulation execution started via API service")

        start_time = time.perf_counter()
        try:
            # Execute simulation using the simulator core function
            events = run_simulation(
                scenario_name=scenario_id,
                seed=seed,
                replay=replay_mode,
                config_path=config_path,
                simulation_id=simulation_id
            )
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            events_count = len(events)
            
            # Persist events using EventService
            self.event_service.save_events(simulation_id, events)
            
            # Load stored events for rule evaluation
            stored_events = self.event_service.load_events(simulation_id)
            
            # Execute detections on generated events
            alerts = self.detection_service.run_detection(simulation_id, stored_events)
            
            # Persist generated alerts
            self.detection_service.save_alerts(simulation_id, alerts)
            
            # Construct and store simulation metadata
            metadata = {
                "simulation_id": simulation_id,
                "scenario": scenario_id,
                "status": "completed",
                "events_generated": events_count,
                "execution_time_ms": execution_time_ms,
                "seed": seed,
                "replay": replay_mode
            }
            self._simulations_metadata[simulation_id] = metadata

            logger.bind(
                scenario=scenario_id,
                seed=seed,
                replay=replay_mode,
                simulation_id=str(simulation_id),
                events_generated=events_count,
                duration_ms=execution_time_ms
            ).info("Simulation execution successfully completed")

            return metadata

        except Exception as exc:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.bind(
                scenario=scenario_id,
                seed=seed,
                replay=replay_mode,
                simulation_id=str(simulation_id),
                duration_ms=execution_time_ms
            ).exception(f"Simulation execution failed: {exc}")
            
            metadata = {
                "simulation_id": simulation_id,
                "scenario": scenario_id,
                "status": "failed",
                "events_generated": 0,
                "execution_time_ms": execution_time_ms,
                "seed": seed,
                "replay": replay_mode,
                "error": str(exc)
            }
            self._simulations_metadata[simulation_id] = metadata
            raise exc
