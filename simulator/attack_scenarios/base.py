import time
import random
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from pydantic import BaseModel
from loguru import logger

from shared.schemas.models.log_event import LogEvent
from simulator.config.entities import (
    EntityManager, 
    SimulationConfig, 
    HostConfig, 
    UserConfig, 
    AttackerConfig
)
from simulator.generators.base import BaseGenerator

class ScenarioMetadata(BaseModel):
    """Production-grade metadata for SOC visibility and MITRE mapping."""
    name: str
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    supported_platforms: List[str]
    version: str = "1.0.0"

class ScenarioBase(ABC):
    """
    Abstract Orchestrator for attack simulations.
    Follows the Template Method pattern for strict execution lifecycles.
    """

    def __init__(
        self, 
        metadata: ScenarioMetadata,
        entity_manager: EntityManager, 
        config: SimulationConfig,
        generators: Dict[str, BaseGenerator]
    ):
        self.metadata = metadata
        self.entity_manager = entity_manager
        self.config = config
        self.generators = generators
        
        # Initialize deterministic RNG from simulation seed
        self._rng = random.Random(config.seed)
        
        self._event_buffer: List[LogEvent] = []
        
        # Scenario Context (Selected during setup)
        self.attacker: Optional[AttackerConfig] = None
        self.victim_host: Optional[HostConfig] = None
        self.victim_user: Optional[UserConfig] = None

    def setup(self) -> None:
        """Selects actors using EntityManager helpers."""
        self.attacker = self.entity_manager.select_attacker(self._rng)
        self.victim_host = self.entity_manager.select_random_host(self._rng)
        self.victim_user = self.entity_manager.select_user_by_host(
            self.victim_host, self._rng
        )

    def validate(self) -> None:
        """Ensures required actors and generators are present."""
        if not all([self.attacker, self.victim_host, self.victim_user]):
            raise RuntimeError("Failed to resolve scenario actors.")
        if not self.generators:
            raise RuntimeError("No generators provided to scenario.")

    @abstractmethod
    def execute(self) -> None:
        """Specific attack steps implemented by subclasses."""
        pass

    def cleanup(self) -> None:
        """Finalizes scenario state."""
        pass

    def add_event(self, event: LogEvent) -> None:
        """Appends an event to the final telemetry list."""
        self._event_buffer.append(event)

    def advance_time(self, seconds: float) -> None:
        """Advances the internal clock of all registered generators."""
        if seconds < 0:
            raise ValueError("Cannot advance time by a negative value.")
        for gen in self.generators.values():
            # Assumes BaseGenerator has a public advance_time method
            gen.advance_time(seconds)

    def run(self) -> List[LogEvent]:
        """Strict execution lifecycle: Setup -> Validate -> Execute -> Cleanup."""
        start_ts = time.perf_counter()
        
        logger.info(f"--- Simulation Start: {self.config.simulation_id} ---")
        logger.info(f"Scenario: {self.metadata.name} | Seed: {self.config.seed}")
        
        try:
            self.setup()
            self.validate()
            self.execute()
            self.cleanup()
            
            duration = round(time.perf_counter() - start_ts, 2)
            logger.info(
                f"--- Simulation Complete --- | "
                f"Events: {len(self._event_buffer)} | "
                f"Duration: {duration}s | "
                f"Replay: {self.config.replay_mode}"
            )
            return self._event_buffer
            
        except Exception as e:
            logger.exception(f"Scenario {self.metadata.name} failed: {e}")
            raise