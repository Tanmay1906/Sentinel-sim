import random
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from shared.schemas.models.log_event import LogEvent
from simulator.config.entities import EntityManager, SimulationConfig


class TimelineEngine:
    """Tracks simulation time progression for a generator."""

    def __init__(self, start_time: datetime):
        self._start_time = start_time
        self._current_offset_seconds = 0.0

    def advance(self, seconds: float) -> datetime:
        self._current_offset_seconds += seconds
        return self.current_time

    @property
    def current_time(self) -> datetime:
        sim_time = self._start_time + timedelta(seconds=self._current_offset_seconds)
        if sim_time.tzinfo is None:
            sim_time = sim_time.replace(tzinfo=timezone.utc)
        return sim_time

    @property
    def offset_seconds(self) -> float:
        return self._current_offset_seconds


class JitterStrategy(ABC):
    """Pluggable timing jitter behavior for future attack-style variations."""

    @abstractmethod
    def sample(self, rng: random.Random, base_delay: float, variance: float = 0.2) -> float:
        raise NotImplementedError


class UniformJitterStrategy(JitterStrategy):
    """Default uniform jitter around a base delay."""

    def sample(self, rng: random.Random, base_delay: float, variance: float = 0.2) -> float:
        low = base_delay * (1 - variance)
        high = base_delay * (1 + variance)
        return rng.uniform(low, high)


class BaseGenerator(ABC):
    """
    The foundation for all telemetry generation in Sentinel-Sim.
    Enforces temporal consistency, deterministic randomness, and ECS compliance.
    """

    def __init__(
        self, 
        entity_manager: EntityManager, 
        config: SimulationConfig,
        generator_seed: Optional[int] = None
    ):
        self.entity_manager = entity_manager
        self.config = config
        
        # Initialize a private, deterministic RNG
        # Uses the config seed + an optional generator-specific seed for variety
        final_seed = config.seed + (generator_seed or 0)
        self._rng = random.Random(final_seed)
        
        # Internal timeline state, kept in a dedicated helper for future replay features
        self.timeline = TimelineEngine(config.start_time)
        self._jitter_strategy: JitterStrategy = UniformJitterStrategy()
        
        # Track offset seconds for direct scenario-controlled time advancement
        self._current_offset_seconds: float = 0.0
        
        logger.debug(f"Initialized {self.__class__.__name__} with seed {final_seed}")

    def _get_simulated_timestamp(self, jitter_range: tuple[float, float] = (0.1, 2.0)) -> datetime:
        """
        Calculates the next timestamp in the simulation timeline.
        Applies a random jitter to simulate realistic network/processing delays.
        """
        jitter = self._rng.uniform(*jitter_range)
        return self.timeline.advance(jitter)

    def _apply_jitter(self, base_delay: float, variance: float = 0.2) -> float:
        """
        Adds a percentage of variance to a base delay.
        Example: base_delay 10.0 with 0.2 variance returns 8.0 to 12.0.
        """
        return self._jitter_strategy.sample(self._rng, base_delay, variance)

    def advance_time(self, seconds: float) -> None:
        """
        Advances the generator's internal simulation clock.
        Used by attack scenarios to control event timing.
        """
        self._current_offset_seconds += seconds

    @abstractmethod
    def compose_event(self, **kwargs) -> LogEvent:
        """
        Must be implemented by sub-classes to return a fully populated 
        LogEvent object using the shared ECS-compliant schema.
        """
        pass

    @abstractmethod
    def get_supported_event_types(self) -> List[str]:
        """
        Returns a list of event types this generator can produce.
        Example: ["process_creation", "network_connection"]
        """
        pass

    def log_generation_trace(self, event_type: str, host_name: str):
        """Standardized tracing for simulation debugging."""
        logger.trace(f"[{self.config.simulation_id}] Generating {event_type} for {host_name}")

    def select_random_entity(self, entity_list: List[Any]) -> Any:
        """Helper to pick a victim or actor using the deterministic RNG."""
        if not entity_list:
            raise ValueError("Cannot select from an empty entity list.")
        return self._rng.choice(entity_list)