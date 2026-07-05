import json
import argparse
import sys
import time
from pathlib import Path
from typing import List, Dict, Type

# pyrefly: ignore [missing-import]
from loguru import logger

# Configuration and Core Logic
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.os_logs import WindowsEventGenerator, LinuxSyslogGenerator
from shared.schemas.models.log_event import LogEvent

# Scenarios
from simulator.attack_scenarios.base import ScenarioBase
from simulator.attack_scenarios.brute_force import BruteForceScenario
from simulator.attack_scenarios.credential_access import CredentialAccessScenario
from simulator.attack_scenarios.persistence import PersistenceScenario
from simulator.attack_scenarios.discovery import DiscoveryScenario
from simulator.attack_scenarios.lateral_movement import LateralMovementScenario
from simulator.attack_scenarios.collection import CollectionScenario
from simulator.attack_scenarios.exfiltration import ExfiltrationScenario
from simulator.attack_scenarios.impact import ImpactScenario

# Scenario Registry
SCENARIOS: Dict[str, Type[ScenarioBase]] = {
    "brute_force": BruteForceScenario,
    "credential_access": CredentialAccessScenario,
    "persistence": PersistenceScenario,
    "discovery": DiscoveryScenario,
    "lateral_movement": LateralMovementScenario,
    "collection": CollectionScenario,
    "exfiltration": ExfiltrationScenario,
    "impact": ImpactScenario,
}

def save_events(events: List[LogEvent], output_path: str) -> None:
    """Serializes LogEvent objects to a pretty-printed JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert Pydantic models to JSON-serializable dictionaries
    event_data = [json.loads(event.model_dump_json()) for event in events]
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(event_data, f, indent=4)
    
    logger.info(f"Successfully wrote {len(events)} events to {path}")

def run_simulation(
    scenario_name: str, 
    seed: int = 42, 
    replay: bool = False,
    config_path: str = "simulator/config"
) -> List[LogEvent]:
    """
    Core orchestration function. 
    Can be called by CLI or future API backend.
    """
    if scenario_name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_name}")

    logger.bind(
        scenario=scenario_name,
        seed=seed,
        replay=replay
    ).info("Simulation starting")

    # 1. Load Entities
    entity_manager = EntityManager(config_path=config_path)
    entity_manager.load_all()

    # 2. Setup Configuration
    sim_config = SimulationConfig(
        scenario_id=scenario_name,
        seed=seed,
        replay_mode=replay
    )

    # 3. Instantiate Generators
    generators = {
        # pyrefly: ignore [bad-instantiation]
        "windows": WindowsEventGenerator(entity_manager, sim_config),
        # pyrefly: ignore [bad-instantiation]
        "linux": LinuxSyslogGenerator(entity_manager, sim_config),
    }

    # 4. Execute Scenario
    scenario_class = SCENARIOS[scenario_name]
    scenario = scenario_class(
        entity_manager=entity_manager,
        config=sim_config,
        generators=generators
    )

    events = scenario.run()
    if not events:
        logger.warning(
            f"Scenario '{scenario_name}' produced no events."
        )
    return events

def main() -> None:
    """CLI Entry point for the Sentinel-Sim Generator."""
    parser = argparse.ArgumentParser(description="Sentinel-Sim: Threat Detection Simulator")
    parser.add_argument("--scenario", required=True, choices=SCENARIOS.keys(), help="Scenario to run")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for determinism")
    parser.add_argument("--replay", action="store_true", help="Enable replay mode (static timestamps)")
    parser.add_argument("--output", default="output/events.json", help="Path to output JSON file")

    args = parser.parse_args()

    start = time.perf_counter()
    try:
        events = run_simulation(args.scenario, args.seed, args.replay)
        save_events(events, args.output)
        elapsed = time.perf_counter() - start
        logger.success(
            f"Generated {len(events)} events in {elapsed:.2f}s"
        )
    except KeyboardInterrupt:
        logger.warning("Simulation aborted by user.")
        sys.exit(0)
    except FileNotFoundError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected Simulation Failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()