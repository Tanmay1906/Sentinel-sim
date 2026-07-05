import pytest
import uuid
from pathlib import Path
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.os_logs import WindowsEventGenerator, LinuxSyslogGenerator
from simulator.main import SCENARIOS

@pytest.fixture
def entity_manager():
    config_dir = Path(__file__).resolve().parents[1] / "simulator" / "config"
    manager = EntityManager(config_path=str(config_dir))
    manager.load_all()
    return manager

@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
def test_all_scenarios_execution(scenario_name, entity_manager):
    sim_config = SimulationConfig(
        simulation_id=uuid.uuid4(),
        scenario_id=scenario_name,
        seed=42,
        replay_mode=False
    )
    
    generators = {
        "windows": WindowsEventGenerator(entity_manager, sim_config),
        "linux": LinuxSyslogGenerator(entity_manager, sim_config),
    }
    
    scenario_class = SCENARIOS[scenario_name]
    scenario = scenario_class(
        entity_manager=entity_manager,
        config=sim_config,
        generators=generators
    )
    
    # Run the template sequence method
    events = scenario.run()
    assert len(events) > 0, f"Scenario {scenario_name} generated 0 events."
    
    # Verify metadata exists on base class or config
    assert scenario.metadata.name is not None
    assert scenario.metadata.description is not None
    assert len(scenario.metadata.mitre_tactics) > 0
    assert len(scenario.metadata.mitre_techniques) > 0
    
    # Check that events are sorted chronologically
    timestamps = [e.timestamp for e in events]
    assert sorted(timestamps) == timestamps, f"Events in {scenario_name} are not sorted chronologically."
    
    # Validate each event structure
    for event in events:
        assert event.id is not None
        assert event.timestamp is not None
        assert event.host is not None
        assert event.event_category is not None
        assert event.event_type is not None
