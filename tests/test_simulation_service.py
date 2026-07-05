import pytest
from app.services.elasticsearch_service import ElasticsearchService
from app.services.event_service import EventService
from app.services.detection_service import DetectionService
from app.services.simulation_service import SimulationService

@pytest.fixture
def services_bundle(tmp_path):
    es = ElasticsearchService()
    es.is_active = False
    
    events_dir = tmp_path / "events"
    alerts_dir = tmp_path / "alerts"
    
    ev_svc = EventService(es)
    ev_svc.data_dir = events_dir
    
    det_svc = DetectionService(es)
    det_svc.data_dir = alerts_dir
    
    sim_svc = SimulationService(es, ev_svc, det_svc)
    return sim_svc, ev_svc, det_svc

@pytest.mark.anyio
async def test_simulation_service_flow(services_bundle):
    sim_svc, ev_svc, det_svc = services_bundle
    
    # 1. Check scenarios list
    scenarios = sim_svc.list_available_scenarios()
    assert "brute_force" in scenarios
    assert "persistence" in scenarios
    
    # 2. Check scenario validation
    assert sim_svc.validate_scenario("brute_force") is True
    assert sim_svc.validate_scenario("invalid_name") is False
    
    # 3. Execute a simulation
    result = await sim_svc.execute_simulation(
        scenario_id="brute_force",
        seed=1,
        replay_mode=False
    )
    
    assert "simulation_id" in result
    simulation_id = result["simulation_id"]
    assert result["scenario"] == "brute_force"
    assert result["status"] == "completed"
    assert result["events_generated"] > 0
    
    # 4. Verify events were stored locally in JSON
    stored_events = ev_svc.load_events(simulation_id)
    assert len(stored_events) == result["events_generated"]
    
    # 5. Verify alerts were generated and stored locally in JSON
    stored_alerts = det_svc.load_alerts(simulation_id)
    assert len(stored_alerts) > 0
    
    # Check that metadata exists in the simulations list
    meta = sim_svc.get_simulation_metadata(simulation_id)
    assert meta is not None
    assert meta["events_generated"] == len(stored_events)
