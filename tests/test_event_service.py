import pytest
import uuid
from app.services.elasticsearch_service import ElasticsearchService
from app.services.event_service import EventService

@pytest.fixture
def event_service(tmp_path):
    es = ElasticsearchService()
    es.is_active = False
    
    svc = EventService(es)
    svc.data_dir = tmp_path
    return svc

def test_save_load_delete_events(event_service):
    sim_id = uuid.uuid4()
    events = [
        {
            "id": str(uuid.uuid4()),
            "timestamp": "2026-07-05T12:00:00Z",
            "host": {
                "hostname": "win-dc-01",
                "ip": ["10.0.20.10"],
                "os_family": "windows",
                "criticality": "high"
            },
            "user": {
                "name": "bjohnson",
                "domain": "corp.sentinel.sim"
            },
            "event_category": "iam",
            "event_type": "authentication_success",
            "log_source": "windows_event_security",
            "raw_log": "Successful Logon",
            "custom_fields": {
                "winlog_event_id": 4624
            }
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": "2026-07-05T12:01:00Z",
            "host": {
                "hostname": "win-dc-01",
                "ip": ["10.0.20.10"],
                "os_family": "windows",
                "criticality": "high"
            },
            "user": {
                "name": "fgallagher",
                "domain": "corp.sentinel.sim"
            },
            "event_category": "process",
            "event_type": "process_creation",
            "log_source": "windows_event_security",
            "raw_log": "Process Created",
            "custom_fields": {
                "winlog_event_id": 4688
            }
        }
    ]
    
    # Save
    event_service.save_events(sim_id, events)
    assert len(event_service.list_simulations()) == 1
    
    # Load
    loaded = event_service.load_events(sim_id)
    assert len(loaded) == 2
    assert loaded[0]["user"]["name"] == "bjohnson"
    
    # Search single filter
    results = event_service.search_events(simulation_id=sim_id, user="fgallagher")
    assert len(results) == 1
    assert results[0]["user"]["name"] == "fgallagher"
    
    # Search multiple filter mismatch
    results_mismatch = event_service.search_events(simulation_id=sim_id, user="bjohnson", event_id=4688)
    assert len(results_mismatch) == 0
    
    # Retrieve single event
    e_id = uuid.UUID(events[0]["id"])
    ev = event_service.get_event(sim_id, e_id)
    assert ev is not None
    assert ev["user"]["name"] == "bjohnson"
    
    # Delete
    assert event_service.delete_events(sim_id) is True
    assert len(event_service.list_simulations()) == 0
