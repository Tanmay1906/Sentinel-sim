import os
import json
import pytest
import uuid
from fastapi.testclient import TestClient

# Setup mock environment for settings
os.environ["SECRET_KEY"] = "mock_secret_key_mock_secret_key_mock_secret_key"
os.environ["ELASTICSEARCH_URL"] = "http://localhost:9200"
os.environ["ELASTICSEARCH_PASSWORD"] = "elastic"

from backend.app.main import app
from app.api.dependencies import (
    get_simulation_service, 
    get_event_service, 
    get_detection_service,
    get_elasticsearch_service
)
from app.services.elasticsearch_service import ElasticsearchService
from app.services.event_service import EventService
from app.services.detection_service import DetectionService
from app.services.simulation_service import SimulationService

@pytest.fixture(scope="module")
def mock_services(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("api_data")
    es = ElasticsearchService()
    es.is_active = False
    
    events_dir = tmp_path / "events"
    alerts_dir = tmp_path / "alerts"
    
    ev_svc = EventService(es)
    ev_svc.data_dir = events_dir
    
    det_svc = DetectionService(es)
    det_svc.data_dir = alerts_dir
    
    sim_svc = SimulationService(es, ev_svc, det_svc)
    
    # Mock statistics endpoint fallback query path
    def mock_stats():
        total_events = 0
        total_alerts = 0
        events_by_platform = {}
        events_by_category = {}
        top_hosts = {}
        top_users = {}
        top_mitre_techniques = {}
        alerts_by_severity = {}
        alerts_by_rule = {}
        daily_timeline = {}
        
        # Read events
        if events_dir.exists():
            for file in events_dir.glob("*.json"):
                with open(file, "r") as f:
                    data = json.load(f)
                    total_events += len(data)
                    for e in data:
                        platform = e.get("host", {}).get("os_family", "unknown")
                        events_by_platform[platform] = events_by_platform.get(platform, 0) + 1
                        category = e.get("event_category", "unknown")
                        events_by_category[category] = events_by_category.get(category, 0) + 1
                        host = e.get("host", {}).get("hostname", "unknown")
                        top_hosts[host] = top_hosts.get(host, 0) + 1
                        user = e.get("user", {}).get("name", "unknown")
                        top_users[user] = top_users.get(user, 0) + 1
                        
        # Read alerts
        if alerts_dir.exists():
            for file in alerts_dir.glob("*.json"):
                with open(file, "r") as f:
                    data = json.load(f)
                    total_alerts += len(data)
                    for a in data:
                        mitre = a.get("mitre_technique", "unknown")
                        top_mitre_techniques[mitre] = top_mitre_techniques.get(mitre, 0) + 1
                        severity = a.get("severity", "unknown")
                        alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
                        rule = a.get("rule_name", "unknown")
                        alerts_by_rule[rule] = alerts_by_rule.get(rule, 0) + 1
                        daily_timeline["2026-07-05"] = daily_timeline.get("2026-07-05", 0) + 1
                        
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "events_by_platform": events_by_platform,
            "events_by_category": events_by_category,
            "top_hosts": top_hosts,
            "top_users": top_users,
            "top_mitre_techniques": top_mitre_techniques,
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_rule": alerts_by_rule,
            "daily_timeline": daily_timeline
        }
    es.statistics = mock_stats
    
    return sim_svc, ev_svc, det_svc, es

@pytest.fixture(scope="module", autouse=True)
def setup_dependency_overrides(mock_services):
    sim_svc, ev_svc, det_svc, es = mock_services
    
    app.dependency_overrides[get_event_service] = lambda: ev_svc
    app.dependency_overrides[get_detection_service] = lambda: det_svc
    app.dependency_overrides[get_simulation_service] = lambda: sim_svc
    app.dependency_overrides[get_elasticsearch_service] = lambda: es
    
    yield
    
    app.dependency_overrides.clear()

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["api_alive"] is True
        assert data["elasticsearch"]["storage_mode"] == "json"

def test_scenarios_list_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/scenarios")
        assert response.status_code == 200
        data = response.json()
        assert "brute_force" in data

def test_full_simulate_and_query_flow():
    with TestClient(app) as client:
        # 1. Trigger simulation
        payload = {
            "scenario": "brute_force",
            "seed": 42,
            "replay": False
        }
        res_sim = client.post("/api/v1/simulate", json=payload)
        assert res_sim.status_code == 200
        sim_data = res_sim.json()
        sim_id = sim_data["simulation_id"]
        
        # 2. Get events list
        res_ev = client.get(f"/api/v1/events?simulation_id={sim_id}&limit=5")
        assert res_ev.status_code == 200
        assert len(res_ev.json()["events"]) > 0
        
        # 3. Get alerts list
        res_al = client.get(f"/api/v1/alerts?simulation_id={sim_id}")
        assert res_al.status_code == 200
        alerts_list = res_al.json()["alerts"]
        assert len(alerts_list) > 0
        alert_id = alerts_list[0]["alert_id"]
        
        # 4. Get statistics
        res_stats = client.get("/api/v1/statistics")
        assert res_stats.status_code == 200
        stats_data = res_stats.json()
        assert stats_data["total_events"] > 0
        assert stats_data["total_alerts"] > 0
        
        # 5. Retrieve single alert
        res_single = client.get(f"/api/v1/alerts/{sim_id}/{alert_id}")
        assert res_single.status_code == 200
        assert res_single.json()["alert_id"] == alert_id
        
        # 6. Delete alerts and events
        res_del_al = client.delete(f"/api/v1/alerts/{sim_id}")
        assert res_del_al.status_code == 200
        
        res_del_ev = client.delete(f"/api/v1/events/{sim_id}")
        assert res_del_ev.status_code == 200
