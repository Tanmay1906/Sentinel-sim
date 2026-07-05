import pytest
from pathlib import Path
from simulator.config.entities import (
    HostConfig,
    UserConfig,
    AttackerConfig,
    EntityManager,
)

def test_host_schema_validation():
    data = {
        "hostname": "win-dc-01",
        "ip": ["10.0.20.10"],
        "id": "host-win-dc-01",
        "os_family": "windows",
        "os_name": "Windows Server 2022 Datacenter",
        "criticality": "mission_critical",
        "environment": "production",
        "business_owner": "SecOps Team",
        "department": "Infrastructure"
    }
    host = HostConfig(**data)
    assert host.hostname == "win-dc-01"
    assert host.os_family == "windows"

def test_user_schema_validation():
    data = {
        "name": "bjohnson",
        "id": "user-bjohnson",
        "domain": "corp.sentinel.sim",
        "privilege_level": "domain_admin",
        "department": "IT"
    }
    user = UserConfig(**data)
    assert user.name == "bjohnson"
    assert user.privilege_level == "domain_admin"

def test_attacker_schema_validation():
    data = {
        "name": "APT29",
        "actor_type": "apt",
        "skill_level": "elite",
        "ip_pool": ["185.220.101.5"],
        "user_agent_pool": ["Mozilla/5.0"]
    }
    attacker = AttackerConfig(**data)
    assert attacker.name == "APT29"
    assert attacker.actor_type == "apt"

def test_entity_manager_loading():
    config_dir = Path(__file__).resolve().parents[1] / "simulator" / "config"
    manager = EntityManager(config_dir)
    manager.load_all()
    
    # Verify loaded hosts
    assert len(manager.hosts) >= 15
    # Verify loaded users
    assert len(manager.users) >= 20
    # Verify loaded attackers
    assert len(manager.attackers) >= 4
    
    # Test host selection filtering
    windows_hosts = [h for h in manager.hosts if h.os_family == "windows"]
    assert len(windows_hosts) >= 10
    
    # Test host lookup
    dc = next((h for h in manager.hosts if h.hostname == "win-dc-01"), None)
    assert dc is not None
    assert dc.hostname == "win-dc-01"
