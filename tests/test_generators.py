import pytest
import uuid
from datetime import datetime, timezone
from shared.schemas.ecs.base import Process
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.os_logs import WindowsEventGenerator, LinuxSyslogGenerator

@pytest.fixture
def entity_manager():
    manager = EntityManager("simulator/config")
    manager.load_all()
    return manager

@pytest.fixture
def sim_config():
    return SimulationConfig(
        simulation_id=uuid.uuid4(),
        scenario_id="brute_force",
        seed=42,
        replay_mode=False
    )

def test_windows_generator_events(entity_manager, sim_config):
    generator = WindowsEventGenerator(entity_manager, sim_config)
    
    # Grab the first Windows host and first user
    windows_hosts = [h for h in entity_manager.hosts if h.os_family == "windows"]
    assert len(windows_hosts) > 0
    host = windows_hosts[0]
    user = entity_manager.users[0]
    
    # 1. Test 4624
    ev_4624 = generator.generate_4624(host, user, logon_type=3)
    assert ev_4624.event_category == "iam"
    assert ev_4624.event_type == "authentication_success"
    assert ev_4624.custom_fields["winlog_event_id"] == 4624
    assert ev_4624.custom_fields["logon_type"] == 3
    
    # 2. Test 4625
    ev_4625 = generator.generate_4625(host, user)
    assert ev_4625.event_category == "iam"
    assert ev_4625.event_type == "authentication_failure"
    assert ev_4625.custom_fields["winlog_event_id"] == 4625
    
    # 3. Test 4688
    proc = Process(pid=1234, name="whoami.exe", command_line="whoami /all", executable="whoami.exe")
    ev_4688 = generator.generate_4688(host, user, proc)
    assert ev_4688.event_category == "process"
    assert ev_4688.custom_fields["winlog_event_id"] == 4688
    assert ev_4688.process.command_line == "whoami /all"

def test_linux_generator_events(entity_manager, sim_config):
    generator = LinuxSyslogGenerator(entity_manager, sim_config)
    
    # Grab the first Linux host and first user
    linux_hosts = [h for h in entity_manager.hosts if h.os_family == "linux"]
    assert len(linux_hosts) > 0
    host = linux_hosts[0]
    user = entity_manager.users[0]
    
    # Test SSH login
    ev_ssh = generator.generate_ssh_login(host, user, success=False, src_ip="192.168.1.100")
    assert ev_ssh.log_source == "auth_log"
    assert ev_ssh.event_type == "authentication_failure"
    assert "Failed password for" in ev_ssh.raw_log

def test_advance_time_and_determinism(entity_manager, sim_config):
    generator = WindowsEventGenerator(entity_manager, sim_config)
    
    windows_hosts = [h for h in entity_manager.hosts if h.os_family == "windows"]
    host = windows_hosts[0]
    user = entity_manager.users[0]
    
    t_start = generator.timeline.current_time
    generator.advance_time(10.0)
    
    # Subsequent event must have timestamp advanced by at least 10s
    ev = generator.generate_4624(host, user)
    t_event = ev.timestamp
    assert (t_event - t_start).total_seconds() >= 10.0
