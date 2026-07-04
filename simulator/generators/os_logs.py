from datetime import datetime
from typing import List, Optional, Any, Dict
from uuid import uuid4

from shared.schemas.models.log_event import LogEvent
from shared.schemas.ecs.base import Host, User, Process, File
from shared.constants.enums import Platform
from simulator.generators.base import BaseGenerator

# --- Log Templates (Realistic Mocking) ---

WIN_EVENT_BASE = "Subject: Security ID: S-1-5-18 Account Name: SYSTEM Account Domain: NT AUTHORITY. "
LINUX_DATE_FMT = "%b %d %H:%M:%S"

# --- Internal Event Factory ---

class EventFactory:
    """Utility to construct valid ECS LogEvents with consistent metadata."""
    
    @staticmethod
    def create_base(
        generator: BaseGenerator, 
        host: Host, 
        user: User, 
        category: str, 
        event_type: str
    ) -> LogEvent:
        # Strict Validation: Ensure host/user are known to the system
        if host not in generator.entity_manager.hosts:
            raise ValueError(f"Unauthorized Host: {host.hostname}")
        if user not in generator.entity_manager.users:
            raise ValueError(f"Unauthorized User: {user.name}")

        return LogEvent(
            timestamp=generator._get_simulated_timestamp(),
            event_category=category,
            event_type=event_type,
            host=host,
            user=user,
            raw_log="",
            log_source="generic"
        )

# --- Windows Implementation ---

class WindowsEventGenerator(BaseGenerator):
    """Refined Generator for high-fidelity Windows Security Events."""

    def get_supported_event_types(self) -> List[str]:
        return ["4624", "4625", "4688", "4720", "4732", "4104", "4698", "1102"]

    def generate_4624(self, host: Host, user: User, logon_type: int = 3) -> LogEvent:
        """Success Logon."""
        event = EventFactory.create_base(self, host, user, "iam", "authentication_success")
        event.log_source = "windows_event_security"
        event.raw_log = (
            f"An account was successfully logged on. {WIN_EVENT_BASE} "
            f"Target: User: {user.name} Domain: {user.domain}. Logon Type: {logon_type}. "
            f"Logon ID: {hex(self._rng.getrandbits(32))}"
        )
        event.custom_fields = {"winlog_event_id": 4624, "logon_type": logon_type}
        return event

    def generate_4625(self, host: Host, user: User) -> LogEvent:
        """Failed Logon."""
        event = EventFactory.create_base(self, host, user, "iam", "authentication_failure")
        event.log_source = "windows_event_security"
        event.raw_log = (
            f"An account failed to log on. {WIN_EVENT_BASE} "
            f"Failure Information: Reason: Unknown user name or bad password. "
            f"Status: 0xC000006D. Sub Status: 0xC0000064."
        )
        event.custom_fields = {"winlog_event_id": 4625}
        return event

    def generate_4688(self, host: Host, user: User, process: Process) -> LogEvent:
        """Process Creation."""
        event = EventFactory.create_base(self, host, user, "process", "creation")
        event.log_source = "windows_event_security"
        event.process = process
        event.raw_log = (
            f"A new process has been created. Creator: User: {user.name}. "
            f"New Process Name: {process.executable} Command Line: {process.command_line} "
            f"Process ID: {hex(process.pid)}"
        )
        event.custom_fields = {"winlog_event_id": 4688}
        return event

    def generate_4104(self, host: Host, user: User, script_content: str) -> LogEvent:
        """PowerShell Script Block Logging."""
        event = EventFactory.create_base(self, host, user, "process", "script_execution")
        event.log_source = "powershell"
        event.raw_log = (
            f"Creating Scriptblock text (1 of 1):\n{script_content}\n"
            f"ScriptBlock ID: {uuid4()} Path: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        )
        event.custom_fields = {"winlog_event_id": 4104}
        return event

    def generate_1102(self, host: Host, user: User) -> LogEvent:
        """Audit Log Cleared."""
        event = EventFactory.create_base(self, host, user, "admin", "deletion")
        event.log_source = "windows_event_security"
        event.raw_log = f"The audit log was cleared. Subject: User: {user.name} Domain: {user.domain}."
        event.custom_fields = {"winlog_event_id": 1102}
        return event

# --- Linux Implementation ---

class LinuxSyslogGenerator(BaseGenerator):
    """Refined Generator for standard Linux distribution logs."""

    def get_supported_event_types(self) -> List[str]:
        return ["ssh_login", "sudo", "auditd", "cron"]

    def generate_ssh_login(self, host: Host, user: User, success: bool = True, src_ip: str = "1.2.3.4") -> LogEvent:
        """SSH Authentication via auth.log."""
        event_type = "authentication_success" if success else "authentication_failure"
        event = EventFactory.create_base(self, host, user, "authentication", event_type)
        event.log_source = "auth_log"
        status = "Accepted" if success else "Failed"
        event.raw_log = (
            f"{event.timestamp.strftime(LINUX_DATE_FMT)} {host.hostname} sshd[{self._rng.randint(1000, 9000)}]: "
            f"{status} password for {user.name} from {src_ip} port {self._rng.randint(30000, 60000)} ssh2"
        )
        return event

    def generate_sudo(self, host: Host, user: User, command: str) -> LogEvent:
        """Sudo execution entry."""
        event = EventFactory.create_base(self, host, user, "process", "elevation")
        event.log_source = "auth_log"
        event.process = Process(pid=self._rng.randint(1000, 9000), name="sudo", command_line=command)
        event.raw_log = (
            f"{event.timestamp.strftime(LINUX_DATE_FMT)} {host.hostname} sudo: "
            f"{user.name} : TTY=pts/0 ; PWD=/home/{user.name} ; USER=root ; COMMAND={command}"
        )
        return event

    def generate_auditd_exec(self, host: Host, user: User, executable: str) -> LogEvent:
        """Auditd EXECVE log."""
        event = EventFactory.create_base(self, host, user, "process", "creation")
        event.log_source = "auditd"
        event.process = Process(pid=self._rng.randint(1000, 9000), name=executable.split("/")[-1], executable=executable)
        event.raw_log = (
            f"type=SYSCALL msg=audit({event.timestamp.timestamp()}:{self._rng.randint(100, 999)}): "
            f"arch=c000003e syscall=59 success=yes exit=0 a0=7ff exe=\"{executable}\" key=\"exec_rules\""
        )
        return event