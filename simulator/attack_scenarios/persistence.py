from typing import Dict
# pyrefly: ignore [missing-import]
from loguru import logger

from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator

# --- Executable Constants ---
SCHTASKS_EXE = "C:\\Windows\\System32\\schtasks.exe"
REG_EXE = "C:\\Windows\\System32\\reg.exe"
NET_EXE = "C:\\Windows\\System32\\net.exe"
POWERSHELL_EXE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

# --- Persistence Command Constants ---
WIN_TASK_CMD = f'{SCHTASKS_EXE} /create /tn "WinUpdate" /tr "C:\\temp\\svc.exe" /sc onlogon /ru "SYSTEM"'
WIN_RUN_CMD = f'{REG_EXE} add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Svc" /t REG_SZ /d "C:\\temp\\svc.exe" /f'
WIN_PS_CMD = "Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'C:\\temp\\svc.exe') -TaskName 'Svc'"
WIN_USER_CMD = f"{NET_EXE} user backupsvc P@ssw0rd123! /add"
WIN_GROUP_CMD = f"{NET_EXE} localgroup administrators backupsvc /add"

NIX_CRON_CMD = '(crontab -l ; echo "*/30 * * * * /tmp/.svc") | crontab -'
NIX_SYSTEMD_CMD = "systemctl enable mal.service"
NIX_USER_CMD = "useradd -m -s /bin/bash backupsvc"
NIX_SUDO_CMD = "echo 'backupsvc ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"

# --- Timing Constants (Seconds) ---
LOGIN_DELAY = (2.0, 5.0)
TASK_DELAY = (30.0, 60.0)
REGISTRY_DELAY = (15.0, 45.0)
ACCOUNT_DELAY = (60.0, 120.0)
GROUP_DELAY = (5.0, 15.0)


class PersistenceScenario(ScenarioBase):
    """
    Simulates MITRE ATT&CK Persistence techniques (TA0003).
    Models stateful adversary behavior to maintain access across reboots.
    """

    def __init__(self, entity_manager: EntityManager, config: SimulationConfig, generators: Dict[str, BaseGenerator]):
        metadata = ScenarioMetadata(
            name="Persistence and Account Manipulation",
            description="Simulates post-compromise persistence via tasks, registry, and backdooring accounts.",
            mitre_tactics=["Persistence", "Privilege Escalation", "Defense Evasion"],
            mitre_techniques=["T1053.005", "T1547.001", "T1136.001", "T1098", "T1053.003"],
            supported_platforms=["windows", "linux"],
            version="1.2.0"
        )
        super().__init__(metadata, entity_manager, config, generators)
        self._platform: str = ""

    def execute(self) -> None:
        """Main dispatcher for the persistence lifecycle."""
        self._validate_state()
        logger.info(f"Starting {self.metadata.name} on {self.victim_host.hostname} ({self._platform})")

        if self._platform == "windows":
            self._execute_windows_sequence()
        elif self._platform == "linux":
            self._execute_linux_sequence()
        else:
            raise RuntimeError(f"Platform {self._platform} not supported.")

        logger.info(f"Persistence Scenario successfully completed for {self.victim_host.hostname}")

    def _validate_state(self) -> None:
        """Ensures all context and telemetry generators are ready and normalized."""
        if not self.victim_host or not self.victim_host.hostname:
            raise RuntimeError("Persistence scenario lacks valid victim host context.")
        if not self.victim_user or not self.victim_user.name:
            raise RuntimeError("Persistence scenario lacks valid victim user context.")
        if not self.attacker or not self.attacker.name or not self.attacker.ip_pool:
            raise RuntimeError("Persistence scenario lacks valid attacker infrastructure context.")
        
        self._platform = self.victim_host.os_family.strip().lower()
        gen_key = "windows" if self._platform == "windows" else "linux"
        if gen_key not in self.generators:
            raise RuntimeError(f"Required generator '{gen_key}' is missing for platform {self._platform}.")

    def _execute_windows_sequence(self) -> None:
        """Coordinates Windows-specific persistence phases."""
        self._win_phase_login()
        self._win_phase_scheduled_task()
        self._win_phase_registry_run()
        self._win_phase_powershell_persistence()
        self._win_phase_account_backdoor()

    def _execute_linux_sequence(self) -> None:
        """Coordinates Linux-specific persistence phases."""
        self._nix_phase_login()
        self._nix_phase_cron_persistence()
        self._nix_phase_systemd_persistence()
        self._nix_phase_account_backdoor()

    # --- Windows Phases ---

    def _win_phase_login(self) -> None:
        """SOC Insight: Models initial successful authentication (4624) prior to persistence setup."""
        logger.info("T1078: Established initial session. Detection: Event ID 4624.")
        self._wait(LOGIN_DELAY)
        self.add_event(self._win_gen().generate_4624(self.victim_host, self.victim_user))

    def _win_phase_scheduled_task(self) -> None:
        """SOC Insight: Models T1053.005. Links process execution (4688) to task registration (4698)."""
        logger.info("T1053.005: Scheduled Task registered via schtasks.exe. Detection: Event ID 4698.")
        self._wait(TASK_DELAY)
        self._emit_win_process("schtasks.exe", SCHTASKS_EXE, WIN_TASK_CMD)
        self.advance_time(self._rng.uniform(1.0, 3.0))
        self.add_event(self._win_gen().generate_4698(self.victim_host, self.victim_user))

    def _win_phase_registry_run(self) -> None:
        """SOC Insight: Models T1547.001. Registry-based persistence via reg.exe (4688)."""
        logger.info("T1547.001: Run Key added via reg.exe. Detection: Event ID 4688 registry flags.")
        self._wait(REGISTRY_DELAY)
        self._emit_win_process("reg.exe", REG_EXE, WIN_RUN_CMD)

    def _win_phase_powershell_persistence(self) -> None:
        """SOC Insight: Models fileless/scripted persistence. Detection: Script Block Logging (4104)."""
        logger.info("T1059.001: PowerShell persistence deployed. Detection: Event ID 4104.")
        self._wait(TASK_DELAY)
        self.add_event(self._win_gen().generate_4104(self.victim_host, self.victim_user, WIN_PS_CMD))

    def _win_phase_account_backdoor(self) -> None:
        """SOC Insight: Models T1136.001. Explicit link between net.exe (4688) and User Creation (4720)."""
        logger.warning("T1136.001: Admin Backdoor created. Detection: Event IDs 4720, 4732.")
        self._wait(ACCOUNT_DELAY)
        self._emit_win_process("net.exe", NET_EXE, WIN_USER_CMD)
        self.add_event(self._win_gen().generate_4720(self.victim_host, self.victim_user))
        self._wait(GROUP_DELAY)
        self._emit_win_process("net.exe", NET_EXE, WIN_GROUP_CMD)
        self.add_event(self._win_gen().generate_4732(self.victim_host, self.victim_user))

    # --- Linux Phases ---

    def _nix_phase_login(self) -> None:
        """SOC Insight: Models initial SSH access in auth.log (Accepted password)."""
        logger.info("T1078: Establishing SSH session. Detection: auth.log 'Accepted password'.")
        self._wait(LOGIN_DELAY)
        ip = str(self.attacker.ip_pool[0])
        self.add_event(self._nix_gen().generate_ssh_login(self.victim_host, self.victim_user, True, ip))

    def _nix_phase_cron_persistence(self) -> None:
        """SOC Insight: Models T1053.003. Detection: Auditd EXECVE syscall for crontab manipulation."""
        logger.info("T1053.003: Cron persistence deployed. Detection: Auditd SYSCALL_59.")
        self._wait(TASK_DELAY)
        self._emit_linux_exec(NIX_CRON_CMD)

    def _nix_phase_systemd_persistence(self) -> None:
        """SOC Insight: Models T1543.002. Detection: Auditd monitoring systemctl and service files."""
        logger.info("T1543.002: Systemd service enabled. Detection: Auditd SYSCALL.")
        self._wait(REGISTRY_DELAY)
        self._emit_linux_exec(NIX_SYSTEMD_CMD)

    def _nix_phase_account_backdoor(self) -> None:
        """SOC Insight: Models T1136. Links useradd process (Auditd) with sudoers modification (sudo log)."""
        logger.warning("T1136: Backdoor user created with sudo. Detection: Auditd + sudo logs.")
        self._wait(ACCOUNT_DELAY)
        self._emit_linux_exec(NIX_USER_CMD)
        self._wait(GROUP_DELAY)
        self._emit_linux_exec(NIX_SUDO_CMD)
        self.add_event(self._nix_gen().generate_sudo(self.victim_host, self.victim_user, "sudoers_mod"))

    # --- Reusable Helpers ---

    def _wait(self, delay_range: tuple[float, float]) -> None:
        """Applies a deterministic delay between attack steps."""
        self.advance_time(self._rng.uniform(*delay_range))

    def _win_gen(self) -> BaseGenerator:
        """Safe access to the Windows telemetry generator."""
        return self.generators["windows"]

    def _nix_gen(self) -> BaseGenerator:
        """Safe access to the Linux telemetry generator."""
        return self.generators["linux"]

    def _emit_win_process(self, name: str, path: str, cmd: str) -> None:
        """Standardized helper for emitting Windows process creation (4688) events."""
        proc = Process(pid=self._rng.randint(1000, 9999), name=name, executable=path, command_line=cmd)
        self.add_event(self._win_gen().generate_4688(self.victim_host, self.victim_user, proc))

    def _emit_linux_exec(self, command: str) -> None:
        """Standardized helper for emitting Linux Auditd EXECVE telemetry."""
        self.add_event(self._nix_gen().generate_auditd_exec(self.victim_host, self.victim_user, command))
