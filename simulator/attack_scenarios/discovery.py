from typing import Dict, Final, List, Tuple
# pyrefly: ignore [missing-import]
from loguru import logger
from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator

# --- Executable Command Definitions ---
WIN_RECON: Final[List[Tuple[str, str, str, str]]] = [
    ("whoami.exe", "C:\\Windows\\System32\\whoami.exe", "whoami", "T1033"),
    ("hostname.exe", "C:\\Windows\\System32\\hostname.exe", "hostname", "T1082"),
    ("systeminfo.exe", "C:\\Windows\\System32\\systeminfo.exe", "systeminfo", "T1082"),
    ("ipconfig.exe", "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all", "T1016"),
    ("tasklist.exe", "C:\\Windows\\System32\\tasklist.exe", "tasklist", "T1057"),
    ("net.exe", "C:\\Windows\\System32\\net.exe", "net user", "T1087"),
    ("net.exe", "C:\\Windows\\System32\\net.exe", "net localgroup administrators", "T1087"),
    ("arp.exe", "C:\\Windows\\System32\\arp.exe", "arp -a", "T1016"),
    ("netstat.exe", "C:\\Windows\\System32\\netstat.exe", "netstat -ano", "T1049"),
    ("wmic.exe", "C:\\Windows\\System32\\wbem\\wmic.exe", "wmic process list full", "T1057")
]
NIX_RECON: Final[List[Tuple[str, str]]] = [
    ("whoami", "T1033"),
    ("hostname", "T1082"),
    ("id", "T1033"),
    ("uname -a", "T1082"),
    ("ip addr", "T1016"),
    ("ps aux", "T1057"),
    ("ss -tulpn", "T1049"),
    ("cat /etc/passwd", "T1087"),
    ("find /home", "T1083")
]

# --- Timing Constants ---
WAIT_LOGIN: Final[Tuple[float, float]] = (2.0, 5.0)
WAIT_RECON: Final[Tuple[float, float]] = (1.0, 4.0)


class DiscoveryScenario(ScenarioBase):
    """
    Simulates MITRE ATT&CK Discovery (TA0007).
    Models post-compromise reconnaissance where an adversary gathers system, user, and network context.
    """

    def __init__(
        self,
        entity_manager: EntityManager,
        config: SimulationConfig,
        generators: Dict[str, BaseGenerator]
    ):
        metadata = ScenarioMetadata(
            name="System and Network Discovery Reconnaissance",
            description="Simulates comprehensive discovery commands to identify users, software, and network configuration.",
            mitre_tactics=["Discovery"],
            mitre_techniques=["T1033", "T1082", "T1016", "T1049", "T1057", "T1087", "T1083"],
            supported_platforms=["windows", "linux"],
            version="1.0.0"
        )
        super().__init__(metadata, entity_manager, config, generators)

    def execute(self) -> None:
        """Main dispatcher for the discovery scenario sequence."""
        self._validate_state()
        platform = self.victim_host.os_family.strip().lower()
        
        log = logger.bind(
            technique="TA0007", 
            host=self.victim_host.hostname, 
            user=self.victim_user.name,
            platform=platform
        )
        log.info(f"Starting discovery reconnaissance on {self.victim_host.hostname}")

        if platform == "windows":
            self._execute_windows_sequence(self.generators["windows"])
        elif platform == "linux":
            self._execute_linux_sequence(self.generators["linux"])
        else:
            raise RuntimeError(f"Unsupported platform: {platform}")

        log.info("Discovery scenario orchestration successfully completed.")

    def _execute_windows_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates Windows discovery timeline: Logon -> Recon commands."""
        self._wait(WAIT_LOGIN)
        self.add_event(gen.generate_4624(self.victim_host, self.victim_user))
        
        for name, path, cmd, tid in WIN_RECON:
            self._wait(WAIT_RECON)
            self._emit_win_recon(gen, name, path, cmd, tid)

    def _execute_linux_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates Linux discovery timeline: SSH Login -> Auditd Recon."""
        self._wait(WAIT_LOGIN)
        src_ip = str(self._rng.choice(self.attacker.ip_pool))
        self.add_event(gen.generate_ssh_login(self.victim_host, self.victim_user, True, src_ip))
        
        for cmd, tid in NIX_RECON:
            self._wait(WAIT_RECON)
            self._emit_nix_recon(gen, cmd, tid)

    def _emit_win_recon(self, gen: BaseGenerator, name: str, path: str, cmd: str, tid: str) -> None:
        """Helper to create and emit a Windows process discovery event (4688)."""
        logger.bind(technique=tid, eid=4688).debug(f"Discovery phase: Executing {name}")
        proc = Process(
            pid=self._rng.randint(1000, 9999),
            name=name,
            executable=path,
            command_line=cmd
        )
        self.add_event(gen.generate_4688(self.victim_host, self.victim_user, proc))

    def _emit_nix_recon(self, gen: BaseGenerator, cmd: str, tid: str) -> None:
        """Helper to create and emit a Linux Auditd execution discovery event."""
        logger.bind(technique=tid, source="auditd").debug(f"Discovery phase: Executing {cmd}")
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, cmd))

    def _validate_state(self) -> None:
        """Ensures all actors and platform-specific generators are available."""
        if not self.victim_host or not self.victim_user or not self.attacker:
            raise RuntimeError("Discovery scenario lacks required context.")
        if not self.attacker.ip_pool:
            raise RuntimeError(f"Attacker {self.attacker.name} has no IP pool.")
        
        if not self.victim_host.os_family:
            raise RuntimeError(f"Host {self.victim_host.hostname} missing os_family metadata.")
            
        platform = self.victim_host.os_family.strip().lower()
        if platform not in self.generators:
            raise RuntimeError(f"Required generator '{platform}' is missing for discovery simulation.")

    def _wait(self, delay_range: Tuple[float, float]) -> None:
        """Applies a deterministic delay using the scenario's RNG."""
        self.advance_time(self._rng.uniform(*delay_range))