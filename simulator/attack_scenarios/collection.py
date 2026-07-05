from typing import Dict, Final, List, Tuple
# pyrefly: ignore [missing-import]
from loguru import logger
from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator

# --- Collection Command Constants ---
WIN_DIR_SEARCH: Final[str] = "cmd.exe /c dir /s /b C:\\Users\\*.docx C:\\Users\\*.pdf C:\\Users\\*.xlsx"
WIN_PS_COLLECT: Final[str] = "Get-ChildItem -Path C:\\Users\\ -Include *.key,*.gpg,*.pgp -Recurse -ErrorAction SilentlyContinue"
WIN_COMPRESS: Final[str] = "tar.exe -caf C:\\Users\\Public\\data_stage.zip C:\\Users\\Documents\\"
WIN_MOVE_STAGE: Final[str] = "cmd.exe /c copy C:\\Users\\Public\\data_stage.zip C:\\Windows\\Temp\\debug.bin"
NIX_FIND_SENSITIVE: Final[str] = "find /home /var/www \\( -name '*.conf' -o -name '*.key' -o -name '*.backup' \\) -type f"
NIX_GREP_SECRETS: Final[str] = "grep -rE 'password|api_key|secret' /home/ /etc/config/*"
NIX_TAR_STAGE: Final[str] = "tar -czf /tmp/.system_cache.tar.gz /home/user/Documents /home/user/.ssh"
NIX_LSBLK: Final[str] = "lsblk --output NAME,FSTYPE,LABEL,MOUNTPOINT"

# --- Timing Constants ---
WAIT_LOGIN: Final[Tuple[float, float]] = (2.0, 5.0)
WAIT_COLLECT: Final[Tuple[float, float]] = (5.0, 15.0)
WAIT_ARCHIVE: Final[Tuple[float, float]] = (10.0, 30.0)


class CollectionScenario(ScenarioBase):
    """
    Simulates MITRE ATT&CK Collection (TA0009).
    Models adversary behavior for identifying, gathering, and staging sensitive data for exfiltration.
    """

    def __init__(
        self,
        entity_manager: EntityManager,
        config: SimulationConfig,
        generators: Dict[str, BaseGenerator]
    ):
        metadata = ScenarioMetadata(
            name="Sensitive Data Collection and Staging",
            description="Simulates automated search and archiving of sensitive files and credentials.",
            mitre_tactics=["Collection"],
            mitre_techniques=["T1005", "T1074.001", "T1119", "T1560.001", "T1039"],
            supported_platforms=["windows", "linux"],
            version="1.0.0"
        )
        super().__init__(metadata, entity_manager, config, generators)

    def execute(self) -> None:
        """Main dispatcher for the collection scenario."""
        self._validate_state()
        platform = self.victim_host.os_family.strip().lower()
        
        log = logger.bind(
            technique="TA0009",
            host=self.victim_host.hostname,
            user=self.victim_user.name,
            platform=platform
        )
        log.info(f"Initiating Collection and Staging on {self.victim_host.hostname}")

        if platform == "windows":
            self._execute_windows_sequence(self.generators["windows"])
        elif platform == "linux":
            self._execute_linux_sequence(self.generators["linux"])
        else:
            raise RuntimeError(f"Unsupported platform for collection: {platform}")

        log.info("Collection scenario orchestration successfully completed.")

    def _execute_windows_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates Windows collection: Search -> PS Capture -> Archive -> Stage."""
        self._wait(WAIT_LOGIN)
        self.add_event(gen.generate_4624(self.victim_host, self.victim_user))
        
        # Phase 1: Automated Search
        logger.info("Searching user documents")
        self._wait(WAIT_COLLECT)
        self._emit_win_proc(gen, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", WIN_DIR_SEARCH)
        
        # Phase 2: PowerShell Scripted Collection
        self._wait(WAIT_COLLECT)
        self.add_event(gen.generate_4104(self.victim_host, self.victim_user, WIN_PS_COLLECT))
        
        # Phase 3: Archive Staging
        logger.info("Archiving sensitive files")
        self._wait(WAIT_ARCHIVE)
        self._emit_win_proc(gen, "tar.exe", "C:\\Windows\\System32\\tar.exe", WIN_COMPRESS)
        
        # Phase 4: Data Staged
        logger.info("Preparing staging directory")
        self._wait(WAIT_COLLECT)
        self._emit_win_proc(gen, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", WIN_MOVE_STAGE)

    def _execute_linux_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates Linux collection: Find -> Grep -> Tar -> Mount discovery."""
        self._wait(WAIT_LOGIN)
        src_ip = str(self._rng.choice(self.attacker.ip_pool))
        self.add_event(gen.generate_ssh_login(self.victim_host, self.victim_user, True, src_ip))
        
        # Phase 1: File Search
        logger.info("Searching user documents")
        self._wait(WAIT_COLLECT)
        self._emit_nix_exec(gen, NIX_FIND_SENSITIVE, "T1005")
        
        # Phase 2: Grep for secrets in configs
        self._wait(WAIT_COLLECT)
        self._emit_nix_exec(gen, NIX_GREP_SECRETS, "T1552.001")
        
        # Phase 3: Local Staging via Tar
        logger.info("Archiving sensitive files")
        self._wait(WAIT_ARCHIVE)
        self._emit_nix_exec(gen, NIX_TAR_STAGE, "T1560.001")
        
        # Phase 4: Identify Removable Media/Network Shares
        self._wait(WAIT_COLLECT)
        self._emit_nix_exec(gen, NIX_LSBLK, "T1082")

    def _emit_win_proc(self, gen: BaseGenerator, name: str, path: str, cmd: str) -> None:
        """Constructs and emits a Windows process creation event (4688)."""
        logger.bind(technique="T1119", eid=4688).debug(f"Collection: Executing {name}")
        proc = Process(
            pid=self._rng.randint(1000, 9999),
            name=name,
            executable=path,
            command_line=cmd
        )
        self.add_event(gen.generate_4688(self.victim_host, self.victim_user, proc))

    def _emit_nix_exec(self, gen: BaseGenerator, cmd: str, technique_id: str) -> None:
        """Constructs and emits a Linux Auditd execution event."""
        logger.bind(technique=technique_id, source="auditd").debug(f"Collection: Executing {cmd}")
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, cmd))

    def _validate_state(self) -> None:
        """Ensures all actor contexts and platform-specific generators are initialized."""
        if not self.victim_host or not self.victim_user or not self.attacker:
            raise RuntimeError("Collection scenario lacks required actor context.")
        if not self.attacker.ip_pool:
            raise RuntimeError(f"Attacker {self.attacker.name} has no IP pool.")
        
        platform = self.victim_host.os_family.strip().lower()
        if platform not in self.generators:
            raise RuntimeError(f"Required generator '{platform}' is missing for collection simulation.")

    def _wait(self, delay_range: Tuple[float, float]) -> None:
        """Deterministic delay between steps."""
        self.advance_time(self._rng.uniform(*delay_range))