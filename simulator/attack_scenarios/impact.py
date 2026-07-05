from typing import Dict, Final
# pyrefly: ignore [missing-import]
from loguru import logger
from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator

# --- Windows Executable Constants ---
VSSADMIN_EXE: Final[str] = "C:\\Windows\\System32\\vssadmin.exe"
WBADMIN_EXE: Final[str] = "C:\\Windows\\System32\\wbadmin.exe"
NET_EXE: Final[str] = "C:\\Windows\\System32\\net.exe"
CIPHER_EXE: Final[str] = "C:\\Windows\\System32\\cipher.exe"
NOTEPAD_EXE: Final[str] = "C:\\Windows\\System32\\notepad.exe"
RANSOM_EXE: Final[str] = "C:\\Users\\Public\\ransomware.exe"

# --- Linux Command Constants ---
NIX_STOP_SVC: Final[str] = "systemctl stop apparmor"
NIX_RM_BACKUP: Final[str] = "rm -rf /var/backups/"
NIX_ENCRYPT: Final[str] = "openssl enc -aes-256-cbc -salt -in data.zip -out data.zip.enc -k P@ss"
NIX_RENAME: Final[str] = "find /home -name '.docx' -exec mv {} {}.lock ;"
NIX_NOTE: Final[str] = "echo 'Files encrypted. Pay 1 BTC to address...' > /etc/motd"

# --- Delay Ranges ---
SHORT_DELAY: Final[tuple] = (1.0, 3.0)
ACTION_DELAY: Final[tuple] = (5.0, 15.0)


class ImpactScenario(ScenarioBase):

    def __init__(self, entity_manager: EntityManager, config: SimulationConfig, generators: Dict[str, BaseGenerator]):
        metadata = ScenarioMetadata(
            name="Ransomware and Data Destruction",
            description="Simulates destructive impact via system recovery inhibition and data encryption.",
            mitre_tactics=["Impact", "Defense Evasion"],
            mitre_techniques=["T1486", "T1490", "T1489", "T1562.001"],
            supported_platforms=["windows", "linux"],
            version="1.0.0"
        )
        super().__init__(metadata, entity_manager, config, generators)
        self._platform: str = ""

    def execute(self) -> None:
        """Main dispatcher for the impact scenario lifecycle."""
        self._validate_state()
        self._platform = self.victim_host.os_family.strip().lower()
        
        log = logger.bind(
            technique="TA0040",
            host=self.victim_host.hostname,
            user=self.victim_user.name,
            platform=self._platform
        )
        log.info(f"Initiating Impact/Ransomware scenario on {self.victim_host.hostname}")

        if self._platform == "windows":
            self._execute_windows_sequence(self.generators["windows"])
        elif self._platform == "linux":
            self._execute_linux_sequence(self.generators["linux"])
        else:
            raise RuntimeError(f"Unsupported platform: {self._platform}")

        log.info("Impact scenario orchestration successfully completed.")

    def _validate_state(self) -> None:
        """Validates all actors and platform-specific generators are available."""
        if not self.victim_host or not self.victim_user or not self.attacker:
            raise RuntimeError("Impact scenario lacks required actor context.")
        
        platform = self.victim_host.os_family.strip().lower()
        if platform not in self.generators:
            raise RuntimeError(f"Required generator '{platform}' is missing for impact simulation.")

    def _execute_windows_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates the Windows ransomware timeline."""
        self._wait(*SHORT_DELAY)
        self.add_event(gen.generate_4624(self.victim_host, self.victim_user))
        
        self._win_inhibit_recovery(gen)
        self._win_disable_security(gen)
        self._win_encrypt_data(gen)
        self._win_display_note(gen)

    def _win_inhibit_recovery(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models recovery inhibition via vssadmin and wbadmin (T1490)."""
        logger.bind(technique="T1490", platform="windows").info("Inhibiting system recovery.")
        self._wait(*ACTION_DELAY)
        self._emit_win_proc(gen, "vssadmin.exe", VSSADMIN_EXE, "delete shadows /all /quiet")
        
        self._wait(*SHORT_DELAY)
        self._emit_win_proc(gen, "wbadmin.exe", WBADMIN_EXE, "delete catalog -quiet")

    def _win_disable_security(self, gen: BaseGenerator) -> None:
        """SOC Insight: Disabling Windows Defender via net stop and PowerShell (T1562.001)."""
        logger.bind(technique="T1562.001", platform="windows").info("Disabling security tools.")
        self._wait(*ACTION_DELAY)
        self._emit_win_proc(gen, "net.exe", NET_EXE, "stop WinDefend")
        
        self._wait(*SHORT_DELAY)
        self.add_event(gen.generate_4104(self.victim_host, self.victim_user, "Set-MpPreference -DisableRealtimeMonitoring $true"))

    def _win_encrypt_data(self, gen: BaseGenerator) -> None:
        """SOC Insight: Modeling data encryption for impact (T1486) via cipher and custom binary."""
        logger.bind(technique="T1486", platform="windows").info("Encrypting user data.")
        self._wait(*ACTION_DELAY)
        self._emit_win_proc(gen, "cipher.exe", CIPHER_EXE, "/w:C:")
        
        self._wait(*SHORT_DELAY)
        self._emit_win_proc(gen, "ransomware.exe", RANSOM_EXE, f"{RANSOM_EXE} --encrypt C:\\Users")

    def _win_display_note(self, gen: BaseGenerator) -> None:
        """SOC Insight: Final ransomware stage: displaying the ransom note via notepad."""
        self._wait(*ACTION_DELAY)
        self._emit_win_proc(gen, "notepad.exe", NOTEPAD_EXE, "notepad.exe C:\\READ_ME_NOW.txt")

    def _execute_linux_sequence(self, gen: BaseGenerator) -> None:
        """Orchestrates the Linux ransomware timeline."""
        self._wait(*SHORT_DELAY)
        src_ip = str(self._rng.choice(self.attacker.ip_pool))
        self.add_event(gen.generate_ssh_login(self.victim_host, self.victim_user, True, src_ip))
        
        self._nix_impact_lifecycle(gen)

    def _nix_impact_lifecycle(self, gen: BaseGenerator) -> None:
        """SOC Insight: Models the Linux impact killchain: stop service -> delete -> encrypt -> note."""
        logger.bind(technique="T1489", platform="linux").info("Inhibiting system services.")
        self._wait(*ACTION_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_STOP_SVC))
        
        logger.bind(technique="T1490", platform="linux").info("Deleting backup snapshots.")
        self._wait(*ACTION_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_RM_BACKUP))
        
        logger.bind(technique="T1486", platform="linux").info("Encrypting data via openssl.")
        self._wait(*ACTION_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_ENCRYPT))
        
        self._wait(*SHORT_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_RENAME))
        
        self._wait(*ACTION_DELAY)
        self.add_event(gen.generate_auditd_exec(self.victim_host, self.victim_user, NIX_NOTE))

    def _wait(self, min_s: float, max_s: float) -> None:
        """Applies a deterministic delay using the scenario's RNG."""
        self.advance_time(self._rng.uniform(min_s, max_s))

    def _emit_win_proc(self, gen: BaseGenerator, name: str, path: str, cmd: str) -> None:
        """Constructs and adds a Windows process creation event (4688)."""
        proc = Process(
            pid=self._rng.randint(1000, 9999),
            name=name,
            executable=path,
            command_line=cmd
        )
        self.add_event(gen.generate_4688(self.victim_host, self.victim_user, proc))