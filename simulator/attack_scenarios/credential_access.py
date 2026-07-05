from typing import Dict
# pyrefly: ignore [missing-import]
from loguru import logger

from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig
from simulator.generators.base import BaseGenerator

# --- Scenario Constants ---
WIN_CMD_PATH = "C:\\Windows\\System32\\cmd.exe"
WIN_PS_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
WIN_MIMIKATZ_PATH = "C:\\Temp\\mimikatz.exe"
WIN_MIMIKATZ_CMD = "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"
WIN_SAM_EXPORT_CMD = "reg save HKLM\\SAM C:\\windows\\temp\\sam.save"
WIN_PS_DISCOVERY = "Get-ChildItem C:\\Users\\ -Include *.txt,*.config -Recurse | Select-String 'pass'"

LINUX_BASH_PATH = "/bin/bash"
LINUX_SHADOW_CMD = "/usr/bin/cat /etc/shadow"
LINUX_GREP_CMD = "/usr/bin/grep -r 'password' /home/"
LINUX_FIND_SSH_CMD = "/usr/bin/find / -name 'id_rsa'"

# --- Timing Constants (Seconds) ---
DELAY_SHELL_MIN, DELAY_SHELL_MAX = 2.0, 5.0
DELAY_MIMIKATZ_MIN, DELAY_MIMIKATZ_MAX = 10.0, 25.0
DELAY_DISCOVERY_MIN, DELAY_DISCOVERY_MAX = 5.0, 12.0


class CredentialAccessScenario(ScenarioBase):
    """
    Simulates T1003 (OS Credential Dumping) and related harvesting techniques.
    Architecture: Decoupled attack phases dispatched by platform.
    """

    def __init__(
        self,
        entity_manager: EntityManager,
        config: SimulationConfig,
        generators: Dict[str, BaseGenerator]
    ):
        metadata = ScenarioMetadata(
            name="Advanced Credential Access and Harvesting",
            description="Multi-stage dumping of LSASS memory and sensitive credential file discovery.",
            mitre_tactics=["Credential Access", "Execution", "Discovery", "Defense Evasion"],
            mitre_techniques=["T1003.001", "T1003.008", "T1059.001", "T1552.001", "T1548.003"],
            supported_platforms=["windows", "linux"],
            version="1.1.0"
        )
        super().__init__(metadata, entity_manager, config, generators)

    def execute(self) -> None:
        """
        Main entry point. Validates state and dispatches to platform-specific sequences.
        Ensures execution logic stays under 40 lines.
        """
        self._validate_scenario_state()
        platform = self.victim_host.os_family.strip().lower()
        
        logger.info(f"Phase 1: Starting {self.metadata.name} on {self.victim_host.hostname}")

        if platform == "windows":
            self._execute_windows_sequence()
        elif platform == "linux":
            self._execute_linux_sequence()
        else:
            raise RuntimeError(f"Unsupported platform: {platform}")

        logger.info(f"Final Phase: {self.metadata.name} successfully concluded.")

    # --- Private Windows Sequence ---

    def _execute_windows_sequence(self) -> None:
        """Orchestrates the Windows credential dumping chain."""
        self._spawn_windows_shell()
        self._execute_mimikatz()
        self._export_sam_database()
        self._search_windows_credentials()

    def _spawn_windows_shell(self) -> None:
        """Spawns initial cmd.exe. Detectable via Event 4688 (Process Creation)."""
        logger.info("Phase 2: Establishing initial shell presence.")
        self.advance_time(self._rng.uniform(DELAY_SHELL_MIN, DELAY_SHELL_MAX))
        self._emit_win_process("cmd.exe", WIN_CMD_PATH, "cmd.exe")

    def _execute_mimikatz(self) -> None:
        """Runs Mimikatz. High-fidelity alert for LSASS memory access (T1003.001)."""
        logger.warning("Phase 3: Initiating memory-based credential dumping.")
        self.advance_time(self._rng.uniform(DELAY_MIMIKATZ_MIN, DELAY_MIMIKATZ_MAX))
        self._emit_win_process("mimikatz.exe", WIN_MIMIKATZ_PATH, WIN_MIMIKATZ_CMD)

    def _export_sam_database(self) -> None:
        """Exports SAM hive using reg.exe. Detectable via specific command line arguments."""
        logger.info("Phase 4: Exporting local SAM database for offline cracking.")
        self.advance_time(self._rng.uniform(DELAY_DISCOVERY_MIN, DELAY_DISCOVERY_MAX))
        self._emit_win_process("reg.exe", "C:\\Windows\\System32\\reg.exe", WIN_SAM_EXPORT_CMD)

    def _search_windows_credentials(self) -> None:
        """Uses PowerShell to find passwords in files. Detectable via Script Block (4104)."""
        logger.info("Phase 5: Conducting file-based credential discovery.")
        self.advance_time(self._rng.uniform(DELAY_DISCOVERY_MIN, DELAY_DISCOVERY_MAX))
        win_gen = self._windows_generator()
        self.add_event(win_gen.generate_4104(self.victim_host, self.victim_user, WIN_PS_DISCOVERY))

    # --- Private Linux Sequence ---

    def _execute_linux_sequence(self) -> None:
        """Orchestrates the Linux credential harvesting chain."""
        self._spawn_linux_shell()
        self._read_shadow_file()
        self._search_linux_credentials()
        self._locate_ssh_keys()

    def _spawn_linux_shell(self) -> None:
        """Executes /bin/bash. Detectable via auditd EXECVE or syslog."""
        logger.info("Phase 2: Opening interactive bash session.")
        self.advance_time(self._rng.uniform(DELAY_SHELL_MIN, DELAY_SHELL_MAX))
        nix_gen = self._linux_generator()
        self.add_event(nix_gen.generate_auditd_exec(self.victim_host, self.victim_user, LINUX_BASH_PATH))

    def _read_shadow_file(self) -> None:
        """Accesses /etc/shadow via sudo. Detectable via sudo logs or auditd syscalls."""
        logger.warning("Phase 3: Attempting to read protected password hashes.")
        self.advance_time(self._rng.uniform(DELAY_DISCOVERY_MIN, DELAY_DISCOVERY_MAX))
        nix_gen = self._linux_generator()
        self.add_event(nix_gen.generate_sudo(self.victim_host, self.victim_user, LINUX_SHADOW_CMD))

    def _search_linux_credentials(self) -> None:
        """Recursive grep for 'password'. Detectable via process execution Monitoring."""
        logger.info("Phase 4: Searching home directories for plaintext secrets.")
        self.advance_time(self._rng.uniform(DELAY_DISCOVERY_MIN, DELAY_DISCOVERY_MAX))
        nix_gen = self._linux_generator()
        self.add_event(nix_gen.generate_auditd_exec(self.victim_host, self.victim_user, LINUX_GREP_CMD))

    def _locate_ssh_keys(self) -> None:
        """Locates id_rsa files. Core indicator for T1552.004 (Private Keys)."""
        logger.info("Phase 5: Identifying private SSH keys for lateral movement.")
        self.advance_time(self._rng.uniform(DELAY_DISCOVERY_MIN, DELAY_DISCOVERY_MAX))
        nix_gen = self._linux_generator()
        self.add_event(nix_gen.generate_auditd_exec(self.victim_host, self.victim_user, LINUX_FIND_SSH_CMD))

    # --- Reusable Helpers ---

    def _windows_generator(self) -> BaseGenerator:
        return self.generators["windows"]

    def _linux_generator(self) -> BaseGenerator:
        return self.generators["linux"]

    def _emit_win_process(self, name: str, path: str, cmd: str) -> None:
        """Helper to create and emit a Windows process event (4688)."""
        win_gen = self._windows_generator()
        proc = Process(pid=self._rng.randint(1000, 9999), name=name, executable=path, command_line=cmd)
        self.add_event(win_gen.generate_4688(self.victim_host, self.victim_user, proc))

    def _validate_scenario_state(self) -> None:
        """Ensures all prerequisites for the simulation are met."""
        if not self.victim_host or not self.victim_user or not self.attacker:
            raise RuntimeError("Incomplete actor context for scenario.")
        
        if not self.attacker.ip_pool:
            raise RuntimeError(f"Attacker {self.attacker.name} lacks infrastructure (IP Pool).")
            
        platform = self.victim_host.os_family.strip().lower()
        required_gen = (
            "windows"
            if platform == "windows"
            else "linux"
        )
        if required_gen not in self.generators:
            raise RuntimeError(f"Required generator '{required_gen}' is missing.")