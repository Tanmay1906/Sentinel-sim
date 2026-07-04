import random
import yaml
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Type, Union
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError

from shared.schemas.ecs.base import Host, User
from shared.constants.enums import AssetCriticality

# --- Simulation & Environment Orchestration Models ---

class SimulationConfig(BaseModel):
    """Metadata for the current execution run."""
    simulation_id: UUID = Field(default_factory=uuid4)
    scenario_id: str
    seed: int = 42
    replay_mode: bool = False
    start_time: datetime = Field(default_factory=datetime.now)
    timezone: str = "UTC"

class EnvironmentConfig(BaseModel):
    """Global network and organizational context."""
    domain_name: str
    org_name: str
    external_gateway: IPvAnyAddress
    dns_servers: List[IPvAnyAddress]
    network_zones: Dict[str, str]  # e.g., {"DMZ": "10.0.2.0/24"}

# --- Extended Entity Models ---

class HostConfig(Host):
    """Extended Host model with simulator-specific metadata."""
    criticality: AssetCriticality
    environment: Literal["production", "development", "staging", "lab"]
    business_owner: str
    department: str
    installed_software: List[str] = Field(default_factory=list)
    edr_enabled: bool = True
    av_enabled: bool = True
    tags: List[str] = Field(default_factory=list)

class UserConfig(User):
    """Extended User model with identity risk metadata."""
    department: str
    manager: Optional[str] = None
    privilege_level: Literal["standard", "elevated", "domain_admin", "service"]
    risk_score: int = Field(default=0, ge=0, le=100)
    mfa_enabled: bool = True
    account_disabled: bool = False
    last_login: Optional[datetime] = None

class AttackerConfig(BaseModel):
    """Behavioral and infrastructure profile of a threat actor."""
    name: str
    actor_type: Literal["apt", "insider", "script_kiddie", "cyber_criminal"]
    motivation: List[str] = Field(default_factory=list)
    skill_level: Literal["low", "medium", "high", "elite"]
    preferred_techniques: List[str] = Field(default_factory=list)  # MITRE IDs

    # Infrastructure Pool
    ip_pool: List[IPvAnyAddress]
    user_agent_pool: List[str]

# --- Entity Manager (The Loader) ---

class EntityManager:
    """
    Service responsible for loading and providing entities from YAML configurations.
    Implements validation logic to ensure the 'world' is consistent.
    """
    def __init__(self, config_path: Union[str, Path]):
        self.base_path = Path(config_path).expanduser().resolve()
        self._hosts: List[HostConfig] = []
        self._users: List[UserConfig] = []
        self._attackers: List[AttackerConfig] = []
        self._env: Optional[EnvironmentConfig] = None
        self.validation_errors: Dict[str, str] = {}

    @property
    def env(self) -> Optional[EnvironmentConfig]:
        return self._env.model_copy(deep=True) if self._env is not None else None

    @env.setter
    def env(self, value: Optional[EnvironmentConfig]) -> None:
        self._env = value

    @property
    def hosts(self) -> Tuple[HostConfig, ...]:
        return tuple(host.model_copy(deep=True) for host in self._hosts)

    @property
    def users(self) -> Tuple[UserConfig, ...]:
        return tuple(user.model_copy(deep=True) for user in self._users)

    @property
    def attackers(self) -> Tuple[AttackerConfig, ...]:
        return tuple(attacker.model_copy(deep=True) for attacker in self._attackers)

    def _load_yaml(self, filename: str) -> Any:
        file_path = self.base_path / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file {filename} missing at {file_path}")

        with open(file_path, "r", encoding="utf-8") as stream:
            try:
                return yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                raise ValueError(f"Malformed YAML in {filename}: {exc}") from exc

    def _load_and_validate_models(self, filename: str, model_cls: Type[BaseModel]) -> List[BaseModel]:
        data = self._load_yaml(filename)
        if not isinstance(data, list):
            raise ValueError(f"{filename} must contain a list of configuration objects")

        try:
            return [model_cls(**item) for item in data]
        except ValidationError as exc:
            raise ValueError(f"Invalid entries in {filename}: {exc}") from exc

    def load_all(self) -> None:
        """Loads all entities and validates schemas."""
        self.validation_errors.clear()
        self._env = None
        self._hosts = []
        self._users = []
        self._attackers = []

        try:
            env_data = self._load_yaml("environment.yaml")
            if not isinstance(env_data, dict):
                raise ValueError("environment.yaml must contain a mapping of configuration values")
            self._env = EnvironmentConfig(**env_data)
        except (TypeError, ValueError, ValidationError) as exc:
            self.validation_errors["environment.yaml"] = f"Unable to validate environment configuration: {exc}"
            raise ValueError(self.validation_errors["environment.yaml"]) from exc

        try:
            self._hosts = self._load_and_validate_models("hosts.yaml", HostConfig)
        except (TypeError, ValueError, ValidationError) as exc:
            self.validation_errors["hosts.yaml"] = f"Unable to validate host configuration: {exc}"
            raise ValueError(self.validation_errors["hosts.yaml"]) from exc

        try:
            self._users = self._load_and_validate_models("users.yaml", UserConfig)
        except (TypeError, ValueError, ValidationError) as exc:
            self.validation_errors["users.yaml"] = f"Unable to validate user configuration: {exc}"
            raise ValueError(self.validation_errors["users.yaml"]) from exc

        try:
            self._attackers = self._load_and_validate_models("attackers.yaml", AttackerConfig)
        except (TypeError, ValueError, ValidationError) as exc:
            self.validation_errors["attackers.yaml"] = f"Unable to validate attacker configuration: {exc}"
            raise ValueError(self.validation_errors["attackers.yaml"]) from exc

    def get_critical_hosts(self) -> List[HostConfig]:
        return [host.model_copy(deep=True) for host in self._hosts if host.criticality == AssetCriticality.MISSION_CRITICAL]

    def get_attacker_by_name(self, name: str) -> Optional[AttackerConfig]:
        attacker = next((a for a in self._attackers if a.name == name), None)
        return attacker.model_copy(deep=True) if attacker is not None else None

    def get_random_standard_user(self, seed: int) -> UserConfig:
        rng = random.Random(seed)
        standard_users = [user for user in self._users if user.privilege_level == "standard"]
        if not standard_users:
            raise ValueError("No standard users are configured")
        return rng.choice(standard_users).model_copy(deep=True)
    
    def select_attacker(self, rng: random.Random) -> AttackerConfig:
        """
        Deterministically selects a threat actor using the supplied RNG.
        """
        if not self._attackers:
            raise RuntimeError("No attackers loaded in EntityManager.")

        return rng.choice(self._attackers)


    def select_random_host(self, rng: random.Random) -> HostConfig:
        """
        Deterministically selects a host using the supplied RNG.
        """
        if not self._hosts:
            raise RuntimeError("No hosts loaded in EntityManager.")

        return rng.choice(self._hosts)


    def select_user_by_host(
        self,
        host: HostConfig,
        rng: random.Random,
    ) -> UserConfig:
        """
        Deterministically selects a user for a target host.

        Future versions can map users to assets. For now, a deterministic
        random user keeps replay behaviour stable.
        """
        if not self._users:
            raise RuntimeError("No users loaded in EntityManager.")

        return rng.choice(self._users)