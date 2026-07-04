from shared.constants.enums import AssetCriticality

class Asset(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    hostname: str
    criticality: AssetCriticality
    environment: str = "Production"
    owner: str
    department: str
    operating_system: str
    ip_addresses: List[str] = Field(default_factory=list)
    is_isolated: bool = False

class UserIdentity(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    username: str
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    mfa_enabled: bool = False
    account_disabled: bool = False