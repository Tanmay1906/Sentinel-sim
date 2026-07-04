from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, IPvAnyAddress

class ECSBase(BaseModel):
    model_config = {"extra": "allow"}

class Host(ECSBase):
    hostname: str
    ip: Optional[List[IPvAnyAddress]] = Field(default_factory=list)
    id: Optional[str] = None
    os_family: Optional[str] = None
    os_name: Optional[str] = None
    architecture: Optional[str] = None

class User(ECSBase):
    name: str
    id: Optional[str] = None
    domain: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    email: Optional[str] = None

class Process(ECSBase):
    pid: int
    name: str
    executable: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    hash_sha256: Optional[str] = None

class Network(ECSBase):
    protocol: str = "tcp"
    source_ip: IPvAnyAddress
    source_port: int
    destination_ip: IPvAnyAddress
    destination_port: int
    bytes_sent: Optional[int] = None

class File(ECSBase):
    path: str
    name: str
    extension: Optional[str] = None
    size: Optional[int] = None
    hash_sha256: Optional[str] = None