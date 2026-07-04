from enum import Enum

class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCReferenceType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    MUTEX = "mutex"
    CERTIFICATE_SERIAL = "certificate_serial"

class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MISSION_CRITICAL = "mission_critical"

class RuleStatus(str, Enum):
    EXPERIMENTAL = "experimental"
    TESTING = "testing"
    STABLE = "stable"
    DEPRECATED = "deprecated"

class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    AWS = "aws"
    AZURE = "azure"