"""
JOCKY Canonical Evidence Model
Defines the standard canonical schema for all forensic evidence items
collected across Windows, Linux, and other host environments.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import socket
from typing import Any, Dict, List, Optional
import uuid


class EvidenceType(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    EVENT = "event"
    REGISTRY = "registry"
    GENERIC = "generic"


class EvidenceStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class CanonicalEvidenceItem:
    """
    Standardized, canonical evidence record for all forensic artifacts.
    Enforces required provenance metadata and deterministic representation for integrity.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host: str = field(default_factory=socket.gethostname)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    type: str = EvidenceType.GENERIC.value
    source: str = "unknown"
    collector: str = "unknown"
    status: str = EvidenceStatus.SUCCESS.value
    data: Dict[str, Any] = field(default_factory=dict)
    hash: Optional[str] = None
    limitations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self, include_hash: bool = True) -> Dict[str, Any]:
        """Convert evidence item to dictionary. If include_hash is False, omits hash for hashing."""
        d = {
            "id": self.id,
            "host": self.host,
            "timestamp": self.timestamp,
            "type": self.type,
            "source": self.source,
            "collector": self.collector,
            "status": self.status,
            "data": self.data,
            "limitations": self.limitations,
            "errors": self.errors,
        }
        if include_hash:
            d["hash"] = self.hash
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalEvidenceItem":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            host=data.get("host", socket.gethostname()),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            type=data.get("type", EvidenceType.GENERIC.value),
            source=data.get("source", "unknown"),
            collector=data.get("collector", "unknown"),
            status=data.get("status", EvidenceStatus.SUCCESS.value),
            data=data.get("data", {}),
            hash=data.get("hash"),
            limitations=data.get("limitations", []),
            errors=data.get("errors", []),
        )


# ============================================================================
# Strongly-Typed Canonical Entity Schemas
# ============================================================================

@dataclass
class ProcessEvidence:
    """Canonical process representation across Windows and Linux."""
    pid: int
    ppid: int
    name: str
    exe_path: Optional[str] = None
    exe_hash: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    created_time: Optional[str] = None
    status: str = "unknown"
    memory_bytes: Optional[int] = None
    threads: Optional[int] = None
    platform_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe_path": self.exe_path,
            "exe_hash": self.exe_hash,
            "cmdline": self.cmdline,
            "username": self.username,
            "created_time": self.created_time,
            "status": self.status,
            "memory_bytes": self.memory_bytes,
            "threads": self.threads,
            "platform_data": self.platform_data,
        }


@dataclass
class FileEvidence:
    """Canonical filesystem artifact representation."""
    path: str
    size: int
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    accessed_time: Optional[str] = None
    permissions: Optional[str] = None
    type: str = "file"
    sha256: Optional[str] = None
    md5: Optional[str] = None
    platform_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "accessed_time": self.accessed_time,
            "permissions": self.permissions,
            "type": self.type,
            "sha256": self.sha256,
            "md5": self.md5,
            "platform_data": self.platform_data,
        }


@dataclass
class NetworkEvidence:
    """Canonical network connection representation."""
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str = "UNKNOWN"
    pid: Optional[int] = None
    process_name: Optional[str] = None
    platform_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "status": self.status,
            "pid": self.pid,
            "process_name": self.process_name,
            "platform_data": self.platform_data,
        }


@dataclass
class EventEvidence:
    """Canonical system/audit event representation."""
    log_name: str
    event_id: int
    source: str
    time_created: str
    event_data: Dict[str, Any] = field(default_factory=dict)
    message: Optional[str] = None
    platform_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_name": self.log_name,
            "event_id": self.event_id,
            "source": self.source,
            "time_created": self.time_created,
            "event_data": self.event_data,
            "message": self.message,
            "platform_data": self.platform_data,
        }


@dataclass
class RegistryEvidence:
    """Canonical Windows registry autorun/service representation."""
    hive: str
    key: str
    value_name: str
    value_data: Optional[str] = None
    value_type: Optional[int] = None
    platform_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hive": self.hive,
            "key": self.key,
            "value_name": self.value_name,
            "value_data": self.value_data,
            "value_type": self.value_type,
            "platform_data": self.platform_data,
        }

