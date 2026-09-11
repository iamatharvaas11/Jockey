"""
JOCKY Forensic Collector Contract
Defines the common normalized data structures and base interface for all forensic collectors.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import socket
from typing import Any, Dict, List, Optional


class CollectorStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class CollectionError:
    """Structured error information reported by a collector."""
    collector: str
    message: str
    code: str = "ERR_COLLECTION_FAILED"
    recoverable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector": self.collector,
            "message": self.message,
            "code": self.code,
            "recoverable": self.recoverable,
        }


@dataclass
class EvidenceItem:
    """A single normalized forensic evidence record."""
    type: str
    data: Dict[str, Any]
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "timestamp": self.timestamp,
            "source": self.source,
            "data": self.data,
            "limitations": self.limitations,
        }


class CollectorResult(list):
    """
    Standardized, normalized result envelope returned by every forensic collector.
    Subclasses list for complete backward compatibility with list consumers,
    while carrying rich provenance metadata (host, timestamp, status, errors, limitations).
    """

    def __init__(
        self,
        data: Optional[List[Dict[str, Any]]] = None,
        host: Optional[str] = None,
        timestamp: Optional[str] = None,
        type: str = "generic",
        source: str = "unknown",
        status: CollectorStatus = CollectorStatus.SUCCESS,
        errors: Optional[List[str]] = None,
        limitations: Optional[List[str]] = None,
    ):
        super().__init__(data or [])
        self.host = host or socket.gethostname()
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.type = type
        self.source = source
        self.status = status
        self.errors = errors if errors is not None else []
        self.limitations = limitations if limitations is not None else []

    @property
    def data(self) -> List[Dict[str, Any]]:
        return list(self)

    @data.setter
    def data(self, val: List[Dict[str, Any]]):
        self.clear()
        self.extend(val)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "timestamp": self.timestamp,
            "type": self.type,
            "source": self.source,
            "status": self.status.value if isinstance(self.status, CollectorStatus) else str(self.status),
            "count": len(self),
            "data": list(self),
            "errors": self.errors,
            "limitations": self.limitations,
        }


class BaseCollector(ABC):
    """Abstract base class for all JOCKY forensic collectors."""

    def __init__(self, name: str = "base_collector"):
        self.name = name

    @abstractmethod
    def collect(self, **kwargs) -> CollectorResult:
        """
        Execute collection and return a standardized CollectorResult.
        Must not raise unhandled exceptions that terminate execution.
        """
        pass
