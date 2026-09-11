"""
JOCKY Base Platform Adapter
Defines the standard abstraction interface implemented by OS-specific forensic adapters.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from collectors.base import CollectorResult


class ForensicAdapter(ABC):
    """Abstract interface bridging runtime execution to OS-specific collectors."""

    @abstractmethod
    def scan_processes(self, **kwargs) -> CollectorResult:
        """Scan active processes on the host system."""
        pass

    @abstractmethod
    def scan_files(self, paths: Optional[List[str]] = None, **kwargs) -> CollectorResult:
        """Scan target filesystem paths for forensic artifacts."""
        pass

    @abstractmethod
    def scan_network(self, **kwargs) -> CollectorResult:
        """Scan active network sockets and connections."""
        pass

    @abstractmethod
    def scan_eventlogs(self, log_name: str = "System", max_records: int = 50, **kwargs) -> CollectorResult:
        """Scan system event / audit logs."""
        pass

    @abstractmethod
    def scan_registry(self, **kwargs) -> CollectorResult:
        """Scan system configuration / registry autoruns where supported."""
        pass

    @abstractmethod
    def get_system_info(self) -> Dict[str, Any]:
        """Collect host system identifying information."""
        pass
