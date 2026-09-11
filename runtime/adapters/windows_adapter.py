"""
JOCKY Windows Platform Adapter
Implements the ForensicAdapter contract using Windows-native collectors.
"""
import os
import platform
import socket
from typing import Any, Dict, List, Optional

from collectors.base import CollectorResult, CollectorStatus
from collectors.eventlog_collector import EventLogCollector
from collectors.file_collector import FileCollector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from collectors.registry_collector import RegistryCollector
from runtime.adapters.base_adapter import ForensicAdapter


class WindowsAdapter(ForensicAdapter):
    """Forensic adapter targeting Windows platforms (NT/Win32/Win64)."""

    def __init__(self):
        self.process_collector = ProcessCollector()
        self.file_collector = FileCollector()
        self.network_collector = NetworkCollector()
        self.eventlog_collector = EventLogCollector()
        self.registry_collector = RegistryCollector()

    def scan_processes(self, **kwargs) -> CollectorResult:
        return self.process_collector.collect(**kwargs)

    def scan_files(self, paths: Optional[List[str]] = None, **kwargs) -> CollectorResult:
        if not paths:
            paths = [
                os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "AppData", "Local", "Temp"),
                "C:\\Windows\\Temp",
            ]
        return self.file_collector.collect(paths=paths, **kwargs)

    def scan_network(self, **kwargs) -> CollectorResult:
        return self.network_collector.collect_connections(**kwargs)

    def scan_eventlogs(self, log_name: str = "System", max_records: int = 50, **kwargs) -> CollectorResult:
        return self.eventlog_collector.collect(log_name=log_name, max_records=max_records, **kwargs)

    def scan_registry(self, **kwargs) -> CollectorResult:
        return self.registry_collector.collect_run_keys()

    def get_system_info(self) -> Dict[str, Any]:
        try:
            user = os.getlogin()
        except Exception:
            user = os.environ.get("USERNAME", "unknown")

        return {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "current_user": user,
            "adapter": "WindowsAdapter",
        }
