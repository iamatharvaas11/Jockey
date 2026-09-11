"""
JOCKY Linux Platform Adapter
Implements the ForensicAdapter contract using Linux-compatible collectors.
Fixes legacy broken imports and guarantees safe execution on Ubuntu/WSL.
"""
import os
import platform
import socket
from typing import Any, Dict, List, Optional

from collectors.base import CollectorResult, CollectorStatus
from collectors.file_collector import FileCollector
from collectors.linux_collector import LinuxCollector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from runtime.adapters.base_adapter import ForensicAdapter

try:
    import pwd
except ImportError:
    pwd = None


class LinuxAdapter(ForensicAdapter):
    """Forensic adapter targeting Linux platforms (Ubuntu, Debian, WSL, CentOS/RHEL)."""

    def __init__(self):
        self.linux_collector = LinuxCollector()
        self.process_collector = ProcessCollector()
        self.file_collector = FileCollector()
        self.network_collector = NetworkCollector()

    def scan_processes(self, **kwargs) -> CollectorResult:
        # Prefer psutil process collector; fallback to /proc parser
        try:
            res = self.process_collector.collect(**kwargs)
            if res.data:
                return res
        except Exception:
            pass
        return self.linux_collector.collect_proc_processes()

    def scan_files(self, paths: Optional[List[str]] = None, **kwargs) -> CollectorResult:
        if not paths:
            paths = ["/tmp", "/var/tmp", "/dev/shm"]
        existing = [p for p in paths if os.path.exists(p)]
        return self.file_collector.collect(paths=existing if existing else paths, **kwargs)

    def scan_network(self, **kwargs) -> CollectorResult:
        try:
            res = self.network_collector.collect_connections(**kwargs)
            if res.status != CollectorStatus.FAILED:
                return res
        except Exception:
            pass
        return self.linux_collector.collect_proc_network()

    def scan_eventlogs(self, log_name: str = "auth.log", max_records: int = 50, **kwargs) -> CollectorResult:
        # On Linux, collect system authentication and audit logs
        return self.linux_collector.collect_auth_logs(max_lines=max_records)

    def scan_registry(self, **kwargs) -> CollectorResult:
        # Registry is strictly a Windows artifact
        return CollectorResult(
            type="registry",
            source="linux",
            status=CollectorStatus.UNSUPPORTED,
            data=[],
            limitations=["Windows Registry is not supported on Linux."],
        )

    def get_system_info(self) -> Dict[str, Any]:
        current_user = "unknown"
        if pwd:
            try:
                current_user = pwd.getpwuid(os.getuid())[0]
            except Exception:
                current_user = os.getenv("USER", "unknown")

        return {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "current_user": current_user,
            "adapter": "LinuxAdapter",
        }
