"""
JOCKY Linux Collector
Collects Linux forensic artifacts directly from pseudo-filesystems (/proc, /proc/net)
and system log files (/var/log/auth.log, /var/log/syslog, crontabs).
"""
import os
import sys
from typing import Dict, List, Optional

from .base import BaseCollector, CollectorResult, CollectorStatus


class LinuxCollector(BaseCollector):
    """Forensic artifact collector for Linux / Ubuntu / WSL environments."""

    def __init__(self):
        super().__init__(name="linux_collector")
        self.is_linux = sys.platform.startswith("linux")

    def collect(self, **kwargs) -> CollectorResult:
        """Default collection gathers processes via /proc."""
        return self.collect_proc_processes()

    def collect_proc_processes(self) -> CollectorResult:
        """Parse running process state directly from /proc."""
        if not self.is_linux:
            return CollectorResult(
                type="process",
                source=sys.platform,
                status=CollectorStatus.UNSUPPORTED,
                data=[],
                limitations=["Linux /proc process collection is only supported on Linux/WSL."],
            )

        processes = []
        errors = []
        limitations = []

        if not os.path.exists("/proc"):
            return CollectorResult(
                type="process",
                source="linux",
                status=CollectorStatus.FAILED,
                data=[],
                errors=["/proc filesystem is not mounted or accessible."],
            )

        try:
            entries = os.listdir("/proc")
        except Exception as e:
            return CollectorResult(
                type="process",
                source="linux",
                status=CollectorStatus.FAILED,
                data=[],
                errors=[f"Failed to list /proc: {str(e)}"],
            )

        for pid in entries:
            if not pid.isdigit():
                continue
            try:
                proc_stat_path = f"/proc/{pid}/stat"
                proc_cmdline_path = f"/proc/{pid}/cmdline"
                proc_exe_path = f"/proc/{pid}/exe"

                name = "unknown"
                ppid = 0
                status_char = "unknown"

                if os.path.exists(proc_stat_path):
                    with open(proc_stat_path, "r", encoding="utf-8", errors="ignore") as f:
                        stat_content = f.read()
                        # /proc/[pid]/stat format: pid (name) state ppid ...
                        parts = stat_content.split()
                        if len(parts) >= 4:
                            name = parts[1].strip("()")
                            status_char = parts[2]
                            ppid = int(parts[3]) if parts[3].isdigit() else 0

                cmdline = ""
                if os.path.exists(proc_cmdline_path):
                    with open(proc_cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                        cmdline = f.read().replace("\x00", " ").strip()

                exe_link = ""
                try:
                    if os.path.islink(proc_exe_path):
                        exe_link = os.readlink(proc_exe_path)
                except (PermissionError, OSError):
                    pass

                processes.append({
                    "pid": int(pid),
                    "ppid": ppid,
                    "name": name,
                    "exe_path": exe_link,
                    "status": status_char,
                    "cmdline": cmdline,
                })

            except (PermissionError, FileNotFoundError):
                # Process disappeared or requires root
                continue
            except Exception as e:
                errors.append(f"PID {pid}: {str(e)}")

        status = CollectorStatus.SUCCESS
        if errors and not processes:
            status = CollectorStatus.FAILED
        elif errors:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="process",
            source="linux_proc",
            status=status,
            data=processes,
            errors=errors,
            limitations=limitations,
        )

    def collect_proc_network(self) -> CollectorResult:
        """Parse active network connections from /proc/net/tcp and /proc/net/udp."""
        if not self.is_linux:
            return CollectorResult(
                type="network",
                source=sys.platform,
                status=CollectorStatus.UNSUPPORTED,
                data=[],
                limitations=["Linux /proc/net collection is only supported on Linux/WSL."],
            )

        connections = []
        errors = []
        limitations = []

        for proto in ["tcp", "udp"]:
            path = f"/proc/net/{proto}"
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        connections.append({
                            "protocol": proto.upper(),
                            "local_address": parts[1],
                            "remote_address": parts[2],
                            "status": parts[3],
                            "inode": parts[9],
                        })
            except (PermissionError, OSError) as e:
                errors.append(f"Cannot read {path}: {str(e)}")

        return CollectorResult(
            type="network",
            source="linux_proc_net",
            status=CollectorStatus.SUCCESS if not errors else CollectorStatus.PARTIAL,
            data=connections,
            errors=errors,
            limitations=limitations,
        )

    def collect_auth_logs(self, max_lines: int = 500) -> CollectorResult:
        """Collect authentication and system logs from /var/log/auth.log or /var/log/secure."""
        if not self.is_linux:
            return CollectorResult(
                type="eventlog",
                source=sys.platform,
                status=CollectorStatus.UNSUPPORTED,
                data=[],
                limitations=["Linux auth log collection is only supported on Linux/WSL."],
            )

        log_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages"]
        logs = []
        errors = []
        limitations = []
        target_path = None

        for p in log_paths:
            if os.path.exists(p):
                target_path = p
                break

        if not target_path:
            return CollectorResult(
                type="eventlog",
                source="linux_logs",
                status=CollectorStatus.FAILED,
                data=[],
                limitations=["No standard system auth logs found in /var/log."],
            )

        try:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
            for line in lines:
                logs.append({
                    "log_name": os.path.basename(target_path),
                    "message": line.strip(),
                })
        except PermissionError:
            limitations.append(f"Root privileges required to read {target_path}.")
            return CollectorResult(
                type="eventlog",
                source="linux_logs",
                status=CollectorStatus.FAILED,
                data=[],
                errors=[f"Permission denied reading {target_path}."],
                limitations=limitations,
            )
        except Exception as e:
            errors.append(f"Error reading {target_path}: {str(e)}")

        return CollectorResult(
            type="eventlog",
            source="linux_logs",
            status=CollectorStatus.SUCCESS if not errors else CollectorStatus.PARTIAL,
            data=logs,
            errors=errors,
            limitations=limitations,
        )
