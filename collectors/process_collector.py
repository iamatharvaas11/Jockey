"""
JOCKY Process Collector
Collects running processes, executable hashes, parent-child relationships,
and metadata with resilient error handling for protected/terminated processes.
"""
import ctypes
import datetime
from datetime import timezone
import hashlib
import os
import sys
from typing import Dict, List, Optional

import psutil

from .base import BaseCollector, CollectorResult, CollectorStatus

_EXE_HASH_CACHE: Dict[str, str] = {}


class ProcessCollector(BaseCollector):
    """Forensic process collector extracting process metadata, trees, and executable hashes."""

    def __init__(self):
        super().__init__(name="process_collector")
        self.cache = _EXE_HASH_CACHE

    def _hash_file(self, filepath: str) -> str:
        if not filepath:
            return ""
        if filepath in self.cache:
            return self.cache[filepath]

        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                # 64KB fast header fingerprinting for instant triage
                chunk = f.read(65536)
                if chunk:
                    sha256.update(chunk)
            h = sha256.hexdigest()
            self.cache[filepath] = h
            return h
        except (PermissionError, FileNotFoundError, OSError):
            self.cache[filepath] = ""
            return ""

    def _get_ppid_map_win32(self) -> Dict[int, int]:
        """Fast Windows ToolHelp32 Snapshot to get all PPIDs rapidly."""
        if sys.platform != "win32":
            return {}
        try:
            from ctypes import wintypes

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            h = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            if h == -1 or not h:
                return {}
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            ppid_map = {}
            if ctypes.windll.kernel32.Process32First(h, ctypes.byref(entry)):
                while True:
                    ppid_map[entry.th32ProcessID] = entry.th32ParentProcessID
                    if not ctypes.windll.kernel32.Process32Next(h, ctypes.byref(entry)):
                        break
            ctypes.windll.kernel32.CloseHandle(h)
            return ppid_map
        except Exception:
            return {}

    def collect(self, **kwargs) -> CollectorResult:
        """
        Collect process list with metadata.
        Returns a normalized CollectorResult envelope.
        """
        processes = []
        errors = []
        limitations = []
        access_denied_count = 0

        ppid_map = self._get_ppid_map_win32() if sys.platform == "win32" else {}

        # Non-blocking attributes
        attrs = ["pid", "name", "exe", "cmdline", "status", "create_time"]

        for proc in psutil.process_iter(attrs):
            try:
                pinfo = proc.info
                pid = pinfo.get("pid")
                if pid is None:
                    continue

                # Process identity
                name = pinfo.get("name") or ""
                exe_path = pinfo.get("exe") or ""
                exe_hash = self._hash_file(exe_path) if exe_path else ""

                cmdline_parts = pinfo.get("cmdline") or []
                cmdline_str = " ".join(cmdline_parts) if cmdline_parts else ""

                # PPID resolution
                ppid = ppid_map.get(pid)
                if ppid is None:
                    try:
                        ppid = proc.ppid()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        ppid = 0

                # User resolution
                username = ""
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    access_denied_count += 1
                    if pid == 0:
                        username = "SYSTEM" if sys.platform == "win32" else "root"
                    elif pid == 4 and sys.platform == "win32":
                        username = "NT AUTHORITY\\SYSTEM"
                    else:
                        username = "UNKNOWN"

                # Start time
                create_time_raw = pinfo.get("create_time")
                created_time_str = ""
                if create_time_raw:
                    try:
                        created_time_str = datetime.datetime.fromtimestamp(
                            create_time_raw, timezone.utc
                        ).isoformat()
                    except Exception:
                        pass

                # Memory
                memory_bytes = 0
                try:
                    memory_bytes = proc.memory_info().rss
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Threads
                threads = 0
                try:
                    threads = proc.num_threads()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                processes.append({
                    "pid": pid,
                    "ppid": ppid or 0,
                    "name": name,
                    "exe_path": exe_path,
                    "exe_hash": exe_hash,
                    "cmdline": cmdline_str,
                    "username": username,
                    "status": pinfo.get("status") or "unknown",
                    "created_time": created_time_str,
                    "threads": threads,
                    "memory_bytes": memory_bytes,
                })

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                # Process terminated while iterating
                continue
            except psutil.AccessDenied:
                access_denied_count += 1
                continue
            except Exception as e:
                errors.append(f"PID {getattr(proc, 'pid', 'unknown')}: {str(e)}")

        if access_denied_count > 0:
            limitations.append(
                f"Elevated privileges required: Access was denied for {access_denied_count} protected process attributes."
            )

        status = CollectorStatus.SUCCESS
        if errors and not processes:
            status = CollectorStatus.FAILED
        elif errors or limitations:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="process",
            source=sys.platform,
            status=status,
            data=processes,
            errors=errors,
            limitations=limitations,
        )

    def collect_modules(self, pid: int) -> List[dict]:
        """Collect DLLs or shared libraries mapped by a process."""
        modules = []
        try:
            proc = psutil.Process(pid)
            for m in proc.memory_maps():
                modules.append({
                    "path": m.path,
                    "rss": getattr(m, "rss", 0),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError, NotImplementedError):
            pass
        return modules

    def build_process_tree(self, processes: List[dict]) -> dict:
        """Build hierarchical parent-child process tree."""
        nodes = {}
        for p in processes:
            pid = p["pid"]
            nodes[pid] = {
                "pid": pid,
                "ppid": p.get("ppid", 0),
                "name": p.get("name", ""),
                "exe": p.get("exe_path", ""),
                "children": [],
            }

        root_nodes = {}

        def has_cycle(start_pid: int, target_pid: int) -> bool:
            curr = target_pid
            visited = set()
            while curr in nodes and curr not in visited:
                if curr == start_pid:
                    return True
                visited.add(curr)
                curr = nodes[curr]["ppid"]
            return False

        for pid, node in nodes.items():
            ppid = node["ppid"]
            if ppid in nodes and ppid != pid and not has_cycle(pid, ppid):
                nodes[ppid]["children"].append(node)
            else:
                root_nodes[pid] = node

        return root_nodes
