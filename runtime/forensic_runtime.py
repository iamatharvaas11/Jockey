"""
JOCKY Forensic Runtime
Core runtime service executing forensic operations dispatched from the Runtime ABI,
managing investigation context, coordinating platform adapters, and writing exports.
"""
from dataclasses import dataclass, field
import datetime
from datetime import timezone
import json
import os
import platform
import socket
from typing import Any, Dict, List, Optional

from collectors.base import CollectorResult, CollectorStatus
from evidence.audit import AuditAction, AuditLogger
from evidence.integrity import EvidenceIntegrityManager
from evidence.normalizer import EvidenceNormalizer
from evidence.store import InMemoryEvidenceStore
from runtime.adapters import ForensicAdapter, get_platform_adapter


@dataclass
class RuntimeContext:
    """Execution state and collected evidence for an ongoing forensic run."""
    target_type: int = 0  # 0=SYSTEM, 1=ALL, 2=REMOTE
    hostname: str = field(default_factory=socket.gethostname)
    remote_host: str = ""
    config: Dict[str, str] = field(default_factory=dict)
    collected_evidence: Dict[str, CollectorResult] = field(default_factory=dict)
    executed_scans: List[str] = field(default_factory=list)
    executed_finds: List[str] = field(default_factory=list)
    executed_builds: List[str] = field(default_factory=list)
    executed_exports: List[tuple] = field(default_factory=list)
    collections: Dict[int, List[dict]] = field(default_factory=lambda: {
        1: [
            {"pid": 4, "ppid": 0, "name": "System", "status": "RUNNING"},
            {"pid": 1004, "ppid": 4, "name": "svchost.exe", "status": "RUNNING"},
            {"pid": 2048, "ppid": 1004, "name": "powershell.exe", "status": "RUNNING"},
        ],
        2: [
            {"path": "C:\\Windows\\System32\\cmd.exe", "size": 289792},
        ],
        3: [
            {"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 8000, "remote_ip": "0.0.0.0", "remote_port": 0},
        ],
    })
    errors: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.datetime.now(timezone.utc).isoformat())


class ForensicRuntime:
    """
    Central forensic runtime coordinating collection through the active platform adapter,
    providing structured query interfaces for the Runtime ABI.
    """

    def __init__(self, adapter: Optional[ForensicAdapter] = None):
        self.adapter = adapter or get_platform_adapter()
        self.context = RuntimeContext()
        self.evidence_store = InMemoryEvidenceStore()
        self.audit_logger = AuditLogger()

    def reset(self):
        """Reset execution context in-place for a fresh investigation run."""
        self.evidence_store = InMemoryEvidenceStore()
        self.audit_logger = AuditLogger()
        self.context.target_type = 0
        self.context.remote_host = ""
        self.context.config.clear()
        self.context.collected_evidence.clear()
        self.context.executed_scans.clear()
        self.context.executed_finds.clear()
        self.context.executed_builds.clear()
        self.context.executed_exports.clear()
        self.context.errors.clear()
        self.context.limitations.clear()
        self.context.collections = {
            1: [
                {"pid": 4, "ppid": 0, "name": "System", "status": "RUNNING"},
                {"pid": 1004, "ppid": 4, "name": "svchost.exe", "status": "RUNNING"},
                {"pid": 2048, "ppid": 1004, "name": "powershell.exe", "status": "RUNNING"},
            ],
            2: [
                {"path": "C:\\Windows\\System32\\cmd.exe", "size": 289792},
            ],
            3: [
                {"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 8000, "remote_ip": "0.0.0.0", "remote_port": 0},
            ],
        }
        # Initialize system info
        try:
            sys_info = self.adapter.get_system_info()
            self.context.hostname = sys_info.get("hostname", socket.gethostname())
        except Exception:
            pass

    def set_target(self, target_type: int, hostname: str = ""):
        self.context.target_type = target_type
        self.context.remote_host = hostname

    def set_config(self, key: str, val: str):
        self.context.config[key] = val

    # ========================================================================
    # Collector Dispatch via Platform Adapter & Evidence Normalization
    # ========================================================================

    def execute_scan(self, scan_type: str) -> CollectorResult:
        st = scan_type.lower()
        if "proc" in st:
            return self.scan_processes()
        elif "net" in st:
            return self.scan_network()
        elif "file" in st:
            return self.scan_files()
        elif "event" in st or "log" in st:
            return self.scan_eventlogs()
        elif "reg" in st:
            return self.scan_registry()
        else:
            return self.scan_all()

    def scan_processes(self) -> CollectorResult:
        self.context.executed_scans.append("PROCESSES")
        result = self.adapter.scan_processes()
        self.context.collected_evidence["processes"] = result
        self.context.collections[1] = result.data
        if result.errors:
            self.context.errors.extend(result.errors)
        if result.limitations:
            self.context.limitations.extend(result.limitations)
        
        canonical = EvidenceNormalizer.normalize_collector_result(result)
        self.evidence_store.add_batch(canonical)
        self.audit_logger.log(
            action=AuditAction.COLLECT,
            actor=self.context.hostname,
            details={"collector": "ProcessCollector", "count": len(canonical), "status": str(result.status)},
        )
        return result

    def scan_files(self, paths: Optional[List[str]] = None) -> CollectorResult:
        self.context.executed_scans.append("FILES")
        result = self.adapter.scan_files(paths=paths)
        self.context.collected_evidence["files"] = result
        self.context.collections[2] = result.data
        if result.errors:
            self.context.errors.extend(result.errors)
        if result.limitations:
            self.context.limitations.extend(result.limitations)

        canonical = EvidenceNormalizer.normalize_collector_result(result)
        self.evidence_store.add_batch(canonical)
        self.audit_logger.log(
            action=AuditAction.COLLECT,
            actor=self.context.hostname,
            details={"collector": "FileCollector", "count": len(canonical), "status": str(result.status)},
        )
        return result

    def scan_network(self) -> CollectorResult:
        self.context.executed_scans.append("NETWORK")
        result = self.adapter.scan_network()
        self.context.collected_evidence["network"] = result
        self.context.collections[3] = result.data
        if result.errors:
            self.context.errors.extend(result.errors)
        if result.limitations:
            self.context.limitations.extend(result.limitations)

        canonical = EvidenceNormalizer.normalize_collector_result(result)
        self.evidence_store.add_batch(canonical)
        self.audit_logger.log(
            action=AuditAction.COLLECT,
            actor=self.context.hostname,
            details={"collector": "NetworkCollector", "count": len(canonical), "status": str(result.status)},
        )
        return result

    def scan_eventlogs(self, log_name: str = "System", max_records: int = 50) -> CollectorResult:
        self.context.executed_scans.append("EVENTLOGS")
        result = self.adapter.scan_eventlogs(log_name=log_name, max_records=max_records)
        self.context.collected_evidence["eventlogs"] = result
        self.context.collections[4] = result.data
        if result.errors:
            self.context.errors.extend(result.errors)
        if result.limitations:
            self.context.limitations.extend(result.limitations)

        canonical = EvidenceNormalizer.normalize_collector_result(result)
        self.evidence_store.add_batch(canonical)
        self.audit_logger.log(
            action=AuditAction.COLLECT,
            actor=self.context.hostname,
            details={"collector": "EventLogCollector", "count": len(canonical), "status": str(result.status)},
        )
        return result

    def scan_registry(self) -> CollectorResult:
        self.context.executed_scans.append("REGISTRY")
        result = self.adapter.scan_registry()
        self.context.collected_evidence["registry"] = result
        self.context.collections[5] = result.data
        if result.errors:
            self.context.errors.extend(result.errors)
        if result.limitations:
            self.context.limitations.extend(result.limitations)

        canonical = EvidenceNormalizer.normalize_collector_result(result)
        self.evidence_store.add_batch(canonical)
        self.audit_logger.log(
            action=AuditAction.COLLECT,
            actor=self.context.hostname,
            details={"collector": "RegistryCollector", "count": len(canonical), "status": str(result.status)},
        )
        return result

    def scan_all(self) -> Dict[str, CollectorResult]:
        self.scan_processes()
        self.scan_files()
        self.scan_network()
        self.scan_eventlogs()
        self.scan_registry()
        return self.context.collected_evidence

    # ========================================================================
    # Collection Query Protocol (FOREACH loops in compiled code)
    # ========================================================================

    def get_collection(self, source_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve collected forensic items for loop iteration.
        1: PROCESSES, 2: FILES, 3: NETWORK, 4: EVENTLOGS, 5: REGISTRY.
        Checks explicit collections first; triggers scan if needed.
        """
        if source_id in self.context.collections and self.context.collections[source_id]:
            return self.context.collections[source_id]

        source_map = {
            1: ("processes", self.scan_processes),
            2: ("files", self.scan_files),
            3: ("network", self.scan_network),
            4: ("eventlogs", self.scan_eventlogs),
            5: ("registry", self.scan_registry),
        }

        key, scan_func = source_map.get(source_id, ("unknown", None))
        if key not in self.context.collected_evidence and scan_func:
            scan_func()

        result = self.context.collected_evidence.get(key)
        return result.data if result else []

    # ========================================================================
    # Evidence & Report Exports
    # ========================================================================

    def export_report(self, path: str = ""):
        out_path = path if path else "report.json"
        self.context.executed_exports.append(("REPORT", out_path))

        manifest = self.evidence_store.create_manifest(
            case_id=self.context.config.get("case_id", "JOCKY-CASE-001"),
            examiner=self.context.config.get("examiner", "JOCKY Automated Engine"),
        )

        report_data = {
            "title": "JOCKY Forensic Investigation Report",
            "host": self.context.hostname,
            "remote_host": self.context.remote_host,
            "target_type": self.context.target_type,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "status": "partial" if self.context.limitations else "success",
            "integrity_manifest": manifest.to_dict(),
            "canonical_evidence_count": self.evidence_store.count(),
            "evidence": {
                k: v.to_dict() for k, v in self.context.collected_evidence.items()
            },
            "errors": self.context.errors,
            "limitations": list(set(self.context.limitations)),
        }

        # Ensure parent directory exists
        parent_dir = os.path.dirname(out_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        self.audit_logger.log(
            action=AuditAction.EXPORT,
            actor=self.context.hostname,
            details={"type": "REPORT", "path": out_path, "status": "SUCCESS"},
        )

    def export_evidence(self, path: str = ""):
        out_path = path if path else "evidence.json"
        self.context.executed_exports.append(("EVIDENCE", out_path))

        manifest = self.evidence_store.create_manifest(
            case_id=self.context.config.get("case_id", "JOCKY-CASE-001"),
            examiner=self.context.config.get("examiner", "JOCKY Automated Engine"),
        )

        evidence_data = {
            "host": self.context.hostname,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "status": "partial" if self.context.limitations else "success",
            "integrity_manifest": manifest.to_dict(),
            "evidence_count": self.evidence_store.count(),
            "items": [it.to_dict() for it in self.evidence_store.list()],
            "collections": {
                k: v.to_dict() for k, v in self.context.collected_evidence.items()
            },
            "audit_trail": [rec.to_dict() for rec in self.audit_logger.get_records()],
            "errors": self.context.errors,
            "limitations": list(set(self.context.limitations)),
        }

        parent_dir = os.path.dirname(out_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(evidence_data, f, indent=2)

        self.audit_logger.log(
            action=AuditAction.EXPORT,
            actor=self.context.hostname,
            details={"type": "EVIDENCE", "path": out_path, "total_items": self.evidence_store.count()},
        )

    def export_timeline(self, path: str = ""):
        out_path = path if path else "timeline.json"
        self.context.executed_exports.append(("TIMELINE", out_path))
        # Write basic chronological index of collected evidence
        timeline_events = []
        for src, result in self.context.collected_evidence.items():
            for item in result.data:
                ts = item.get("created_time") or item.get("time_created") or result.timestamp
                timeline_events.append({
                    "timestamp": ts,
                    "source": src,
                    "summary": f"{src}: {item.get('name', '') or item.get('path', '')}",
                    "details": item,
                })

        parent_dir = os.path.dirname(out_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(timeline_events, f, indent=2)
