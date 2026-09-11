"""
JOCKY Forensic Correlation Engine
Discovers and establishes validated, explainable relationships across heterogeneous
canonical evidence artifacts (Process <-> File <-> Network <-> Event <-> Registry).
Avoids naive/blind PID joins by enforcing host isolation and temporal constraints.
"""
from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional
import uuid

from analysis.models import EvidenceRelationship
from evidence.schema import CanonicalEvidenceItem, EvidenceType


class CorrelationEngine:
    """Correlates canonical evidence items into an explicit relationship graph."""

    def __init__(self, time_window_seconds: int = 300):
        self.time_window_seconds = time_window_seconds

    def correlate(self, items: List[CanonicalEvidenceItem]) -> List[EvidenceRelationship]:
        """Analyze a collection of canonical evidence items and extract all relationships."""
        relationships: List[EvidenceRelationship] = []

        # Group items by host to prevent cross-host PID confusion
        items_by_host: Dict[str, List[CanonicalEvidenceItem]] = {}
        for it in items:
            host_key = (it.host or "DEFAULT_HOST").upper()
            items_by_host.setdefault(host_key, []).append(it)

        for host, host_items in items_by_host.items():
            relationships.extend(self._correlate_host_items(host, host_items))

        return relationships

    def _correlate_host_items(self, host: str, items: List[CanonicalEvidenceItem]) -> List[EvidenceRelationship]:
        relationships: List[EvidenceRelationship] = []

        # Segregate by canonical type
        processes: List[CanonicalEvidenceItem] = []
        files: List[CanonicalEvidenceItem] = []
        network: List[CanonicalEvidenceItem] = []
        events: List[CanonicalEvidenceItem] = []
        registry: List[CanonicalEvidenceItem] = []

        for it in items:
            t = it.type.lower()
            if t == EvidenceType.PROCESS.value:
                processes.append(it)
            elif t == EvidenceType.FILE.value:
                files.append(it)
            elif t == EvidenceType.NETWORK.value:
                network.append(it)
            elif t == EvidenceType.EVENT.value:
                events.append(it)
            elif t == EvidenceType.REGISTRY.value:
                registry.append(it)

        # 1. Process -> Process (Parent-Child hierarchy)
        relationships.extend(self._correlate_parent_child(processes))

        # 2. Process -> File (Executable origin / binary resolution)
        relationships.extend(self._correlate_process_to_files(processes, files))

        # 3. Process -> Network (Socket ownership)
        relationships.extend(self._correlate_process_to_network(processes, network))

        # 4. Process -> Event (Security log activity)
        relationships.extend(self._correlate_process_to_events(processes, events))

        # 5. Registry -> File / Process (Persistence mechanisms)
        relationships.extend(self._correlate_registry_to_files_and_proc(registry, files, processes))

        return relationships

    def _correlate_parent_child(self, processes: List[CanonicalEvidenceItem]) -> List[EvidenceRelationship]:
        rel = []
        pid_map: Dict[int, CanonicalEvidenceItem] = {}
        for p in processes:
            pid = p.data.get("pid")
            if isinstance(pid, int):
                pid_map[pid] = p

        for child in processes:
            ppid = child.data.get("ppid")
            c_pid = child.data.get("pid")
            if isinstance(ppid, int) and ppid in pid_map and ppid != c_pid and ppid > 0:
                parent = pid_map[ppid]
                p_name = parent.data.get("name", "unknown")
                c_name = child.data.get("name", "unknown")

                # Verify temporal sanity if created_time available
                confidence = 0.95
                p_time = parent.data.get("created_time")
                c_time = child.data.get("created_time")
                if p_time and c_time and p_time > c_time:
                    # Parent started after child; likely PID reuse
                    confidence = 0.40

                rel.append(EvidenceRelationship(
                    source_evidence_id=parent.id,
                    target_evidence_id=child.id,
                    relationship_type="SPAWNED_CHILD",
                    confidence=confidence,
                    reason=f"Process '{p_name}' (PID {ppid}) spawned child '{c_name}' (PID {c_pid})",
                    metadata={"parent_pid": ppid, "child_pid": c_pid},
                ))
        return rel

    def _correlate_process_to_files(
        self,
        processes: List[CanonicalEvidenceItem],
        files: List[CanonicalEvidenceItem],
    ) -> List[EvidenceRelationship]:
        rel = []
        path_to_file: Dict[str, CanonicalEvidenceItem] = {}
        for f in files:
            p = f.data.get("path")
            if p:
                path_to_file[os.path.normpath(str(p)).lower()] = f

        for proc in processes:
            exe_path = proc.data.get("exe_path")
            if exe_path:
                normalized_exe = os.path.normpath(str(exe_path)).lower()
                if normalized_exe in path_to_file:
                    file_item = path_to_file[normalized_exe]
                    rel.append(EvidenceRelationship(
                        source_evidence_id=proc.id,
                        target_evidence_id=file_item.id,
                        relationship_type="EXECUTED_FROM_FILE",
                        confidence=1.0,
                        reason=f"Process '{proc.data.get('name')}' (PID {proc.data.get('pid')}) executed from filesystem binary '{exe_path}'",
                        metadata={"exe_path": exe_path, "file_size": file_item.data.get("size")},
                    ))
        return rel

    def _correlate_process_to_network(
        self,
        processes: List[CanonicalEvidenceItem],
        network: List[CanonicalEvidenceItem],
    ) -> List[EvidenceRelationship]:
        rel = []
        pid_map: Dict[int, CanonicalEvidenceItem] = {}
        for p in processes:
            pid = p.data.get("pid")
            if isinstance(pid, int):
                pid_map[pid] = p

        for net in network:
            n_pid = net.data.get("pid")
            if isinstance(n_pid, int) and n_pid in pid_map:
                proc = pid_map[n_pid]
                proto = net.data.get("protocol", "TCP")
                lip = net.data.get("local_ip", "0.0.0.0")
                lport = net.data.get("local_port", 0)
                rip = net.data.get("remote_ip", "0.0.0.0")
                rport = net.data.get("remote_port", 0)

                rel.append(EvidenceRelationship(
                    source_evidence_id=proc.id,
                    target_evidence_id=net.id,
                    relationship_type="OPENED_SOCKET",
                    confidence=0.95,
                    reason=f"Process '{proc.data.get('name')}' (PID {n_pid}) owns {proto} socket {lip}:{lport} -> {rip}:{rport}",
                    metadata={"pid": n_pid, "protocol": proto, "remote_ip": rip, "remote_port": rport},
                ))
        return rel

    def _correlate_process_to_events(
        self,
        processes: List[CanonicalEvidenceItem],
        events: List[CanonicalEvidenceItem],
    ) -> List[EvidenceRelationship]:
        rel = []
        pid_map: Dict[int, CanonicalEvidenceItem] = {
            p.data.get("pid"): p for p in processes if isinstance(p.data.get("pid"), int)
        }

        for ev in events:
            edata = ev.data.get("event_data", {})
            event_id = ev.data.get("event_id")

            # Match process creation (e.g. Windows 4688)
            new_pid = edata.get("NewProcessId") or edata.get("ProcessId")
            if isinstance(new_pid, str) and new_pid.startswith("0x"):
                try:
                    new_pid = int(new_pid, 16)
                except ValueError:
                    new_pid = None

            if isinstance(new_pid, int) and new_pid in pid_map:
                proc = pid_map[new_pid]
                rel.append(EvidenceRelationship(
                    source_evidence_id=proc.id,
                    target_evidence_id=ev.id,
                    relationship_type="RECORDED_BY_EVENT",
                    confidence=0.90,
                    reason=f"Process '{proc.data.get('name')}' (PID {new_pid}) recorded in Event {event_id}",
                    metadata={"event_id": event_id, "pid": new_pid},
                ))
        return rel

    def _correlate_registry_to_files_and_proc(
        self,
        registry: List[CanonicalEvidenceItem],
        files: List[CanonicalEvidenceItem],
        processes: List[CanonicalEvidenceItem],
    ) -> List[EvidenceRelationship]:
        rel = []
        path_to_file: Dict[str, CanonicalEvidenceItem] = {
            os.path.normpath(str(f.data.get("path"))).lower(): f
            for f in files if f.data.get("path")
        }

        for reg in registry:
            val_data = str(reg.data.get("value_data") or "")
            if not val_data:
                continue

            clean_val = val_data.strip("\"'").lower()
            for f_path, file_item in path_to_file.items():
                if f_path in clean_val:
                    rel.append(EvidenceRelationship(
                        source_evidence_id=reg.id,
                        target_evidence_id=file_item.id,
                        relationship_type="PERSISTED_IN_REGISTRY",
                        confidence=0.85,
                        reason=f"Registry key '{reg.data.get('key')}\\{reg.data.get('value_name')}' references file '{file_item.data.get('path')}'",
                        metadata={"key": reg.data.get("key"), "value_name": reg.data.get("value_name")},
                    ))
        return rel

