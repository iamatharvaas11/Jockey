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


def _safe_data(item: CanonicalEvidenceItem) -> Dict[str, Any]:
    return item.data if isinstance(item.data, dict) else {}


def _to_pid(val: Any) -> Optional[int]:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if val_str.isdigit():
            try:
                return int(val_str)
            except ValueError:
                return None
        elif val_str.startswith("0x") or val_str.startswith("0X"):
            try:
                return int(val_str, 16)
            except ValueError:
                return None
    return None


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
            t = (it.type or "").lower()
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
            p_data = _safe_data(p)
            pid = _to_pid(p_data.get("pid"))
            if pid is not None:
                pid_map[pid] = p

        for child in processes:
            c_data = _safe_data(child)
            ppid = _to_pid(c_data.get("ppid"))
            c_pid = _to_pid(c_data.get("pid"))
            if ppid is not None and ppid in pid_map and ppid != c_pid and ppid > 0:
                parent = pid_map[ppid]
                parent_data = _safe_data(parent)
                p_name = parent_data.get("name", "unknown")
                c_name = c_data.get("name", "unknown")

                confidence = 0.95
                p_time = parent_data.get("created_time")
                c_time = c_data.get("created_time")
                if p_time and c_time and str(p_time) > str(c_time):
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
            f_data = _safe_data(f)
            p = f_data.get("path")
            if p:
                path_to_file[os.path.normpath(str(p)).lower()] = f

        for proc in processes:
            proc_data = _safe_data(proc)
            exe_path = proc_data.get("exe_path")
            if exe_path:
                normalized_exe = os.path.normpath(str(exe_path)).lower()
                if normalized_exe in path_to_file:
                    file_item = path_to_file[normalized_exe]
                    rel.append(EvidenceRelationship(
                        source_evidence_id=proc.id,
                        target_evidence_id=file_item.id,
                        relationship_type="EXECUTED_FROM_FILE",
                        confidence=1.0,
                        reason=f"Process '{proc_data.get('name')}' (PID {proc_data.get('pid')}) executed from filesystem binary '{exe_path}'",
                        metadata={"exe_path": exe_path, "file_size": _safe_data(file_item).get("size")},
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
            pid = _to_pid(_safe_data(p).get("pid"))
            if pid is not None:
                pid_map[pid] = p

        for net in network:
            net_data = _safe_data(net)
            n_pid = _to_pid(net_data.get("pid"))
            if n_pid is not None and n_pid in pid_map:
                proc = pid_map[n_pid]
                proc_data = _safe_data(proc)
                proto = net_data.get("protocol", "TCP")
                lip = net_data.get("local_ip", "0.0.0.0")
                lport = net_data.get("local_port", 0)
                rip = net_data.get("remote_ip", "0.0.0.0")
                rport = net_data.get("remote_port", 0)

                rel.append(EvidenceRelationship(
                    source_evidence_id=proc.id,
                    target_evidence_id=net.id,
                    relationship_type="OPENED_SOCKET",
                    confidence=0.95,
                    reason=f"Process '{proc_data.get('name')}' (PID {n_pid}) owns {proto} socket {lip}:{lport} -> {rip}:{rport}",
                    metadata={"pid": n_pid, "protocol": proto, "remote_ip": rip, "remote_port": rport},
                ))
        return rel

    def _correlate_process_to_events(
        self,
        processes: List[CanonicalEvidenceItem],
        events: List[CanonicalEvidenceItem],
    ) -> List[EvidenceRelationship]:
        rel = []
        pid_map: Dict[int, CanonicalEvidenceItem] = {}
        for p in processes:
            pid = _to_pid(_safe_data(p).get("pid"))
            if pid is not None:
                pid_map[pid] = p

        for ev in events:
            ev_data = _safe_data(ev)
            edata = ev_data.get("event_data", {})
            if not isinstance(edata, dict):
                edata = {}
            event_id = ev_data.get("event_id")

            new_pid = _to_pid(edata.get("NewProcessId") or edata.get("ProcessId"))
            if new_pid is not None and new_pid in pid_map:
                proc = pid_map[new_pid]
                proc_data = _safe_data(proc)
                rel.append(EvidenceRelationship(
                    source_evidence_id=proc.id,
                    target_evidence_id=ev.id,
                    relationship_type="RECORDED_BY_EVENT",
                    confidence=0.90,
                    reason=f"Process '{proc_data.get('name')}' (PID {new_pid}) recorded in Event {event_id}",
                    metadata={"event_id": event_id, "pid": new_pid},
                ))
        return rel

    def _correlate_registry_to_files_and_proc(
        self,
        registry: List[CanonicalEvidenceItem],
        files: List[CanonicalEvidenceItem],
        processes: List[CanonicalEvidenceItem],
    ) -> List[EvidenceRelationship]:
        import re
        rel = []
        path_to_file: Dict[str, CanonicalEvidenceItem] = {}
        for f in files:
            f_data = _safe_data(f)
            p = f_data.get("path")
            if p:
                path_to_file[os.path.normpath(str(p)).lower()] = f

        for reg in registry:
            reg_data = _safe_data(reg)
            val_data = str(reg_data.get("value_data") or "")
            if not val_data:
                continue

            clean_val = val_data.strip("\"'").lower()
            for f_path, file_item in path_to_file.items():
                pattern = rf'(?:^|[\s"\'=,;])' + re.escape(f_path) + rf'(?:[\s"\'=,;/]|$)'
                if re.search(pattern, clean_val):
                    f_item_data = _safe_data(file_item)
                    rel.append(EvidenceRelationship(
                        source_evidence_id=reg.id,
                        target_evidence_id=file_item.id,
                        relationship_type="PERSISTED_IN_REGISTRY",
                        confidence=0.85,
                        reason=f"Registry key '{reg_data.get('key')}\\{reg_data.get('value_name')}' references file '{f_item_data.get('path')}'",
                        metadata={"key": reg_data.get("key"), "value_name": reg_data.get("value_name")},
                    ))
        return rel

