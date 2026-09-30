
"""
JOCKY Forensic Timeline Engine
Normalizes heterogeneous canonical evidence (process, file, network, event, registry)
into a unified, chronologically sorted super-timeline.
Preserves missing/estimated timestamps explicitly without silently dropping evidence.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from analysis.models import TimelineEvent
from evidence.schema import CanonicalEvidenceItem, EvidenceType


class TimelineEngine:
    """Constructs a unified chronological timeline from canonical forensic evidence."""

    def build_timeline(self, items: List[CanonicalEvidenceItem]) -> List[TimelineEvent]:
        """Convert canonical evidence items into a sorted List of TimelineEvents."""
        timeline_events: List[TimelineEvent] = []

        for item in items:
            t = (item.type or "").lower()
            data = item.data if isinstance(item.data, dict) else {}

            if t == EvidenceType.PROCESS.value:
                timeline_events.extend(self._process_to_timeline(item, data))
            elif t == EvidenceType.FILE.value:
                timeline_events.extend(self._file_to_timeline(item, data))
            elif t == EvidenceType.NETWORK.value:
                timeline_events.extend(self._network_to_timeline(item, data))
            elif t == EvidenceType.EVENT.value:
                timeline_events.extend(self._event_to_timeline(item, data))
            elif t == EvidenceType.REGISTRY.value:
                timeline_events.extend(self._registry_to_timeline(item, data))
            else:
                timeline_events.append(TimelineEvent(
                    timestamp=item.timestamp,
                    host=item.host,
                    type="GENERIC_ARTIFACT",
                    source=item.source,
                    summary=f"Evidence artifact collected: {item.source}",
                    evidence_id=item.id,
                    details=data,
                    is_timestamp_estimated=False,
                ))

        # Sort chronologically
        timeline_events.sort(key=self._sort_key)
        return timeline_events

    def _process_to_timeline(self, item: CanonicalEvidenceItem, data: Dict[str, Any]) -> List[TimelineEvent]:
        events = []
        name = data.get("name", "unknown")
        pid = data.get("pid", 0)
        cmdline = data.get("cmdline") or ""
        ts = data.get("created_time")
        is_estimated = False

        if not ts:
            ts = item.timestamp
            is_estimated = True

        events.append(TimelineEvent(
            timestamp=ts,
            host=item.host,
            type="PROCESS_START",
            source="process",
            summary=f"Process Started: '{name}' (PID {pid})",
            evidence_id=item.id,
            details={"pid": pid, "ppid": data.get("ppid"), "name": name, "cmdline": cmdline, "exe_path": data.get("exe_path")},
            is_timestamp_estimated=is_estimated,
        ))
        return events

    def _file_to_timeline(self, item: CanonicalEvidenceItem, data: Dict[str, Any]) -> List[TimelineEvent]:
        events = []
        path = data.get("path", "unknown")
        size = data.get("size", 0)

        # File Modification
        mod_time = data.get("modified_time")
        if mod_time:
            events.append(TimelineEvent(
                timestamp=mod_time,
                host=item.host,
                type="FILE_MODIFY",
                source="file",
                summary=f"File Modified: '{path}' ({size} bytes)",
                evidence_id=item.id,
                details={"path": path, "size": size, "sha256": data.get("sha256")},
                is_timestamp_estimated=False,
            ))

        # File Creation
        cre_time = data.get("created_time")
        if cre_time and cre_time != mod_time:
            events.append(TimelineEvent(
                timestamp=cre_time,
                host=item.host,
                type="FILE_CREATE",
                source="file",
                summary=f"File Created: '{path}' ({size} bytes)",
                evidence_id=item.id,
                details={"path": path, "size": size, "sha256": data.get("sha256")},
                is_timestamp_estimated=False,
            ))

        if not events:
            # Fallback if filesystem timestamps are unavailable
            events.append(TimelineEvent(
                timestamp=item.timestamp,
                host=item.host,
                type="FILE_RECORDED",
                source="file",
                summary=f"File Recorded: '{path}' ({size} bytes)",
                evidence_id=item.id,
                details={"path": path, "size": size},
                is_timestamp_estimated=True,
            ))

        return events

    def _network_to_timeline(self, item: CanonicalEvidenceItem, data: Dict[str, Any]) -> List[TimelineEvent]:
        proto = data.get("protocol", "TCP")
        lip = data.get("local_ip", "0.0.0.0")
        lport = data.get("local_port", 0)
        rip = data.get("remote_ip", "0.0.0.0")
        rport = data.get("remote_port", 0)
        state = data.get("status", "ESTABLISHED")
        pid = data.get("pid")
        pname = data.get("process_name") or "unknown"

        # Network connections from psutil / /proc do not have individual connection timestamps;
        # record using evidence capture timestamp, explicitly marked as estimated.
        return [TimelineEvent(
            timestamp=item.timestamp,
            host=item.host,
            type="NETWORK_SOCKET",
            source="network",
            summary=f"Network Socket: {proto} {lip}:{lport} -> {rip}:{rport} [{state}] (PID {pid}: {pname})",
            evidence_id=item.id,
            details={"protocol": proto, "local": f"{lip}:{lport}", "remote": f"{rip}:{rport}", "status": state, "pid": pid},
            is_timestamp_estimated=True,
        )]

    def _event_to_timeline(self, item: CanonicalEvidenceItem, data: Dict[str, Any]) -> List[TimelineEvent]:
        log_name = data.get("log_name", "Security")
        event_id = data.get("event_id", 0)
        source = data.get("source", log_name)
        msg = data.get("message") or ""
        ts = data.get("time_created") or item.timestamp
        is_estimated = not bool(data.get("time_created"))

        return [TimelineEvent(
            timestamp=ts,
            host=item.host,
            type="EVENT_LOG",
            source="event",
            summary=f"Event {event_id} ({log_name}): {msg[:100] if msg else source}",
            evidence_id=item.id,
            details={"log_name": log_name, "event_id": event_id, "source": source, "event_data": data.get("event_data", {})},
            is_timestamp_estimated=is_estimated,
        )]

    def _registry_to_timeline(self, item: CanonicalEvidenceItem, data: Dict[str, Any]) -> List[TimelineEvent]:
        hive = data.get("hive", "HKLM")
        key = data.get("key", "")
        v_name = data.get("value_name", "")
        v_data = data.get("value_data", "")

        return [TimelineEvent(
            timestamp=item.timestamp,
            host=item.host,
            type="REGISTRY_KEY",
            source="registry",
            summary=f"Registry Autorun: {hive}\\{key} ({v_name} -> {v_data[:60]})",
            evidence_id=item.id,
            details={"hive": hive, "key": key, "value_name": v_name, "value_data": v_data},
            is_timestamp_estimated=True,
        )]

    @staticmethod
    def _sort_key(event: TimelineEvent) -> tuple[int, str]:
        """
        Produce a deterministic sorting key:
        Items with valid timestamps come first sorted chronologically (bucket 0);
        Items with unparseable/invalid timestamps come next (bucket 1);
        Items with None/empty timestamp come last (bucket 2).
        """
        ts = event.timestamp
        if not ts:
            return 2, ""

        # Normalize timestamp format for comparison
        clean_ts = str(ts).replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return 0, dt.astimezone(timezone.utc).isoformat()
        except Exception:
            return 1, str(ts)

