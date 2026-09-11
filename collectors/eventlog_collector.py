"""
JOCKY Event Log Collector
Collects Windows Event Logs (Security, System, Application) using the Windows Evt API.
Gracefully handles non-Windows platforms and insufficient administrator privileges.
"""
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from .base import BaseCollector, CollectorResult, CollectorStatus


class EventLogCollector(BaseCollector):
    """Forensic event log collector for Windows Event Log (Evt API)."""

    def __init__(self):
        super().__init__(name="eventlog_collector")
        self.is_windows = sys.platform == "win32"
        self.win32evtlog = None
        if self.is_windows:
            try:
                import win32evtlog
                self.win32evtlog = win32evtlog
            except ImportError:
                pass

    def collect(
        self,
        log_name: str = "System",
        event_ids: Optional[List[int]] = None,
        max_records: int = 50,
        **kwargs,
    ) -> CollectorResult:
        """
        Collect event records from the specified log channel.
        Returns a normalized CollectorResult envelope.
        """
        if not self.is_windows:
            return CollectorResult(
                type="eventlog",
                source=sys.platform,
                status=CollectorStatus.UNSUPPORTED,
                data=[],
                limitations=["Windows Event Logs are not available on non-Windows platforms."],
            )

        if not self.win32evtlog:
            return CollectorResult(
                type="eventlog",
                source="win32",
                status=CollectorStatus.FAILED,
                data=[],
                errors=["pywin32 (win32evtlog) is not installed on this system."],
                limitations=["Install pywin32 to enable Windows Event Log collection."],
            )

        results = []
        errors = []
        limitations = []

        try:
            if event_ids:
                ids_str = " or ".join([f"EventID={eid}" for eid in event_ids])
                query = f"*[System[({ids_str})]]"
            else:
                query = "*"

            flags = self.win32evtlog.EvtQueryChannelPath | self.win32evtlog.EvtQueryReverseDirection
            handle = self.win32evtlog.EvtQuery(log_name, flags, query)

            while len(results) < max_records:
                batch_size = min(10, max_records - len(results))
                events = self.win32evtlog.EvtNext(handle, batch_size)
                if not events:
                    break

                for event in events:
                    try:
                        xml_content = self.win32evtlog.EvtRender(event, self.win32evtlog.EvtRenderEventXml)
                        root = ET.fromstring(xml_content)
                        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

                        sys_elem = root.find(f"{ns}System")
                        event_id_str = sys_elem.find(f"{ns}EventID").text if sys_elem is not None and sys_elem.find(f"{ns}EventID") is not None else "0"
                        time_created = sys_elem.find(f"{ns}TimeCreated").get("SystemTime") if sys_elem is not None and sys_elem.find(f"{ns}TimeCreated") is not None else ""
                        provider_elem = sys_elem.find(f"{ns}Provider") if sys_elem is not None else None
                        provider_name = provider_elem.get("Name") if provider_elem is not None else ""

                        event_data = {}
                        data_elem = root.find(f"{ns}EventData")
                        if data_elem is not None:
                            for data in data_elem.findall(f"{ns}Data"):
                                name = data.get("Name")
                                if name:
                                    event_data[name] = data.text

                        results.append({
                            "log_name": log_name,
                            "event_id": int(event_id_str) if event_id_str.isdigit() else 0,
                            "source": provider_name,
                            "time_created": time_created,
                            "event_data": event_data,
                            "message": f"Event {event_id_str} from {provider_name}",
                        })
                    except Exception as e:
                        errors.append(f"Failed to render event record: {str(e)}")

        except Exception as e:
            err_msg = str(e)
            if "Access is denied" in err_msg or "5" in err_msg:
                limitations.append(f"Administrator privileges required to query channel '{log_name}'.")
            errors.append(f"EvtQuery failed on log '{log_name}': {err_msg}")

        status = CollectorStatus.SUCCESS
        if errors and not results:
            status = CollectorStatus.FAILED
        elif errors or limitations:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="eventlog",
            source="win32",
            status=status,
            data=results,
            errors=errors,
            limitations=limitations,
        )

    def collect_security_events(self, max_records: int = 50) -> CollectorResult:
        """Collect security log events (requires Administrator elevation)."""
        return self.collect(log_name="Security", max_records=max_records)
