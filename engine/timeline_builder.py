class TimelineBuilder:
    def __init__(self):
        self.events = []

    def _add_event(self, ts, source, ev_type, severity, title, desc, ent_id, raw):
        if ts:
            self.events.append({
                "timestamp_utc": ts,
                "source_type": source,
                "event_type": ev_type,
                "severity": severity,
                "title": title,
                "description": desc,
                "entity_id": ent_id,
                "raw_data": raw
            })

    def add_process_events(self, processes: list):
        for p in processes:
            self._add_event(
                ts=p.get('create_time'),
                source="Process",
                ev_type="ProcessCreation",
                severity="low",
                title=f"Process Created: {p.get('name')}",
                desc=f"PID {p.get('pid')} launched with cmd: {p.get('cmdline')}",
                ent_id=str(p.get('pid')),
                raw={"pid": p.get('pid'), "name": p.get('name'), "exe": p.get('exe_path')}
            )

    def add_network_events(self, connections: list):
        for c in connections:
            # We don't have timestamps for connections from psutil, using 'now' could be misleading.
            # Assuming real connections have some sort of time or we log them at collection time.
            # For timeline, we might not have exact time unless derived elsewhere.
            pass 

    def add_eventlog_events(self, events: list):
        for e in events:
            self._add_event(
                ts=e.get('time_created'),
                source="EventLog",
                ev_type=e.get('event_id'),
                severity="medium" if e.get('event_id') in ['4625', '4688'] else "info",
                title=f"Event ID: {e.get('event_id')}",
                desc=str(e.get('event_data')),
                ent_id=e.get('event_id'),
                raw=e
            )

    def add_file_events(self, files: list):
        for f in files:
            self._add_event(
                ts=f.get('modified_time'),
                source="File",
                ev_type="FileModification",
                severity="low",
                title=f"File Modified: {f.get('path')}",
                desc=f"Size: {f.get('size')} bytes",
                ent_id=f.get('path'),
                raw=f
            )
            self._add_event(
                ts=f.get('created_time'),
                source="File",
                ev_type="FileCreation",
                severity="low",
                title=f"File Created: {f.get('path')}",
                desc=f"Size: {f.get('size')} bytes",
                ent_id=f.get('path'),
                raw=f
            )

    def add_registry_events(self, registry: list):
        for r in registry:
            pass # No timestamps collected for registry in simple collector

    def add_alert(self, alert: dict):
        self._add_event(
            ts=alert.get('timestamp'), # If available
            source="Alert",
            ev_type="IOCMatch",
            severity=alert.get('severity', 'high'),
            title=f"Alert: {alert.get('type')}",
            desc=str(alert),
            ent_id="alert",
            raw=alert
        )

    def build(self) -> list[dict]:
        self.events.sort(key=lambda x: x.get('timestamp_utc') or "")
        return self.events

    def filter_by_severity(self, min_severity: str) -> list[dict]:
        levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_lvl = levels.get(min_severity.lower(), 0)
        return [e for e in self.events if levels.get(e.get('severity', 'info'), 0) >= min_lvl]

    def filter_by_source(self, source: str) -> list[dict]:
        return [e for e in self.events if e.get('source_type') == source]

    def filter_by_timerange(self, start: str, end: str) -> list[dict]:
        return [e for e in self.events if start <= (e.get('timestamp_utc') or "") <= end]
