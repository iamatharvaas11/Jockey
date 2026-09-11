"""
Tests for JOCKY Stage 6 Timeline Engine and Unified Investigation Analysis
Covers timestamp sorting, mixed evidence types, missing timestamps,
duplicate timestamps, and full pipeline execution.
"""
import pytest

from analysis import run_investigation_analysis
from analysis.models import InvestigationAnalysis, TimelineEvent
from analysis.timeline import TimelineEngine
from evidence.schema import CanonicalEvidenceItem, EvidenceType


# ============================================================================
# 1. Timeline Engine Tests
# ============================================================================

class TestTimelineEngine:
    @pytest.fixture
    def engine(self):
        return TimelineEngine()

    def test_timestamp_sorting_chronological(self, engine):
        item_early = CanonicalEvidenceItem(
            id="T1",
            host="HOST",
            type=EvidenceType.PROCESS.value,
            data={"pid": 10, "name": "early.exe", "created_time": "2026-09-01T10:00:00Z"},
        )
        item_late = CanonicalEvidenceItem(
            id="T3",
            host="HOST",
            type=EvidenceType.PROCESS.value,
            data={"pid": 30, "name": "late.exe", "created_time": "2026-09-03T10:00:00Z"},
        )
        item_mid = CanonicalEvidenceItem(
            id="T2",
            host="HOST",
            type=EvidenceType.PROCESS.value,
            data={"pid": 20, "name": "mid.exe", "created_time": "2026-09-02T10:00:00Z"},
        )

        # Feed in shuffled order: late, early, mid
        events = engine.build_timeline([item_late, item_early, item_mid])
        assert len(events) == 3
        timestamps = [e.timestamp for e in events]
        assert timestamps == [
            "2026-09-01T10:00:00Z",
            "2026-09-02T10:00:00Z",
            "2026-09-03T10:00:00Z",
        ]

    def test_mixed_evidence_types_in_timeline(self, engine):
        proc = CanonicalEvidenceItem(
            id="E-P", host="HOST", type="process", data={"pid": 1, "name": "init", "created_time": "2026-09-03T01:00:00Z"}
        )
        file_ev = CanonicalEvidenceItem(
            id="E-F", host="HOST", type="file", data={"path": "/bin/init", "size": 100, "modified_time": "2026-09-03T02:00:00Z"}
        )
        net = CanonicalEvidenceItem(
            id="E-N", host="HOST", timestamp="2026-09-03T03:00:00Z", type="network", data={"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 80}
        )
        evt = CanonicalEvidenceItem(
            id="E-E", host="HOST", type="event", data={"event_id": 4624, "time_created": "2026-09-03T04:00:00Z"}
        )
        reg = CanonicalEvidenceItem(
            id="E-R", host="HOST", timestamp="2026-09-03T05:00:00Z", type="registry", data={"hive": "HKLM", "key": "Run", "value_name": "x", "value_data": "y"}
        )

        timeline = engine.build_timeline([proc, file_ev, net, evt, reg])
        assert len(timeline) >= 5
        types = {e.type for e in timeline}
        assert "PROCESS_START" in types
        assert "FILE_MODIFY" in types
        assert "NETWORK_SOCKET" in types
        assert "EVENT_LOG" in types
        assert "REGISTRY_KEY" in types

    def test_missing_timestamps_preserved_and_flagged(self, engine):
        item_no_ts = CanonicalEvidenceItem(
            id="NO-TS",
            host="HOST",
            timestamp="",  # Empty timestamp
            type="process",
            data={"pid": 99, "name": "ghost.exe", "created_time": None},
        )
        item_with_ts = CanonicalEvidenceItem(
            id="HAS-TS",
            host="HOST",
            type="process",
            data={"pid": 100, "name": "live.exe", "created_time": "2026-09-03T12:00:00Z"},
        )

        timeline = engine.build_timeline([item_no_ts, item_with_ts])
        assert len(timeline) == 2
        # Event with known timestamp should come first
        assert timeline[0].evidence_id == "HAS-TS"
        assert timeline[1].evidence_id == "NO-TS"
        assert timeline[1].is_timestamp_estimated is True

    def test_duplicate_timestamps_preserved(self, engine):
        item1 = CanonicalEvidenceItem(
            id="DUP-1", host="HOST", type="process", data={"pid": 1, "name": "p1", "created_time": "2026-09-03T12:00:00Z"}
        )
        item2 = CanonicalEvidenceItem(
            id="DUP-2", host="HOST", type="process", data={"pid": 2, "name": "p2", "created_time": "2026-09-03T12:00:00Z"}
        )
        timeline = engine.build_timeline([item1, item2])
        assert len(timeline) == 2
        assert timeline[0].timestamp == "2026-09-03T12:00:00Z"
        assert timeline[1].timestamp == "2026-09-03T12:00:00Z"


# ============================================================================
# 2. Unified Investigation Analysis Pipeline Test
# ============================================================================

class TestUnifiedInvestigationAnalysis:
    def test_run_investigation_analysis_pipeline(self):
        items = [
            CanonicalEvidenceItem(
                id="P-01",
                host="HOST-1",
                type=EvidenceType.PROCESS.value,
                data={
                    "pid": 5001,
                    "ppid": 1000,
                    "name": "powershell.exe",
                    "exe_path": "C:\\Windows\\System32\\powershell.exe",
                    "cmdline": "powershell.exe -enc AAAAAAAABBBBBBBBCCCCCCCCDDDDDD==",
                    "created_time": "2026-09-03T10:00:00Z",
                },
            ),
            CanonicalEvidenceItem(
                id="F-01",
                host="HOST-1",
                type=EvidenceType.FILE.value,
                data={
                    "path": "C:\\Windows\\System32\\powershell.exe",
                    "size": 450000,
                    "modified_time": "2026-09-01T00:00:00Z",
                },
            ),
            CanonicalEvidenceItem(
                id="N-01",
                host="HOST-1",
                timestamp="2026-09-03T10:01:00Z",
                type=EvidenceType.NETWORK.value,
                data={
                    "pid": 5001,
                    "protocol": "TCP",
                    "local_ip": "192.168.1.10",
                    "local_port": 49999,
                    "remote_ip": "10.0.0.99",
                    "remote_port": 443,
                },
            ),
        ]

        analysis = run_investigation_analysis(items, case_id="CASE-ALPHA")
        assert isinstance(analysis, InvestigationAnalysis)
        assert analysis.case_id == "CASE-ALPHA"

        # Check IOC findings: powershell -enc (IOC-PROC-001) and remote IP 10.0.0.99 (IOC-NET-001)
        assert len(analysis.findings) >= 2
        rule_ids = {f.rule_id for f in analysis.findings}
        assert "IOC-PROC-001" in rule_ids
        assert "IOC-NET-001" in rule_ids

        # Check relationships: EXECUTED_FROM_FILE and OPENED_SOCKET
        assert len(analysis.relationships) >= 2
        rel_types = {r.relationship_type for r in analysis.relationships}
        assert "EXECUTED_FROM_FILE" in rel_types
        assert "OPENED_SOCKET" in rel_types

        # Check timeline
        assert len(analysis.timeline) >= 3
        # Check statistics
        stats = analysis.statistics
        assert stats["evidence_items"] == 3
        assert stats["ioc_findings"] >= 2
        assert stats["relationships"] >= 2
        assert stats["timeline_events"] >= 3

        # Check serialization round-trip
        data_dict = analysis.to_dict()
        assert data_dict["case_id"] == "CASE-ALPHA"
        assert len(data_dict["findings"]) == len(analysis.findings)

