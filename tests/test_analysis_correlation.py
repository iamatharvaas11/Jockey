"""
Tests for JOCKY Stage 6 Correlation Engine
Covers process-file, process-network, parent-child, event, and registry correlation,
time windowing, and cross-host isolation.
"""
import pytest

from analysis.correlation import CorrelationEngine
from analysis.models import EvidenceRelationship
from evidence.schema import CanonicalEvidenceItem, EvidenceType


# ============================================================================
# 1. Correlation Tests
# ============================================================================

class TestCorrelationEngine:
    @pytest.fixture
    def engine(self):
        return CorrelationEngine(time_window_seconds=300)

    def test_process_file_correlation(self, engine):
        proc = CanonicalEvidenceItem(
            id="PROC-101",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 101, "name": "beacon.exe", "exe_path": "C:\\Tools\\beacon.exe"},
        )
        file_ev = CanonicalEvidenceItem(
            id="FILE-201",
            host="HOST-A",
            type=EvidenceType.FILE.value,
            data={"path": "C:\\Tools\\beacon.exe", "size": 65536, "sha256": "a" * 64},
        )
        relationships = engine.correlate([proc, file_ev])
        assert len(relationships) == 1
        r = relationships[0]
        assert r.relationship_type == "EXECUTED_FROM_FILE"
        assert r.source_evidence_id == proc.id
        assert r.target_evidence_id == file_ev.id
        assert r.confidence == 1.0

    def test_process_network_correlation(self, engine):
        proc = CanonicalEvidenceItem(
            id="PROC-102",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 4455, "name": "curl.exe", "exe_path": "C:\\Windows\\curl.exe"},
        )
        net_ev = CanonicalEvidenceItem(
            id="NET-301",
            host="HOST-A",
            type=EvidenceType.NETWORK.value,
            data={"pid": 4455, "protocol": "TCP", "local_ip": "192.168.1.5", "local_port": 50000, "remote_ip": "93.184.216.34", "remote_port": 80},
        )
        relationships = engine.correlate([proc, net_ev])
        assert len(relationships) == 1
        r = relationships[0]
        assert r.relationship_type == "OPENED_SOCKET"
        assert r.source_evidence_id == proc.id
        assert r.target_evidence_id == net_ev.id

    def test_parent_child_correlation(self, engine):
        parent = CanonicalEvidenceItem(
            id="P-01",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 1000, "ppid": 4, "name": "explorer.exe"},
        )
        child = CanonicalEvidenceItem(
            id="P-02",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 2048, "ppid": 1000, "name": "cmd.exe"},
        )
        relationships = engine.correlate([parent, child])
        assert len(relationships) == 1
        r = relationships[0]
        assert r.relationship_type == "SPAWNED_CHILD"
        assert r.source_evidence_id == parent.id
        assert r.target_evidence_id == child.id

    def test_event_process_correlation(self, engine):
        proc = CanonicalEvidenceItem(
            id="PROC-103",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 3322, "name": "whoami.exe"},
        )
        evt = CanonicalEvidenceItem(
            id="EVT-01",
            host="HOST-A",
            type=EvidenceType.EVENT.value,
            data={"event_id": 4688, "event_data": {"NewProcessId": 3322}},
        )
        relationships = engine.correlate([proc, evt])
        assert len(relationships) == 1
        assert relationships[0].relationship_type == "RECORDED_BY_EVENT"

    def test_registry_persistence_correlation(self, engine):
        reg = CanonicalEvidenceItem(
            id="REG-01",
            host="HOST-A",
            type=EvidenceType.REGISTRY.value,
            data={"hive": "HKLM", "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "Backdoor", "value_data": "C:\\Windows\\Temp\\srv.exe"},
        )
        file_ev = CanonicalEvidenceItem(
            id="FILE-202",
            host="HOST-A",
            type=EvidenceType.FILE.value,
            data={"path": "C:\\Windows\\Temp\\srv.exe", "size": 1024},
        )
        relationships = engine.correlate([reg, file_ev])
        assert len(relationships) == 1
        assert relationships[0].relationship_type == "PERSISTED_IN_REGISTRY"

    def test_unrelated_evidence_does_not_correlate(self, engine):
        proc = CanonicalEvidenceItem(
            id="PROC-999",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 999, "name": "notepad.exe", "exe_path": "C:\\Windows\\notepad.exe"},
        )
        net_ev = CanonicalEvidenceItem(
            id="NET-999",
            host="HOST-A",
            type=EvidenceType.NETWORK.value,
            data={"pid": 111, "remote_ip": "1.1.1.1"},  # different PID
        )
        relationships = engine.correlate([proc, net_ev])
        assert len(relationships) == 0

    def test_cross_host_isolation_prevents_spurious_joins(self, engine):
        """PID 500 on HOST-A must NOT correlate with socket PID 500 on HOST-B!"""
        proc_host_a = CanonicalEvidenceItem(
            id="PROC-A",
            host="HOST-A",
            type=EvidenceType.PROCESS.value,
            data={"pid": 500, "name": "service.exe"},
        )
        net_host_b = CanonicalEvidenceItem(
            id="NET-B",
            host="HOST-B",
            type=EvidenceType.NETWORK.value,
            data={"pid": 500, "remote_ip": "8.8.8.8"},
        )
        relationships = engine.correlate([proc_host_a, net_host_b])
        assert len(relationships) == 0

