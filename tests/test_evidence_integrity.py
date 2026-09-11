"""
Tests for JOCKY Stage 5 Evidence Integrity, Deterministic Hashing,
Tamper Detection, Manifest Verification, EvidenceStore, and Audit Trails.
"""
import os
import tempfile
import pytest

from evidence.audit import AuditAction, AuditLogger, AuditRecord
from evidence.integrity import (
    EvidenceIntegrityManager,
    IntegrityError,
    IntegrityManifest,
    VerificationReport,
    VerificationStatus,
)
from evidence.normalizer import EvidenceNormalizer
from evidence.schema import CanonicalEvidenceItem, EvidenceStatus, EvidenceType
from evidence.store import FileEvidenceStore, InMemoryEvidenceStore
from engine.report_generator import ReportGenerator


# ============================================================================
# 1. Deterministic Hashing Tests
# ============================================================================

class TestDeterministicHashing:
    def test_deterministic_hash_same_content(self):
        item1 = CanonicalEvidenceItem(
            id="STATIC-UUID-1234",
            host="HOST-A",
            timestamp="2026-09-03T12:00:00Z",
            type=EvidenceType.PROCESS.value,
            source="win32",
            data={"pid": 100, "name": "test.exe"},
        )
        item2 = CanonicalEvidenceItem(
            id="STATIC-UUID-1234",
            host="HOST-A",
            timestamp="2026-09-03T12:00:00Z",
            type=EvidenceType.PROCESS.value,
            source="win32",
            data={"name": "test.exe", "pid": 100},  # reversed dict keys
        )
        h1 = EvidenceIntegrityManager.compute_evidence_hash(item1)
        h2 = EvidenceIntegrityManager.compute_evidence_hash(item2)
        assert len(h1) == 64
        assert h1 == h2, "Hashing must be independent of dict key insertion order"

    def test_hash_excludes_hash_field(self):
        """The hash attribute of the item must not affect its computed digest."""
        item = CanonicalEvidenceItem(
            id="UUID-1",
            host="HOST",
            type=EvidenceType.FILE.value,
            data={"path": "/tmp/a", "size": 10},
        )
        h_before = EvidenceIntegrityManager.compute_evidence_hash(item)
        item.hash = h_before
        h_after = EvidenceIntegrityManager.compute_evidence_hash(item)
        assert h_before == h_after

    def test_missing_data_or_unhashable_raises_integrity_error(self):
        """Missing hash generation must be an error, not a placeholder or silent failure."""
        class UnserializableObject:
            pass

        item = CanonicalEvidenceItem(
            id="UUID-BAD",
            host="HOST",
            type=EvidenceType.GENERIC.value,
            data={"bad_obj": UnserializableObject()},
        )
        with pytest.raises(IntegrityError):
            EvidenceIntegrityManager.compute_evidence_hash(item)


# ============================================================================
# 2. Hash Verification & Tamper Detection Tests
# ============================================================================

class TestTamperDetection:
    def test_unmodified_item_is_valid(self):
        item = CanonicalEvidenceItem(
            id="ITEM-01",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={"pid": 456, "name": "worker.exe"},
        )
        EvidenceIntegrityManager.attach_hash(item)
        assert EvidenceIntegrityManager.verify_item(item) == VerificationStatus.VALID

    def test_tampered_item_is_detected_as_modified(self):
        item = CanonicalEvidenceItem(
            id="ITEM-02",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={"pid": 456, "name": "worker.exe"},
        )
        EvidenceIntegrityManager.attach_hash(item)
        recorded_hash = item.hash

        # Malicious modification
        item.data["pid"] = 9999

        status = EvidenceIntegrityManager.verify_item(item, recorded_hash)
        assert status == VerificationStatus.MODIFIED

    def test_missing_hash_fails_verification(self):
        item = CanonicalEvidenceItem(id="NO-HASH", host="HOST", data={})
        status = EvidenceIntegrityManager.verify_item(item, recorded_hash=None)
        assert status == VerificationStatus.CORRUPTED


# ============================================================================
# 3. Integrity Manifest Tests
# ============================================================================

class TestIntegrityManifest:
    def test_manifest_creation_and_root_hash(self):
        items = [
            CanonicalEvidenceItem(id=f"ITEM-{i}", host="HOST", data={"val": i})
            for i in range(5)
        ]
        manifest = EvidenceIntegrityManager.create_manifest(items, case_id="CASE-99")
        assert manifest.case_id == "CASE-99"
        assert len(manifest.entries) == 5
        assert len(manifest.root_hash) == 64

        # Verification must pass
        report = EvidenceIntegrityManager.verify_manifest(manifest, items)
        assert report.status == VerificationStatus.VALID
        assert report.valid_count == 5

    def test_manifest_detects_tampered_item(self):
        items = [
            CanonicalEvidenceItem(id=f"ITEM-{i}", host="HOST", data={"val": i})
            for i in range(3)
        ]
        manifest = EvidenceIntegrityManager.create_manifest(items)

        # Tamper with second item
        items[1].data["val"] = 99999

        report = EvidenceIntegrityManager.verify_manifest(manifest, items)
        assert report.status == VerificationStatus.MODIFIED
        assert report.modified_count == 1
        assert report.valid_count == 2

    def test_manifest_detects_corrupted_root_hash(self):
        items = [CanonicalEvidenceItem(id="ITEM-1", host="HOST", data={"x": 1})]
        manifest = EvidenceIntegrityManager.create_manifest(items)

        # Corrupt manifest root hash
        manifest.root_hash = "0" * 64

        report = EvidenceIntegrityManager.verify_manifest(manifest, items)
        assert report.status == VerificationStatus.CORRUPTED
        assert any(d.get("evidence_id") == "MANIFEST_ROOT" for d in report.details)

    def test_manifest_detects_missing_evidence_item(self):
        items = [CanonicalEvidenceItem(id=f"ITEM-{i}", host="HOST", data={"i": i}) for i in range(3)]
        manifest = EvidenceIntegrityManager.create_manifest(items)

        # Remove item from store
        remaining_items = items[:2]
        report = EvidenceIntegrityManager.verify_manifest(manifest, remaining_items)
        assert report.status == VerificationStatus.MISSING_EVIDENCE
        assert report.missing_count == 1


# ============================================================================
# 4. Evidence Store & Filtering Tests
# ============================================================================

class TestEvidenceStore:
    def test_store_crud_and_filters(self):
        store = InMemoryEvidenceStore()
        item1 = CanonicalEvidenceItem(id="P1", host="WIN", timestamp="2026-09-03T10:00:00Z", type="process", data={"pid": 1, "name": "p1"})
        item2 = CanonicalEvidenceItem(id="F1", host="WIN", timestamp="2026-09-03T11:00:00Z", type="file", data={"path": "/a", "size": 10})
        item3 = CanonicalEvidenceItem(id="P2", host="LNX", timestamp="2026-09-03T12:00:00Z", type="process", data={"pid": 2, "name": "p2"})

        store.add_batch([item1, item2, item3])
        assert store.count() == 3
        assert store.get("P1") is not None

        # Filter by type
        processes = store.list(evidence_type="process")
        assert len(processes) == 2

        # Filter by host
        lnx_items = store.list(host="LNX")
        assert len(lnx_items) == 1
        assert lnx_items[0].id == "P2"

        # Filter by timestamp range
        time_filtered = store.list(start_time="2026-09-03T10:30:00Z", end_time="2026-09-03T11:30:00Z")
        assert len(time_filtered) == 1
        assert time_filtered[0].id == "F1"

    def test_export_import_roundtrip(self):
        store = InMemoryEvidenceStore()
        item = CanonicalEvidenceItem(id="E1", host="HOST", type="network", data={"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 80})
        store.add(item)

        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = os.path.join(tmpdir, "exported_evidence.json")
            store.export_json(export_path)
            assert os.path.exists(export_path)

            new_store = InMemoryEvidenceStore()
            imported_count = new_store.import_json(export_path)
            assert imported_count == 1
            assert new_store.get("E1") is not None
            assert new_store.get("E1").hash == item.hash

            # Verify integrity in new store
            v_report = new_store.verify_integrity()
            assert v_report.status == VerificationStatus.VALID


# ============================================================================
# 5. Audit Logging Tests
# ============================================================================

class TestAuditLogging:
    def test_audit_record_creation_and_hash(self):
        logger = AuditLogger()
        rec = logger.log(
            action=AuditAction.COLLECT,
            actor="Examiner-1",
            evidence_id="EVID-100",
            result="SUCCESS",
            details={"type": "process"},
        )
        assert rec.action == "COLLECT"
        assert rec.evidence_id == "EVID-100"
        assert len(rec.record_hash) == 64
        assert rec.record_hash == rec.compute_hash()

        records = logger.get_records(evidence_id="EVID-100")
        assert len(records) == 1


# ============================================================================
# 6. Report Generator Integrity Bug Fix Test
# ============================================================================

class TestReportGeneratorIntegrityBugFix:
    def test_report_without_manifest_is_unverified(self):
        """Must not invent SHA-256 hashes or claim verified integrity when no manifest exists."""
        gen = ReportGenerator(case_id="TEST-CASE")
        report = gen.generate(
            processes=[{"pid": 1, "name": "init"}],
            integrity_manifest=None,
        )
        manifest = report["integrity_manifest"]
        assert manifest["status"] == "unverified"
        assert manifest["verified"] is False
        assert len(manifest["artifacts"]) == 0
        assert "compliance" not in report.get("meta", {})

    def test_report_with_manifest_preserves_real_status(self):
        gen = ReportGenerator(case_id="TEST-CASE")
        real_manifest = {
            "status": "verified",
            "verified": True,
            "root_hash": "a" * 64,
            "artifacts": [{"name": "proc.json", "hash_sha256": "b" * 64, "status": "VERIFIED"}],
        }
        report = gen.generate(
            processes=[{"pid": 1, "name": "init"}],
            integrity_manifest=real_manifest,
        )
        manifest = report["integrity_manifest"]
        assert manifest["status"] == "verified"
        assert manifest["verified"] is True
        assert len(manifest["artifacts"]) == 1

