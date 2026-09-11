"""
Tests for JOCKY Stage 7 Production-Quality Forensic Reporting Subsystem
Covers complete reports, integrity verification statuses (VERIFIED, UNVERIFIED, FAILED),
partial evidence, missing timestamps, empty investigations, malformed evidence,
and JSON / HTML / PDF export formats.
"""
import os
import tempfile
import pytest

from analysis.models import EvidenceRelationship, IOCFinding, InvestigationAnalysis, TimelineEvent
from engine.report_generator import ReportGenerator
from evidence.audit import AuditAction, AuditLogger, AuditRecord
from evidence.integrity import IntegrityManifest, VerificationReport, VerificationStatus
from evidence.schema import CanonicalEvidenceItem, EvidenceType


class TestForensicReporting:
    @pytest.fixture
    def generator(self):
        return ReportGenerator(case_id="CASE-2026-TEST", examiner="Lead Investigator")

    def test_complete_report_generation(self, generator):
        evidence = [
            CanonicalEvidenceItem(
                id="EVID-1",
                host="WIN-SERVER",
                type=EvidenceType.PROCESS.value,
                data={"pid": 100, "name": "cmd.exe"},
            ),
            CanonicalEvidenceItem(
                id="EVID-2",
                host="WIN-SERVER",
                type=EvidenceType.NETWORK.value,
                data={"pid": 100, "remote_ip": "1.2.3.4"},
            ),
        ]
        manifest = IntegrityManifest(
            manifest_id="M-01",
            case_id="CASE-2026-TEST",
            root_hash="a" * 64,
            status="verified",
            entries=[],
        )
        v_report = VerificationReport(
            status=VerificationStatus.VALID,
            total_checked=2,
            valid_count=2,
            modified_count=0,
            missing_count=0,
            corrupted_count=0,
        )
        analysis = InvestigationAnalysis(
            findings=[IOCFinding(rule_id="RULE-1", rule_name="Test Finding", severity="high", reason="Observed anomaly")],
            relationships=[EvidenceRelationship(source_evidence_id="EVID-1", target_evidence_id="EVID-2", relationship_type="OPENED_SOCKET")],
            timeline=[TimelineEvent(timestamp="2026-09-03T10:00:00Z", summary="Process started", type="PROCESS_START")],
        )

        logger = AuditLogger()
        rec = logger.log(action=AuditAction.COLLECT, actor="Agent", evidence_id="EVID-1", result="SUCCESS")

        report = generator.generate(
            evidence_items=evidence,
            integrity_manifest=manifest,
            verification_report=v_report,
            analysis=analysis,
            audit_records=[rec],
            limitations=["Protected system processes skipped"],
            errors=[],
        )

        assert report["meta"]["case_id"] == "CASE-2026-TEST"
        assert "WIN-SERVER" in report["meta"]["hosts"]
        assert report["summary"]["total_evidence_items"] == 2
        assert report["summary"]["total_ioc_findings"] == 1
        assert report["summary"]["total_relationships"] == 1
        assert report["summary"]["total_timeline_events"] == 1
        assert report["summary"]["total_audit_records"] == 1
        assert report["summary"]["integrity_status"] == "verified"
        assert report["integrity_manifest"]["verified"] is True
        assert len(report["limitations"]) == 1

    def test_report_without_integrity_manifest_is_unverified(self, generator):
        """When integrity data is absent, status must strictly be UNVERIFIED."""
        report = generator.generate(
            processes=[{"pid": 1, "name": "system"}],
            integrity_manifest=None,
            verification_report=None,
        )
        assert report["summary"]["integrity_status"] == "unverified"
        assert report["integrity_manifest"]["status"] == "unverified"
        assert report["integrity_manifest"]["verified"] is False
        assert report["integrity_manifest"]["root_hash"] is None

    def test_report_with_failed_verification_is_failed(self, generator):
        """When manifest verification fails, status must strictly be FAILED."""
        manifest = IntegrityManifest(
            manifest_id="M-FAIL",
            root_hash="0" * 64,
            status="failed",
        )
        v_report = VerificationReport(
            status=VerificationStatus.MODIFIED,
            total_checked=1,
            valid_count=0,
            modified_count=1,
            missing_count=0,
            corrupted_count=0,
            details=[{"evidence_id": "E1", "reason": "Hash mismatch"}],
        )
        report = generator.generate(
            integrity_manifest=manifest,
            verification_report=v_report,
        )
        assert report["summary"]["integrity_status"] == "failed"
        assert report["integrity_manifest"]["status"] == "failed"
        assert report["integrity_manifest"]["verified"] is False

    def test_partial_evidence_reporting(self, generator):
        """Report handles missing collectors or partial evidence gracefully."""
        report = generator.generate(
            processes=None,
            connections=[{"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 80}],
            events=None,
        )
        assert report["summary"]["total_evidence_items"] == 1
        assert report["summary"]["evidence_by_type"]["network"] == 1
        assert report["summary"]["evidence_by_type"]["process"] == 0

    def test_missing_timestamps_in_timeline(self, generator):
        """Timeline events with missing timestamps are preserved and marked without crash."""
        analysis = InvestigationAnalysis(
            timeline=[
                TimelineEvent(timestamp=None, summary="Socket observed", is_timestamp_estimated=True),
                TimelineEvent(timestamp="2026-09-03T12:00:00Z", summary="Process launched"),
            ]
        )
        report = generator.generate(analysis=analysis)
        assert len(report["timeline"]) == 2
        assert report["timeline"][0]["timestamp"] is None
        assert report["timeline"][0]["is_timestamp_estimated"] is True

    def test_empty_investigation_report(self, generator):
        """Report on empty dataset produces valid schema with 0 counts."""
        report = generator.generate()
        assert report["summary"]["total_evidence_items"] == 0
        assert report["summary"]["total_ioc_findings"] == 0
        assert report["summary"]["integrity_status"] == "unverified"
        assert isinstance(report["meta"]["generated_at"], str)

    def test_malformed_evidence_items_handled_safely(self, generator):
        """Corrupted dicts or irregular keys do not crash report generation."""
        corrupted = [
            {"corrupted": True},
            None,
            "not a dict or item",
            {"type": "process", "pid": "not-an-int"},
        ]
        # Filter non-dicts
        safe_corrupted = [x for x in corrupted if isinstance(x, dict)]
        report = generator.generate(evidence_items=safe_corrupted)
        assert report["summary"]["total_evidence_items"] == 2

    def test_json_and_html_export_roundtrip(self, generator):
        report = generator.generate(
            processes=[{"pid": 4, "name": "System"}],
            limitations=["Requires SYSTEM privileges"],
            errors=["Network adapter 2 timeout"],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "report.json")
            html_path = os.path.join(tmpdir, "report.html")

            generator.to_json(report, json_path)
            generator.to_html(report, html_path)

            assert os.path.exists(json_path)
            assert os.path.exists(html_path)

            # Validate JSON content
            import json
            with open(json_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["meta"]["case_id"] == "CASE-2026-TEST"

            # Validate HTML content
            with open(html_path, "r", encoding="utf-8") as f:
                html_text = f.read()
            assert "Forensic Investigation Report" in html_text
            assert "Requires SYSTEM privileges" in html_text
            assert "Network adapter 2 timeout" in html_text

    def test_pdf_export_dependency_handling(self, generator):
        report = generator.generate()
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = os.path.join(tmpdir, "report.pdf")
            try:
                import reportlab
                result = generator.to_pdf(report, pdf_path)
                assert result is True
                assert os.path.exists(pdf_path)
            except ImportError:
                # If reportlab is not installed, must raise clean NotImplementedError
                with pytest.raises(NotImplementedError) as exc:
                    generator.to_pdf(report, pdf_path)
                assert "reportlab" in str(exc.value)
