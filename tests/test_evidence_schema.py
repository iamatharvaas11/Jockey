"""
Tests for JOCKY Stage 5 Canonical Evidence Schema, Normalization, and Validation.
"""
from datetime import datetime, timezone
import pytest

from collectors.base import CollectorResult, CollectorStatus
from evidence.normalizer import EvidenceNormalizer
from evidence.schema import (
    CanonicalEvidenceItem,
    EvidenceStatus,
    EvidenceType,
    EventEvidence,
    FileEvidence,
    NetworkEvidence,
    ProcessEvidence,
    RegistryEvidence,
)
from evidence.validator import EvidenceValidator, ValidationResult


# ============================================================================
# 1. Canonical Schema & Validator Unit Tests
# ============================================================================

class TestEvidenceValidator:
    def test_valid_generic_item(self):
        item = CanonicalEvidenceItem(
            host="HOST01",
            type=EvidenceType.GENERIC.value,
            source="test_source",
            status=EvidenceStatus.SUCCESS.value,
            data={"test_key": "test_val"},
        )
        res = EvidenceValidator.validate(item)
        assert res.is_valid
        assert len(res.errors) == 0

    def test_missing_host_fails(self):
        item = CanonicalEvidenceItem(
            host="",
            type=EvidenceType.PROCESS.value,
            source="win32",
            data={"pid": 1234, "name": "cmd.exe"},
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("host" in e for e in res.errors)

    def test_invalid_timestamp_fails(self):
        item = CanonicalEvidenceItem(
            host="HOST01",
            timestamp="yesterday at 5pm",
            type=EvidenceType.GENERIC.value,
            source="test",
            data={},
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("timestamp" in e for e in res.errors)

    def test_invalid_type_fails(self):
        item = CanonicalEvidenceItem(
            host="HOST01",
            type="unrecognized_evidence_type",
            source="test",
            data={},
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("type" in e for e in res.errors)

    def test_invalid_status_fails(self):
        item = CanonicalEvidenceItem(
            host="HOST01",
            type=EvidenceType.GENERIC.value,
            source="test",
            status="somewhat_working",
            data={},
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("status" in e for e in res.errors)

    def test_invalid_hash_format_fails(self):
        item = CanonicalEvidenceItem(
            host="HOST01",
            type=EvidenceType.GENERIC.value,
            source="test",
            hash="not_a_64_char_hex_digest",
            data={},
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("hash" in e for e in res.errors)


# ============================================================================
# 2. Process Normalization & Validation Tests
# ============================================================================

class TestProcessEvidenceNormalization:
    def test_windows_process_normalization(self):
        raw_win = {
            "pid": 404,
            "ppid": 4,
            "name": "services.exe",
            "exe_path": "C:\\Windows\\System32\\services.exe",
            "exe_hash": "a" * 64,
            "cmdline": "C:\\Windows\\System32\\services.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "status": "running",
            "memory_bytes": 10485760,
            "threads": 16,
            "win32_specific_handle": 9999,  # platform field
        }
        item = EvidenceNormalizer.normalize_process(raw_win, host="WIN-HOST", source="win32")
        assert item.type == EvidenceType.PROCESS.value
        assert item.host == "WIN-HOST"
        assert item.data["pid"] == 404
        assert item.data["ppid"] == 4
        assert item.data["name"] == "services.exe"
        assert item.data["platform_data"]["win32_specific_handle"] == 9999

        v_res = EvidenceValidator.validate(item)
        assert v_res.is_valid

    def test_linux_process_normalization(self):
        raw_linux = {
            "pid": 1,
            "ppid": 0,
            "name": "systemd",
            "exe": "/lib/systemd/systemd",
            "cmdline": "/sbin/init",
            "username": "root",
            "status": "sleeping",
            "memory_rss": 5242880,
            "linux_cgroup": "/system.slice/init.scope",  # platform field
        }
        item = EvidenceNormalizer.normalize_process(raw_linux, host="UBUNTU-01", source="linux_proc")
        assert item.type == EvidenceType.PROCESS.value
        assert item.host == "UBUNTU-01"
        assert item.data["pid"] == 1
        assert item.data["name"] == "systemd"
        assert item.data["exe_path"] == "/lib/systemd/systemd"
        assert item.data["memory_bytes"] == 5242880
        assert item.data["platform_data"]["linux_cgroup"] == "/system.slice/init.scope"

        v_res = EvidenceValidator.validate(item)
        assert v_res.is_valid

    def test_process_missing_pid_validation_failure(self):
        item = CanonicalEvidenceItem(
            host="HOST",
            type=EvidenceType.PROCESS.value,
            source="win32",
            data={"name": "test.exe"},  # pid missing
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("pid" in e for e in res.errors)


# ============================================================================
# 3. File Evidence Normalization & Validation Tests
# ============================================================================

class TestFileEvidenceNormalization:
    def test_file_normalization_and_validation(self):
        raw = {
            "path": "/etc/passwd",
            "size": 2500,
            "created_time": "2026-01-01T00:00:00Z",
            "modified_time": "2026-02-01T12:00:00Z",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "permissions": "rw-r--r--",
            "inode": 1234567,  # platform field
        }
        item = EvidenceNormalizer.normalize_file(raw, host="LINUX-SRV", source="linux")
        assert item.type == EvidenceType.FILE.value
        assert item.data["path"] == "/etc/passwd"
        assert item.data["size"] == 2500
        assert item.data["platform_data"]["inode"] == 1234567

        v_res = EvidenceValidator.validate(item)
        assert v_res.is_valid

    def test_file_invalid_negative_size(self):
        item = CanonicalEvidenceItem(
            host="HOST",
            type=EvidenceType.FILE.value,
            source="test",
            data={"path": "C:\\boot.ini", "size": -50},
        )
        res = EvidenceValidator.validate(item)
        assert not res.is_valid
        assert any("size" in e for e in res.errors)


# ============================================================================
# 4. Network Evidence Normalization & Validation Tests
# ============================================================================

class TestNetworkEvidenceNormalization:
    def test_network_normalization_and_validation(self):
        raw = {
            "protocol": "tcp",
            "local_address": "127.0.0.1",
            "local_port": 8000,
            "remote_address": "0.0.0.0",
            "remote_port": 0,
            "status": "LISTEN",
            "pid": 5544,
            "process_name": "python.exe",
            "raw_fd": 32,  # platform field
        }
        item = EvidenceNormalizer.normalize_network(raw, host="DEV-BOX", source="win32")
        assert item.type == EvidenceType.NETWORK.value
        assert item.data["protocol"] == "TCP"
        assert item.data["local_ip"] == "127.0.0.1"
        assert item.data["local_port"] == 8000
        assert item.data["pid"] == 5544
        assert item.data["platform_data"]["raw_fd"] == 32

        v_res = EvidenceValidator.validate(item)
        assert v_res.is_valid


# ============================================================================
# 5. Event & Registry Evidence Normalization & Validation Tests
# ============================================================================

class TestEventAndRegistryEvidenceNormalization:
    def test_event_normalization_and_validation(self):
        raw = {
            "log_name": "Security",
            "event_id": 4624,
            "source": "Microsoft-Windows-Security-Auditing",
            "time_created": "2026-09-03T20:00:00Z",
            "message": "An account was successfully logged on.",
            "target_user_sid": "S-1-5-21-1234",  # platform field
        }
        item = EvidenceNormalizer.normalize_event(raw, host="DC01", source="win32_evt")
        assert item.type == EvidenceType.EVENT.value
        assert item.data["event_id"] == 4624
        assert item.data["log_name"] == "Security"
        assert item.data["platform_data"]["target_user_sid"] == "S-1-5-21-1234"

        v_res = EvidenceValidator.validate(item)
        assert v_res.is_valid

    def test_registry_normalization_and_validation(self):
        raw = {
            "hive": "HKCU",
            "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "SecurityUpdater",
            "value_data": "C:\\Users\\Public\\updater.exe",
            "type": 1,
            "winreg_subkeys_count": 0,  # platform field
        }
        item = EvidenceNormalizer.normalize_registry(raw, host="WIN-CLIENT", source="winreg")
        assert item.type == EvidenceType.REGISTRY.value
        assert item.data["hive"] == "HKCU"
        assert item.data["value_name"] == "SecurityUpdater"
        assert item.data["platform_data"]["winreg_subkeys_count"] == 0

        v_res = EvidenceValidator.validate(item)
        assert v_res.is_valid


# ============================================================================
# 6. Batch CollectorResult Normalization Test
# ============================================================================

class TestCollectorResultBatchNormalization:
    def test_normalize_collector_result(self):
        res = CollectorResult(
            host="TEST-HOST",
            type="process",
            source="win32",
            data=[
                {"pid": 100, "name": "proc1.exe"},
                {"pid": 200, "name": "proc2.exe"},
            ],
            limitations=["Access denied on 1 process"],
            errors=[],
        )
        canonical_items = EvidenceNormalizer.normalize_collector_result(res)
        assert len(canonical_items) == 2
        for it in canonical_items:
            assert it.host == "TEST-HOST"
            assert it.type == "process"
            assert it.data["pid"] in (100, 200)

