"""
Tests for JOCKY Stage 4 Runtime and Normalized Collectors
Covers runtime initialization, adapter selection, collector contracts,
error resilience, and platform-specific behaviors.
"""
import hashlib
import os
import platform
import sys
import tempfile
from unittest.mock import MagicMock, patch

import psutil
import pytest

from collectors.base import (
    BaseCollector,
    CollectionError,
    CollectorResult,
    CollectorStatus,
    EvidenceItem,
)
from collectors.eventlog_collector import EventLogCollector
from collectors.file_collector import FileCollector
from collectors.linux_collector import LinuxCollector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from collectors.registry_collector import RegistryCollector
from runtime.adapters import (
    ForensicAdapter,
    LinuxAdapter,
    WindowsAdapter,
    get_platform_adapter,
)
from runtime.forensic_runtime import ForensicRuntime, RuntimeContext


# ============================================================================
# 1. Runtime Architecture & Adapter Selection Tests
# ============================================================================

class TestRuntimeArchitecture:
    def test_adapter_selection_windows(self):
        adapter = get_platform_adapter(force_os="windows")
        assert isinstance(adapter, WindowsAdapter)

    def test_adapter_selection_linux(self):
        adapter = get_platform_adapter(force_os="linux")
        assert isinstance(adapter, LinuxAdapter)

    def test_runtime_initialization(self):
        rt = ForensicRuntime()
        assert rt.adapter is not None
        assert rt.context is not None
        assert rt.context.hostname != ""

    def test_runtime_collector_dispatch(self):
        rt = ForensicRuntime()
        proc_res = rt.scan_processes()
        assert isinstance(proc_res, CollectorResult)
        assert "processes" in rt.context.collected_evidence
        assert len(rt.context.collected_evidence["processes"]) == len(proc_res)

    def test_runtime_collection_query_protocol(self):
        rt = ForensicRuntime()
        # Source 1 is PROCESSES
        items = rt.get_collection(1)
        assert isinstance(items, list)
        assert len(items) > 0
        assert "pid" in items[0]

    def test_runtime_export_report(self):
        rt = ForensicRuntime()
        rt.scan_processes()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "test_rep.json")
            rt.export_report(out_file)
            assert os.path.exists(out_file)
            assert os.path.getsize(out_file) > 0

    def test_runtime_error_resilience(self):
        """Simulate a failing adapter method; runtime must record error without aborting."""
        mock_adapter = MagicMock(spec=ForensicAdapter)
        mock_adapter.scan_processes.return_value = CollectorResult(
            type="process",
            status=CollectorStatus.FAILED,
            errors=["Mocked kernel timeout"],
            limitations=["Incomplete scan"],
        )
        rt = ForensicRuntime(adapter=mock_adapter)
        res = rt.scan_processes()
        assert res.status == CollectorStatus.FAILED
        assert "Mocked kernel timeout" in rt.context.errors
        assert "Incomplete scan" in rt.context.limitations


# ============================================================================
# 2. Process Collector Tests
# ============================================================================

class TestProcessCollectorStage4:
    def test_process_collection_normalization(self):
        col = ProcessCollector()
        res = col.collect()
        assert isinstance(res, CollectorResult)
        assert res.type == "process"
        assert res.status in (CollectorStatus.SUCCESS, CollectorStatus.PARTIAL)
        assert len(res) > 0
        p = res[0]
        for key in ["pid", "ppid", "name", "exe_path", "exe_hash", "username", "status"]:
            assert key in p, f"Missing normalized process field: {key}"

    def test_process_access_denied_handling(self):
        """When psutil raises AccessDenied on username, collector notes limitation and continues."""
        col = ProcessCollector()
        with patch.object(psutil.Process, "username", side_effect=psutil.AccessDenied()):
            res = col.collect()
            assert isinstance(res, CollectorResult)
            # Must not crash, should complete collection
            assert len(res) > 0
            assert any("Elevated privileges" in lim or "denied" in lim.lower() for lim in res.limitations)


# ============================================================================
# 3. File Collector Tests
# ============================================================================

class TestFileCollectorStage4:
    def test_file_hashing_real(self):
        col = FileCollector()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"JOCKY Forensic Evidence File Hash Test 12345")
            tmp_path = f.name

        try:
            expected_sha256 = hashlib.sha256(b"JOCKY Forensic Evidence File Hash Test 12345").hexdigest()
            hashes = col.hash_file(tmp_path)
            assert hashes["sha256"] == expected_sha256
        finally:
            os.remove(tmp_path)

    def test_file_missing_handling(self):
        col = FileCollector()
        res = col.collect(paths=["/path/that/does/not/exist_12345"])
        assert isinstance(res, CollectorResult)
        assert any("does not exist" in lim for lim in res.limitations)
        assert len(res) == 0

    def test_file_permission_denied_handling(self):
        col = FileCollector()
        with patch("builtins.open", side_effect=PermissionError("Locked file")):
            hashes = col.hash_file("C:\\Windows\\System32\\mock_locked.sys")
            assert hashes["sha256"] is None
            assert hashes["md5"] is None


# ============================================================================
# 4. Network Collector Tests
# ============================================================================

class TestNetworkCollectorStage4:
    def test_network_collection_normalization(self):
        col = NetworkCollector()
        res = col.collect()
        assert isinstance(res, CollectorResult)
        assert res.type == "network"
        if len(res) > 0:
            c = res[0]
            for key in ["protocol", "local_ip", "local_port", "remote_ip", "remote_port", "status", "pid"]:
                assert key in c, f"Missing normalized network field: {key}"

    def test_network_permission_denied_handling(self):
        col = NetworkCollector()
        with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
            res = col.collect()
            assert res.status == CollectorStatus.FAILED
            assert len(res.errors) > 0
            assert any("denied" in e.lower() or "privileges" in e.lower() for e in res.errors)


# ============================================================================
# 5. Event Log Collector Tests
# ============================================================================

class TestEventLogCollectorStage4:
    def test_eventlog_non_windows_unsupported(self):
        col = EventLogCollector()
        col.is_windows = False
        res = col.collect()
        assert res.status == CollectorStatus.UNSUPPORTED
        assert any("not available" in lim.lower() for lim in res.limitations)

    def test_eventlog_missing_win32evtlog(self):
        col = EventLogCollector()
        col.is_windows = True
        col.win32evtlog = None
        res = col.collect()
        assert res.status == CollectorStatus.FAILED
        assert any("pywin32" in e for e in res.errors)


# ============================================================================
# 6. Registry Collector Tests
# ============================================================================

class TestRegistryCollectorStage4:
    def test_registry_windows_support(self):
        if sys.platform != "win32":
            pytest.skip("Windows only test")
        col = RegistryCollector()
        res = col.collect_run_keys()
        assert isinstance(res, CollectorResult)
        assert res.type == "registry"

    def test_registry_linux_unsupported(self):
        col = RegistryCollector()
        col.is_windows = False
        res = col.collect_run_keys()
        assert res.status == CollectorStatus.UNSUPPORTED
        assert any("only supported on windows" in lim.lower() for lim in res.limitations)


# ============================================================================
# 7. Platform Adapter Tests
# ============================================================================

class TestPlatformAdaptersStage4:
    def test_windows_adapter_methods(self):
        if sys.platform != "win32":
            pytest.skip("Windows only test")
        adapter = WindowsAdapter()
        assert isinstance(adapter.scan_processes(), CollectorResult)
        assert isinstance(adapter.scan_network(), CollectorResult)
        info = adapter.get_system_info()
        assert info["os"] == "Windows"
        assert info["adapter"] == "WindowsAdapter"

    def test_linux_adapter_instantiation_and_methods(self):
        """Verify LinuxAdapter fixes the legacy broken imports and instantiates cleanly."""
        adapter = LinuxAdapter()
        assert adapter is not None
        # On non-Linux host, registry must report UNSUPPORTED
        reg_res = adapter.scan_registry()
        assert reg_res.status == CollectorStatus.UNSUPPORTED
        info = adapter.get_system_info()
        assert info["adapter"] == "LinuxAdapter"

    def test_linux_collector_proc_on_non_linux(self):
        col = LinuxCollector()
        col.is_linux = False
        res = col.collect_proc_processes()
        assert res.status == CollectorStatus.UNSUPPORTED

