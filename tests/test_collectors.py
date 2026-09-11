"""
Tests for forensic evidence collectors.
Tests actual data collection functionality where available on the current platform.
"""
import pytest
import sys
import os


class TestProcessCollector:
    """Tests for the process collector."""

    def test_import(self):
        """Process collector should be importable."""
        from collectors.process_collector import ProcessCollector
        assert ProcessCollector is not None

    def test_instantiation(self):
        """Process collector should instantiate without error."""
        from collectors.process_collector import ProcessCollector
        collector = ProcessCollector()
        assert collector is not None

    def test_collect_returns_list(self):
        """collect() should return a list of process records."""
        from collectors.process_collector import ProcessCollector
        collector = ProcessCollector()
        result = collector.collect()
        assert isinstance(result, list)
        assert len(result) > 0, "Should find at least one running process"

    def test_process_record_has_required_fields(self):
        """Each process record should have minimum required fields."""
        from collectors.process_collector import ProcessCollector
        collector = ProcessCollector()
        result = collector.collect()
        required_fields = {"pid", "name"}
        for proc in result[:5]:  # Check first 5 to avoid timeout
            for field in required_fields:
                assert field in proc, f"Process record missing field: {field}"

    def test_pid_is_integer(self):
        """Process PIDs should be integers."""
        from collectors.process_collector import ProcessCollector
        collector = ProcessCollector()
        result = collector.collect()
        for proc in result[:5]:
            assert isinstance(proc["pid"], int), f"PID should be int, got {type(proc['pid'])}"


class TestFileCollector:
    """Tests for the file collector."""

    def test_import(self):
        """File collector should be importable."""
        from collectors.file_collector import FileCollector
        assert FileCollector is not None

    def test_instantiation(self):
        """File collector should instantiate without error."""
        from collectors.file_collector import FileCollector
        collector = FileCollector()
        assert collector is not None

    def test_collect_returns_list(self):
        """scan_directory() should return a list of file records."""
        from collectors.file_collector import FileCollector
        collector = FileCollector()
        examples_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "examples"
        )
        result = collector.scan_directory(examples_dir)
        assert isinstance(result, list)
        assert len(result) > 0, "Should find files in examples directory"

    def test_file_record_has_path(self):
        """Each file record should have a path field."""
        from collectors.file_collector import FileCollector
        collector = FileCollector()
        examples_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "examples"
        )
        result = collector.scan_directory(examples_dir)
        for rec in result:
            assert "path" in rec or "file_path" in rec, \
                f"File record missing path field. Keys: {list(rec.keys())}"


class TestNetworkCollector:
    """Tests for the network collector."""

    def test_import(self):
        """Network collector should be importable."""
        from collectors.network_collector import NetworkCollector
        assert NetworkCollector is not None

    def test_instantiation(self):
        """Network collector should instantiate without error."""
        from collectors.network_collector import NetworkCollector
        collector = NetworkCollector()
        assert collector is not None

    def test_collect_connections_returns_list(self):
        """collect_connections() should return network connections."""
        from collectors.network_collector import NetworkCollector
        collector = NetworkCollector()
        result = collector.collect_connections()
        assert isinstance(result, list)

    def test_collect_interfaces_returns_list(self):
        """collect_interfaces() should return network interfaces."""
        from collectors.network_collector import NetworkCollector
        collector = NetworkCollector()
        result = collector.collect_interfaces()
        assert isinstance(result, list)
        assert len(result) > 0, "Should find at least one network interface"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only collector")
class TestEventLogCollector:
    """Tests for the Windows event log collector."""

    def test_import(self):
        """Event log collector should be importable."""
        from collectors.eventlog_collector import EventLogCollector
        assert EventLogCollector is not None

    def test_instantiation(self):
        """Event log collector should instantiate without error."""
        from collectors.eventlog_collector import EventLogCollector
        collector = EventLogCollector()
        assert collector is not None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only collector")
class TestRegistryCollector:
    """Tests for the Windows registry collector."""

    def test_import(self):
        """Registry collector should be importable."""
        from collectors.registry_collector import RegistryCollector
        assert RegistryCollector is not None

    def test_instantiation(self):
        """Registry collector should instantiate without error."""
        from collectors.registry_collector import RegistryCollector
        collector = RegistryCollector()
        assert collector is not None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only collector")
class TestLinuxCollector:
    """Tests for the Linux collector."""

    def test_import(self):
        """Linux collector should be importable."""
        from collectors.linux_collector import LinuxCollector
        assert LinuxCollector is not None
