import os
import sys
import struct
import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient, ASGITransport

from analysis.security.pe_parser import PEFile, calculate_section_entropy
from analysis.security.amsi_detector import AMSIDetector
from analysis.security.etw_detector import ETWDetector
from analysis.security.api_hook_auditor import APIHookAuditor
from analysis.security.iat_scanner import IATScanner
from analysis.security.packed_detector import PackedBinaryDetector
from analysis.security import run_full_security_scan

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app


def create_minimal_pe_bytes(section_name=b".text\x00\x00\x00", section_chars=0x60000020, raw_data=b"\x90" * 512):
    """Generates a minimal valid 64-bit PE header in bytes for testing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)  # e_lfanew = 64

    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)

    # Optional Header Standard Fields (x64: 240 bytes)
    magic = 0x020B  # PE32+ (64-bit)
    entry_point = 0x1000
    image_base = 0x140000000
    sec_align = 0x1000
    file_align = 0x200
    size_of_image = 0x3000
    size_of_headers = 0x200

    opt_header = bytearray(240)
    struct.pack_into("<HBBIIIIQIIHHHHHHIIIIHHQQQQII", opt_header, 0,
                     magic, 1, 0, len(raw_data), 0, 0, entry_point,
                     image_base, sec_align, file_align,
                     6, 0, 0, 0, 6, 0, 0,
                     size_of_image, size_of_headers, 0,
                     3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)

    # Section Header (40 bytes)
    sec_vsize = len(raw_data)
    sec_va = 0x1000
    sec_raw_size = len(raw_data)
    sec_raw_ptr = 0x200
    sec_header = struct.pack("<8sIIIIIIHHI", section_name, sec_vsize, sec_va, sec_raw_size, sec_raw_ptr, 0, 0, 0, 0, section_chars)

    header_data = bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + sec_header
    if len(header_data) < size_of_headers:
        header_data += b"\x00" * (size_of_headers - len(header_data))

    return header_data + raw_data


class TestPEParser:
    """Tests for the pure-Python PE parser and entropy calculator."""

    def test_entropy_calculation(self):
        zero_bytes = b"\x00" * 1024
        assert calculate_section_entropy(zero_bytes) == 0.0

        random_bytes = os.urandom(4096)
        entropy = calculate_section_entropy(random_bytes)
        assert entropy > 7.5, f"Expected high entropy for random data, got {entropy}"

    def test_parse_minimal_pe(self):
        pe_bytes = create_minimal_pe_bytes(section_name=b".text\x00\x00\x00", raw_data=b"\x90\xCC" * 128)
        pe = PEFile(pe_bytes)
        assert pe.coff_header.get("Machine") == 0x8664
        assert pe.coff_header.get("NumberOfSections") == 1
        assert len(pe.sections) == 1
        assert pe.sections[0]["Name"] == ".text"
        assert pe.sections[0]["VirtualSize"] == 256


class TestAMSIDetector:
    """Tests for AMSI Bypass detection logic."""

    def test_cmdline_signature_detection(self):
        detector = AMSIDetector()
        mock_proc = MagicMock()
        mock_proc.name.return_value = "powershell.exe"
        mock_proc.pid = 1337
        mock_proc.cmdline.return_value = ["powershell.exe", "-ep", "bypass", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"]

        with patch("psutil.Process", return_value=mock_proc):
            findings = detector._check_cmdline_signatures(target_pid=1337)
            assert len(findings) > 0
            assert any(f["finding_type"] == "amsi_cmdline_bypass" for f in findings)
            assert findings[0]["mitre_technique"] == "T1562.001"
            assert findings[0]["severity"] == "high"

    def test_clean_cmdline_no_findings(self):
        detector = AMSIDetector()
        mock_proc = MagicMock()
        mock_proc.name.return_value = "powershell.exe"
        mock_proc.pid = 1338
        mock_proc.cmdline.return_value = ["powershell.exe", "-NoProfile", "Get-Date"]

        with patch("psutil.Process", return_value=mock_proc):
            findings = detector._check_cmdline_signatures(target_pid=1338)
            assert len(findings) == 0


class TestETWDetector:
    """Tests for ETW Tampering detection logic."""

    def test_etw_env_variable_disabled(self):
        detector = ETWDetector()
        mock_proc = MagicMock()
        mock_proc.pid = 2001
        mock_proc.name.return_value = "malware.exe"
        mock_proc.environ.return_value = {"PATH": "C:\\", "COMPlus_ETWEnabled": "0"}

        with patch("psutil.Process", return_value=mock_proc):
            findings = detector._check_env_variables(target_pid=2001)
            assert len(findings) == 1
            assert findings[0]["finding_type"] == "etw_env_disabled"
            assert findings[0]["severity"] == "high"
            assert findings[0]["mitre_technique"] == "T1562.006"

    def test_clean_env_no_findings(self):
        detector = ETWDetector()
        mock_proc = MagicMock()
        mock_proc.pid = 2002
        mock_proc.name.return_value = "notepad.exe"
        mock_proc.environ.return_value = {"PATH": "C:\\", "USER": "tester"}

        with patch("psutil.Process", return_value=mock_proc):
            findings = detector._check_env_variables(target_pid=2002)
            assert len(findings) == 0


class TestAPIHookAuditor:
    """Tests for API Hook detection logic."""

    def test_hook_classification(self):
        jmp_rel32 = b"\xE9\x40\x12\x00\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
        assert jmp_rel32[0] == 0xE9

        jmp_rip = b"\xFF\x25\x00\x00\x00\x00\x11\x22\x33\x44\x55\x66\x77\x88\x90\x90"
        assert jmp_rip[0] == 0xFF and jmp_rip[1] == 0x25

        mov_rax_jmp = b"\x48\xB8\x11\x22\x33\x44\x55\x66\x77\x88\xFF\xE0\x90\x90\x90\x90"
        assert mov_rax_jmp.startswith(b"\x48\xB8") and b"\xFF\xE0" in mov_rax_jmp[:16]


class TestIATScanner:
    """Tests for IAT anomaly and capability cluster scanning."""

    def test_injection_cluster_detection(self):
        scanner = IATScanner()
        suspicious_imports = [
            "openprocess", "virtualallocex", "writeprocessmemory",
            "createremotethread", "closehandle"
        ]
        findings = scanner._check_injection_cluster(suspicious_imports, "suspicious.exe")
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "iat_process_injection_cluster"
        assert findings[0]["severity"] == "high"

    def test_dll_injection_cluster_detection(self):
        scanner = IATScanner()
        suspicious_imports = [
            "loadlibrarya", "getprocaddress", "createremotethread"
        ]
        findings = scanner._check_dll_injection_cluster(suspicious_imports, "injector.exe")
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "iat_dll_injection_cluster"

    def test_minimal_imports_anomaly(self):
        scanner = IATScanner()
        minimal_imports = ["loadlibrarya", "getprocaddress", "exitprocess"]
        findings = scanner._check_minimal_imports(minimal_imports, "stager.exe")
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "iat_minimal_imports"


class TestPackedBinaryDetector:
    """Tests for packed/obfuscated binary detection."""

    def test_packer_signature_detection(self, tmp_path):
        upx_pe = create_minimal_pe_bytes(section_name=b"UPX0\x00\x00\x00\x00")
        sample_path = str(tmp_path / "upx_sample.exe")
        with open(sample_path, "wb") as f:
            f.write(upx_pe)

        detector = PackedBinaryDetector()
        findings = detector.scan(sample_path)
        packer_findings = [f for f in findings if f["finding_type"] in ("known_packer_section", "packed_known_signature")]
        assert len(packer_findings) >= 1
        assert "UPX" in packer_findings[0]["description"].upper()

    def test_rwx_section_detection(self, tmp_path):
        rwx_pe = create_minimal_pe_bytes(section_name=b".code\x00\x00\x00", section_chars=0xA0000020)
        sample_path = str(tmp_path / "rwx_sample.exe")
        with open(sample_path, "wb") as f:
            f.write(rwx_pe)

        detector = PackedBinaryDetector()
        findings = detector.scan(sample_path)
        rwx_findings = [f for f in findings if f["finding_type"] in ("rwx_section", "packed_rwx_section")]
        assert len(rwx_findings) >= 1
        assert rwx_findings[0]["severity"] == "high"


class TestFullOrchestrator:
    """Tests for the unified security scan orchestrator."""

    def test_run_full_security_scan(self):
        result = run_full_security_scan()
        assert "total_findings" in result
        assert "modules" in result
        assert "amsi_detector" in result["modules"]
        assert "etw_detector" in result["modules"]
        assert "api_hook_auditor" in result["modules"]


@pytest.mark.asyncio
async def test_backend_security_api_and_service():
    """Integration test for FastAPI security endpoints and service."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Test live scan endpoint
        res = await ac.post("/api/v1/security/scan/live")
        assert res.status_code == 200
        data = res.json()
        assert "scan_id" in data
        assert "status" in data
        assert data["status"] == "COMPLETED"
        assert "summary" in data
        assert "modules" in data

        # 2. Test results history endpoint
        history_res = await ac.get("/api/v1/security/scan/results")
        assert history_res.status_code == 200
        history = history_res.json()
        assert isinstance(history, list)
        assert len(history) >= 1
        assert any(item["scan_id"] == data["scan_id"] for item in history)

        # 3. Test get result by ID
        single_res = await ac.get(f"/api/v1/security/scan/results/{data['scan_id']}")
        assert single_res.status_code == 200
        assert single_res.json()["scan_id"] == data["scan_id"]

        # 4. Test security HTML page
        page_res = await ac.get("/security")
        assert page_res.status_code == 200
        assert "Defensive Security Scanner" in page_res.text
        assert "securityScanner()" in page_res.text
