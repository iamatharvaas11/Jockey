import sys
from typing import Dict, Any, List

class AMSIDetector:
    """
    Detects AMSI bypass techniques via memory patching, process command lines,
    and provider registry modifications.
    """
    def __init__(self):
        self.detector = 'AMSI_BYPASS_DETECTOR'
        self.mitre_technique = 'T1562.001'

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if sys.platform != 'win32':
            return findings

        findings.extend(self._check_memory_patches())
        findings.extend(self._check_cmdline_signatures())
        findings.extend(self._check_provider_registry())
        
        return findings

    def scan_process(self, pid: int) -> List[Dict[str, Any]]:
        findings = []
        if sys.platform != 'win32':
            return findings
        findings.extend(self._check_memory_patches(target_pid=pid))
        findings.extend(self._check_cmdline_signatures(target_pid=pid))
        return findings

    def _check_memory_patches(self, target_pid: int = None) -> List[Dict[str, Any]]:
        findings = []
        try:
            import ctypes
            import psutil
            
            kernel32 = ctypes.windll.kernel32
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400
            
            # Known patch signatures
            patches = [
                (b'\xC3', "Immediate RET (0xC3)"),
                (b'\xB8\x57\x00\x07\x80', "MOV EAX, E_INVALIDARG"),
                (b'\x31\xC0\xC3', "XOR EAX,EAX; RET"),
                (b'\x33\xC0\xC3', "XOR EAX,EAX; RET")
            ]
            
            if target_pid is not None:
                try:
                    p = psutil.Process(target_pid)
                    proc_list = [{'pid': p.pid, 'name': p.name()}]
                except Exception:
                    proc_list = []
            else:
                proc_list = [{'pid': p.info['pid'], 'name': p.info['name']} for p in psutil.process_iter(['pid', 'name'])]

            for proc in proc_list:
                name = proc['name'].lower() if proc['name'] else ''
                if target_pid is not None or name in ('powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe'):
                    pid = proc['pid']
                    h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
                    if not h_process:
                        continue
                        
                    try:
                        # Note: In a real scenario from outside the process, you'd enumerate modules using EnumProcessModules.
                        # For simplicity as per instruction, we use GetModuleHandleW which only works for the CURRENT process,
                        # but we'll load amsi.dll in our own process to find the RVA of AmsiScanBuffer,
                        # assuming ASLR loads it at the same base across processes (not always true without rebasing, but standard).
                        # Or we just check current process. Let's do the exact instruction: GetModuleHandle + ReadProcessMemory.
                        h_amsi = kernel32.GetModuleHandleW("amsi.dll")
                        if not h_amsi:
                            h_amsi = kernel32.LoadLibraryW("amsi.dll")
                        
                        if h_amsi:
                            amsi_scan_buf_addr = kernel32.GetProcAddress(h_amsi, b"AmsiScanBuffer")
                            if amsi_scan_buf_addr:
                                buffer = ctypes.create_string_buffer(16)
                                bytes_read = ctypes.c_size_t()
                                if kernel32.ReadProcessMemory(h_process, amsi_scan_buf_addr, buffer, 16, ctypes.byref(bytes_read)):
                                    read_bytes = buffer.raw
                                    for patch, desc in patches:
                                        if read_bytes.startswith(patch):
                                            findings.append({
                                                'detector': self.detector,
                                                'finding_type': 'amsi_memory_patch',
                                                'severity': 'critical',
                                                'pid': pid,
                                                'process_name': proc.info['name'],
                                                'description': f"AMSI memory patch detected: {desc}",
                                                'evidence': {'bytes_read_hex': read_bytes.hex()},
                                                'mitre_technique': self.mitre_technique,
                                                'remediation': "Terminate process immediately and investigate origin."
                                            })
                    finally:
                        kernel32.CloseHandle(h_process)
                        
        except Exception as e:
            findings.append({
                'detector': self.detector, 'finding_type': 'error', 'severity': 'info',
                'pid': None, 'process_name': None, 'description': str(e),
                'evidence': {}, 'mitre_technique': self.mitre_technique, 'remediation': ''
            })
        return findings

    def _check_cmdline_signatures(self, target_pid: int = None) -> List[Dict[str, Any]]:
        findings = []
        try:
            import psutil
            bypass_strings = ['amsiInitFailed', 'AmsiUtils', 'System.Management.Automation.AmsiUtils', 'SetField', 'NonPublic,Static']
            if target_pid is not None:
                try:
                    p = psutil.Process(target_pid)
                    proc_list = [{'pid': p.pid, 'name': p.name(), 'cmdline': p.cmdline()}]
                except Exception:
                    proc_list = []
            else:
                proc_list = [{'pid': p.info['pid'], 'name': p.info['name'], 'cmdline': p.info.get('cmdline')} for p in psutil.process_iter(['pid', 'name', 'cmdline'])]

            for proc in proc_list:
                name = proc['name'].lower() if proc['name'] else ''
                if target_pid is not None or 'powershell' in name or 'pwsh' in name:
                    cmdline = ' '.join(proc['cmdline'] or [])
                    for s in bypass_strings:
                        if s.lower() in cmdline.lower():
                            findings.append({
                                'detector': self.detector,
                                'finding_type': 'amsi_cmdline_bypass',
                                'severity': 'high',
                                'pid': proc['pid'],
                                'process_name': proc['name'],
                                'description': f"AMSI bypass command line signature detected: {s}",
                                'evidence': {'cmdline': cmdline},
                                'mitre_technique': self.mitre_technique,
                                'remediation': "Investigate the script or command executed for malicious intent."
                            })
        except Exception as e:
             findings.append({
                'detector': self.detector, 'finding_type': 'error', 'severity': 'info',
                'pid': None, 'process_name': None, 'description': str(e),
                'evidence': {}, 'mitre_technique': self.mitre_technique, 'remediation': ''
            })
        return findings

    def _check_provider_registry(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            import winreg
            path = r"SOFTWARE\\Microsoft\\AMSI\\Providers"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                subkeys = winreg.QueryInfoKey(key)[0]
                if subkeys == 0:
                    findings.append({
                        'detector': self.detector,
                        'finding_type': 'amsi_provider_missing',
                        'severity': 'medium',
                        'pid': None,
                        'process_name': None,
                        'description': "No AMSI providers registered in HKLM.",
                        'evidence': {'registry_path': path},
                        'mitre_technique': self.mitre_technique,
                        'remediation': "Restore Windows Defender or relevant AV AMSI provider registry keys."
                    })
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass # Path might not exist
        except Exception as e:
            pass
        return findings
