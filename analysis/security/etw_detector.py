import sys
import os
from typing import Dict, Any, List

class ETWDetector:
    """
    Detects ETW tampering techniques like memory patches, environment variable disablement,
    and autologger registry modifications.
    """
    def __init__(self):
        self.detector = 'ETW_TAMPERING_DETECTOR'
        self.mitre_technique = 'T1562.006'

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if sys.platform != 'win32':
            return findings

        findings.extend(self._check_etw_patches())
        findings.extend(self._check_env_variables())
        findings.extend(self._check_autologger_sessions())
        
        return findings

    def scan_process(self, pid: int) -> List[Dict[str, Any]]:
        findings = []
        if sys.platform != 'win32':
            return findings
        findings.extend(self._check_etw_patches(target_pid=pid))
        findings.extend(self._check_env_variables(target_pid=pid))
        return findings

    def _check_etw_patches(self, target_pid: int = None) -> List[Dict[str, Any]]:
        findings = []
        try:
            import ctypes
            import psutil
            
            kernel32 = ctypes.windll.kernel32
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400
            
            patches = [
                (b'\xC3', "Immediate RET (0xC3)"),
                (b'\x33\xC0\xC3', "XOR EAX,EAX; RET"),
                (b'\x48\x33\xC0\xC3', "XOR RAX,RAX; RET")
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
                pid = proc['pid']
                if pid <= 4:
                    continue
                try:
                    h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
                    if not h_process:
                        continue
                        
                    h_ntdll = kernel32.GetModuleHandleW("ntdll.dll")
                    if h_ntdll:
                        etw_addr = kernel32.GetProcAddress(h_ntdll, b"EtwEventWrite")
                        if etw_addr:
                            buffer = ctypes.create_string_buffer(16)
                            bytes_read = ctypes.c_size_t()
                            if kernel32.ReadProcessMemory(h_process, etw_addr, buffer, 16, ctypes.byref(bytes_read)):
                                read_bytes = buffer.raw
                                for patch, desc in patches:
                                    if read_bytes.startswith(patch):
                                        findings.append({
                                            'detector': self.detector,
                                            'finding_type': 'etw_memory_patch',
                                            'severity': 'critical',
                                            'pid': pid,
                                            'process_name': proc.info['name'],
                                            'description': f"ETW EtwEventWrite memory patch detected: {desc}",
                                            'evidence': {'bytes_read_hex': read_bytes.hex()},
                                            'mitre_technique': self.mitre_technique,
                                            'remediation': "Process may be evading logging. Terminate and investigate."
                                        })
                except Exception:
                    pass
                finally:
                    if 'h_process' in locals() and h_process:
                        kernel32.CloseHandle(h_process)
        except Exception as e:
            findings.append({
                'detector': self.detector, 'finding_type': 'error', 'severity': 'info',
                'pid': None, 'process_name': None, 'description': str(e),
                'evidence': {}, 'mitre_technique': self.mitre_technique, 'remediation': ''
            })
        return findings

    def _check_env_variables(self, target_pid: int = None) -> List[Dict[str, Any]]:
        findings = []
        try:
            import psutil
            if target_pid is not None:
                try:
                    p = psutil.Process(target_pid)
                    proc_list = [{'pid': p.pid, 'name': p.name(), 'environ': p.environ()}]
                except Exception:
                    proc_list = []
            else:
                proc_list = [{'pid': p.info['pid'], 'name': p.info['name'], 'environ': p.info.get('environ')} for p in psutil.process_iter(['pid', 'name', 'environ'])]

            for proc in proc_list:
                env = proc.get('environ')
                if env and env.get('COMPlus_ETWEnabled') == '0':
                    findings.append({
                        'detector': self.detector,
                        'finding_type': 'etw_env_disabled',
                        'severity': 'high',
                        'pid': proc['pid'],
                        'process_name': proc['name'],
                        'description': "Process launched with COMPlus_ETWEnabled=0 to bypass .NET ETW telemetry.",
                        'evidence': {'COMPlus_ETWEnabled': '0'},
                        'mitre_technique': self.mitre_technique,
                        'remediation': "Investigate process origin. Remove environment variable injection."
                    })
        except Exception as e:
            pass
        return findings

    def _check_autologger_sessions(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            import winreg
            base_path = r"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
            num_subkeys = winreg.QueryInfoKey(key)[0]
            
            for i in range(num_subkeys):
                subkey_name = winreg.EnumKey(key, i)
                if subkey_name in ('EventLog-System', 'EventLog-Application', 'EventLog-Security'):
                    try:
                        subkey = winreg.OpenKey(key, subkey_name)
                        start_val, _ = winreg.QueryValueEx(subkey, "Start")
                        if start_val == 0:
                            findings.append({
                                'detector': self.detector,
                                'finding_type': 'etw_autologger_disabled',
                                'severity': 'high',
                                'pid': None,
                                'process_name': None,
                                'description': f"Critical ETW Autologger session disabled: {subkey_name}",
                                'evidence': {'session': subkey_name, 'Start': start_val},
                                'mitre_technique': self.mitre_technique,
                                'remediation': "Enable autologger session via registry."
                            })
                        winreg.CloseKey(subkey)
                    except FileNotFoundError:
                        pass
            winreg.CloseKey(key)
        except Exception as e:
            pass
        return findings
