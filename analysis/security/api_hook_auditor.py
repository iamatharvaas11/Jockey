import sys
import os
from typing import Dict, Any, List

from .pe_parser import PEFile

class APIHookAuditor:
    """
    Audits memory for inline API hooks by comparing in-memory functions to their on-disk PE equivalents.
    """
    def __init__(self):
        self.detector = 'API_HOOK_AUDITOR'
        self.mitre_technique = 'T1055'

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if sys.platform != 'win32':
            return findings

        target_dlls = ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']
        critical_funcs = [
            'NtCreateFile', 'NtOpenProcess', 'NtAllocateVirtualMemory', 
            'NtWriteVirtualMemory', 'NtCreateThreadEx', 'NtMapViewOfSection', 
            'NtProtectVirtualMemory', 'NtReadVirtualMemory', 'NtCreateSection', 'NtQueueApcThread'
        ]

        for dll in target_dlls:
            findings.extend(self._audit_dll(dll, critical_funcs))
            
        return findings

    def scan_process(self, pid: int) -> List[Dict[str, Any]]:
        findings = []
        if sys.platform != 'win32':
            return findings

        target_dlls = ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']
        critical_funcs = [
            'NtCreateFile', 'NtOpenProcess', 'NtAllocateVirtualMemory', 
            'NtWriteVirtualMemory', 'NtCreateThreadEx', 'NtMapViewOfSection', 
            'NtProtectVirtualMemory', 'NtReadVirtualMemory', 'NtCreateSection', 'NtQueueApcThread'
        ]

        for dll in target_dlls:
            findings.extend(self._audit_dll(dll, critical_funcs, target_pid=pid))
            
        return findings

    def _audit_dll(self, dll_name: str, function_names: List[str], target_pid: int = None) -> List[Dict[str, Any]]:
        findings = []
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            disk_path = f"C:\\Windows\\System32\\{dll_name}"
            if not os.path.exists(disk_path):
                return findings
                
            pe = PEFile(disk_path)
            
            h_module = kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = kernel32.LoadLibraryW(dll_name)
                
            if not h_module:
                return findings
                
            h_process = None
            if target_pid is not None and target_pid != os.getpid():
                PROCESS_VM_READ = 0x0010
                PROCESS_QUERY_INFORMATION = 0x0400
                h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, target_pid)
                if not h_process:
                    return findings

            try:
                for func in function_names:
                    func_addr = kernel32.GetProcAddress(h_module, func.encode('ascii'))
                    if not func_addr:
                        continue
                        
                    mem_buf = ctypes.create_string_buffer(16)
                    if h_process:
                        bytes_read = ctypes.c_size_t()
                        if not kernel32.ReadProcessMemory(h_process, func_addr, mem_buf, 16, ctypes.byref(bytes_read)):
                            continue
                    else:
                        ctypes.memmove(mem_buf, func_addr, 16)
                    mem_bytes = mem_buf.raw
                    
                    is_hooked = False
                    hook_type = "Unknown"
                    
                    if mem_bytes[0] == 0xE9:
                        is_hooked = True
                        hook_type = "JMP rel32 (Inline Hook)"
                    elif mem_bytes[0] == 0xFF and mem_bytes[1] == 0x25:
                        is_hooked = True
                        hook_type = "JMP [rip+disp32]"
                    elif mem_bytes.startswith(b'\x48\xB8') and b'\xFF\xE0' in mem_bytes[:16]:
                        is_hooked = True
                        hook_type = "MOV RAX, addr; JMP RAX"
                        
                    if is_hooked:
                        findings.append({
                            'detector': self.detector,
                            'finding_type': 'api_hook_detected',
                            'severity': 'critical',
                            'pid': target_pid or os.getpid(),
                            'process_name': f'PID:{target_pid}' if target_pid else 'current_process',
                            'description': f"Inline API hook detected in {dll_name}!{func}: {hook_type}",
                            'evidence': {'function': func, 'mem_bytes_hex': mem_bytes.hex()},
                            'mitre_technique': self.mitre_technique,
                            'remediation': "Investigate process injection or EDR hooking. Validate hook legitimacy."
                        })
            finally:
                if h_process:
                    kernel32.CloseHandle(h_process)
                    
        except Exception as e:
            findings.append({
                'detector': self.detector, 'finding_type': 'error', 'severity': 'info',
                'pid': None, 'process_name': None, 'description': str(e),
                'evidence': {}, 'mitre_technique': self.mitre_technique, 'remediation': ''
            })
        return findings
