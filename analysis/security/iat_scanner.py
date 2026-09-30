import os
from typing import Dict, Any, List

from .pe_parser import PEFile

class IATScanner:
    """
    Scans the Import Address Table of a PE file for suspicious API combinations indicative of malware.
    """
    def __init__(self):
        self.detector = 'IAT_ANOMALY_SCANNER'
        self.mitre_technique = 'T1055.001'

    def scan(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(file_path):
            return findings

        try:
            pe = PEFile(file_path)
            
            # Flatten imports for easier searching
            all_imports = []
            for dll, funcs in pe.imports.items():
                all_imports.extend([f.lower() for f in funcs])
                
            all_dlls = [dll.lower() for dll in pe.imports.keys()]
            
            findings.extend(self._check_injection_cluster(all_imports, file_path))
            findings.extend(self._check_dll_injection_cluster(all_imports, file_path))
            findings.extend(self._check_minimal_imports(all_imports, file_path))
            findings.extend(self._check_suspicious_dll_combos(all_dlls, all_imports, file_path))
            findings.extend(self._check_credential_apis(all_imports, file_path))
            
        except Exception as e:
            findings.append({
                'detector': self.detector, 'finding_type': 'error', 'severity': 'info',
                'pid': None, 'process_name': None, 'description': str(e),
                'evidence': {}, 'mitre_technique': self.mitre_technique, 'remediation': ''
            })
            
        return findings

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        return self.scan(file_path)

    def _check_injection_cluster(self, imports: List[str], file_path: str) -> List[Dict[str, Any]]:
        cluster = {'openprocess', 'virtualallocex', 'writeprocessmemory', 'createremotethread'}
        if cluster.issubset(set(imports)):
            return [{
                'detector': self.detector,
                'finding_type': 'iat_process_injection_cluster',
                'severity': 'high',
                'pid': None,
                'process_name': os.path.basename(file_path),
                'description': "Suspicious process injection API cluster found in IAT.",
                'evidence': {'cluster': list(cluster)},
                'mitre_technique': self.mitre_technique,
                'remediation': "Analyze binary for shellcode or malicious injection behavior."
            }]
        return []

    def _check_dll_injection_cluster(self, imports: List[str], file_path: str) -> List[Dict[str, Any]]:
        cluster1 = {'loadlibrarya', 'getprocaddress', 'createremotethread'}
        cluster2 = {'loadlibraryw', 'getprocaddress', 'createremotethread'}
        if cluster1.issubset(set(imports)) or cluster2.issubset(set(imports)):
            return [{
                'detector': self.detector,
                'finding_type': 'iat_dll_injection_cluster',
                'severity': 'high',
                'pid': None,
                'process_name': os.path.basename(file_path),
                'description': "Suspicious DLL injection API cluster found in IAT.",
                'evidence': {'apis_found': True},
                'mitre_technique': self.mitre_technique,
                'remediation': "Analyze binary for malicious DLL loading."
            }]
        return []

    def _check_minimal_imports(self, imports: List[str], file_path: str) -> List[Dict[str, Any]]:
        has_loader = any('loadlibrary' in i for i in imports) and 'getprocaddress' in imports
        if len(imports) < 5 and has_loader:
            return [{
                'detector': self.detector,
                'finding_type': 'iat_minimal_imports',
                'severity': 'medium',
                'pid': None,
                'process_name': os.path.basename(file_path),
                'description': "Binary has very few imports but includes dynamic loading APIs (packer/dropper signature).",
                'evidence': {'import_count': len(imports)},
                'mitre_technique': 'T1027',
                'remediation': "Binary is likely packed. Unpack and analyze."
            }]
        return []

    def _check_suspicious_dll_combos(self, dlls: List[str], imports: List[str], file_path: str) -> List[Dict[str, Any]]:
        if 'wininet.dll' in dlls and 'ws2_32.dll' in dlls and ('createprocessa' in imports or 'createprocessw' in imports):
            return [{
                'detector': self.detector,
                'finding_type': 'iat_network_execution_combo',
                'severity': 'medium',
                'pid': None,
                'process_name': os.path.basename(file_path),
                'description': "Binary combines networking and process execution APIs (potential downloader/C2).",
                'evidence': {'dlls': ['wininet.dll', 'ws2_32.dll']},
                'mitre_technique': 'T1105',
                'remediation': "Analyze binary network traffic."
            }]
        return []

    def _check_credential_apis(self, imports: List[str], file_path: str) -> List[Dict[str, Any]]:
        cred_apis = {'lsaenumeratelogonsessions', 'openprocesstoken', 'adjusttokenprivileges'}
        found = cred_apis.intersection(set(imports))
        if found:
            return [{
                'detector': self.detector,
                'finding_type': 'iat_credential_dumping_apis',
                'severity': 'medium',
                'pid': None,
                'process_name': os.path.basename(file_path),
                'description': "Binary imports APIs associated with credential access/token manipulation.",
                'evidence': {'apis_found': list(found)},
                'mitre_technique': 'T1003',
                'remediation': "Analyze for LSASS dumping or privilege escalation."
            }]
        return []
