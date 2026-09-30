import os
from typing import Dict, Any, List

from .pe_parser import PEFile, calculate_section_entropy

class PackedBinaryDetector:
    """
    Detects signs of packing in PE files using section entropy, size discrepancies,
    known packer names, and structural anomalies.
    """
    def __init__(self):
        self.detector = 'PACKED_BINARY_DETECTOR'
        self.mitre_technique = 'T1027.002'

    def scan(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(file_path):
            return findings

        try:
            pe = PEFile(file_path)
            
            findings.extend(self._check_section_entropy(pe, file_path))
            findings.extend(self._check_size_discrepancy(pe, file_path))
            findings.extend(self._check_packer_signatures(pe, file_path))
            findings.extend(self._check_rwx_sections(pe, file_path))
            findings.extend(self._check_overlay(pe, file_path))
            
        except Exception as e:
            findings.append({
                'detector': self.detector, 'finding_type': 'error', 'severity': 'info',
                'pid': None, 'process_name': None, 'description': str(e),
                'evidence': {}, 'mitre_technique': self.mitre_technique, 'remediation': ''
            })
            
        return findings

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        return self.scan(file_path)

    def _check_section_entropy(self, pe: PEFile, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        for sec in pe.sections:
            if sec['Characteristics'] & IMAGE_SCN_MEM_EXECUTE:
                offset = sec['PointerToRawData']
                size = sec['SizeOfRawData']
                if size > 0 and offset + size <= len(pe.data):
                    entropy = calculate_section_entropy(pe.data[offset:offset+size])
                    if entropy > 7.0:
                        findings.append({
                            'detector': self.detector,
                            'finding_type': 'high_entropy_section',
                            'severity': 'high',
                            'pid': None,
                            'process_name': os.path.basename(file_path),
                            'description': f"Executable section '{sec['Name']}' has high entropy ({entropy:.2f}), indicating it is packed or encrypted.",
                            'evidence': {'section': sec['Name'], 'entropy': entropy},
                            'mitre_technique': self.mitre_technique,
                            'remediation': "Unpack binary to analyze underlying code."
                        })
        return findings

    def _check_size_discrepancy(self, pe: PEFile, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        for sec in pe.sections:
            if sec['SizeOfRawData'] > 0:
                if sec['VirtualSize'] > 3 * sec['SizeOfRawData']:
                    findings.append({
                        'detector': self.detector,
                        'finding_type': 'abnormal_section_size',
                        'severity': 'medium',
                        'pid': None,
                        'process_name': os.path.basename(file_path),
                        'description': f"Section '{sec['Name']}' virtual size is significantly larger than raw size (unpacking stub indicator).",
                        'evidence': {'section': sec['Name'], 'VirtualSize': sec['VirtualSize'], 'SizeOfRawData': sec['SizeOfRawData']},
                        'mitre_technique': self.mitre_technique,
                        'remediation': "Analyze memory execution of this section."
                    })
        return findings

    def _check_packer_signatures(self, pe: PEFile, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        known_packers = ['upx0', 'upx1', '.aspack', '.themida', '.vmp0', '.vmp1', '.mpress', 'pec1', 'pec2', '.enigma', '.petite', '.nsp0', '.nsp1']
        for sec in pe.sections:
            name_lower = sec['Name'].lower()
            if any(p in name_lower for p in known_packers):
                findings.append({
                    'detector': self.detector,
                    'finding_type': 'known_packer_section',
                    'severity': 'high',
                    'pid': None,
                    'process_name': os.path.basename(file_path),
                    'description': f"Known packer section name detected: '{sec['Name']}'.",
                    'evidence': {'section': sec['Name']},
                    'mitre_technique': self.mitre_technique,
                    'remediation': "Use appropriate unpacking tools for analysis."
                })
        return findings

    def _check_rwx_sections(self, pe: PEFile, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        IMAGE_SCN_MEM_WRITE = 0x80000000
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        for sec in pe.sections:
            if (sec['Characteristics'] & IMAGE_SCN_MEM_WRITE) and (sec['Characteristics'] & IMAGE_SCN_MEM_EXECUTE):
                findings.append({
                    'detector': self.detector,
                    'finding_type': 'rwx_section',
                    'severity': 'high',
                    'pid': None,
                    'process_name': os.path.basename(file_path),
                    'description': f"Section '{sec['Name']}' has RWX (Read/Write/Execute) permissions.",
                    'evidence': {'section': sec['Name'], 'Characteristics': hex(sec['Characteristics'])},
                    'mitre_technique': self.mitre_technique,
                    'remediation': "Analyze section for self-modifying code or injected payloads."
                })
        return findings

    def _check_overlay(self, pe: PEFile, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        if not pe.sections:
            return findings
            
        last_section = max(pe.sections, key=lambda s: s['PointerToRawData'])
        end_of_pe = last_section['PointerToRawData'] + last_section['SizeOfRawData']
        
        file_size = len(pe.data)
        if file_size > end_of_pe + 512: # Allowing small padding
            overlay_size = file_size - end_of_pe
            findings.append({
                'detector': self.detector,
                'finding_type': 'pe_overlay_detected',
                'severity': 'medium',
                'pid': None,
                'process_name': os.path.basename(file_path),
                'description': f"File contains {overlay_size} bytes of appended data (overlay).",
                'evidence': {'overlay_size': overlay_size},
                'mitre_technique': 'T1027',
                'remediation': "Extract and analyze the appended overlay data."
            })
        return findings
