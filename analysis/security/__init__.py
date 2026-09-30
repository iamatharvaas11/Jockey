import os
from typing import Dict, Any, List

from .amsi_detector import AMSIDetector
from .etw_detector import ETWDetector
from .api_hook_auditor import APIHookAuditor
from .iat_scanner import IATScanner
from .packed_detector import PackedBinaryDetector

def run_full_security_scan(target_file: str = None) -> Dict[str, Any]:
    """
    Orchestrates all 5 security modules and returns unified results.
    """
    all_findings: List[Dict[str, Any]] = []
    modules: Dict[str, Dict[str, Any]] = {}

    # Live host scans: AMSI, ETW, API Hooks
    live_detectors = [
        ('amsi_detector', AMSIDetector()),
        ('etw_detector', ETWDetector()),
        ('api_hook_auditor', APIHookAuditor()),
    ]
    for name, detector in live_detectors:
        try:
            findings = detector.scan()
            status = 'CLEAR'
            if any(f.get('finding_type') == 'UNSUPPORTED_PLATFORM' for f in findings):
                status = 'UNSUPPORTED'
            elif findings:
                status = 'THREATS_DETECTED'
            modules[name] = {'status': status, 'findings': findings, 'finding_count': len(findings)}
            all_findings.extend(findings)
        except Exception as e:
            modules[name] = {'status': 'ERROR', 'findings': [], 'finding_count': 0, 'error': str(e)}

    # File-based scans: IAT, Packed
    if target_file and os.path.exists(target_file):
        file_detectors = [
            ('iat_scanner', IATScanner()),
            ('packed_detector', PackedBinaryDetector()),
        ]
        for name, detector in file_detectors:
            try:
                findings = detector.scan(target_file)
                status = 'THREATS_DETECTED' if findings else 'CLEAR'
                modules[name] = {'status': status, 'findings': findings, 'finding_count': len(findings)}
                all_findings.extend(findings)
            except Exception as e:
                modules[name] = {'status': 'ERROR', 'findings': [], 'finding_count': 0, 'error': str(e)}

    # Count severities
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        sev = f.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        'total_findings': len(all_findings),
        'critical_count': severity_counts['critical'],
        'high_count': severity_counts['high'],
        'medium_count': severity_counts['medium'],
        'low_count': severity_counts['low'],
        'info_count': severity_counts['info'],
        'findings': all_findings,
        'modules': modules,
        'scans_run': len(modules)
    }

__all__ = [
    'run_full_security_scan',
    'AMSIDetector',
    'ETWDetector',
    'APIHookAuditor',
    'IATScanner',
    'PackedBinaryDetector'
]
