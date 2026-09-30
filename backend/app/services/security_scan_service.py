import time
import platform
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

def _serialize_scan(scan) -> Dict[str, Any]:
    return {
        'scan_id': scan.id,
        'scan_type': scan.scan_type,
        'status': scan.status,
        'host': scan.host,
        'target': scan.target,
        'scan_duration_ms': scan.scan_duration_ms,
        'total_findings': scan.total_findings,
        'critical_count': scan.critical_count,
        'high_count': scan.high_count,
        'medium_count': scan.medium_count,
        'low_count': scan.low_count,
        'info_count': scan.info_count,
        'summary': {
            'critical': scan.critical_count or 0,
            'high': scan.high_count or 0,
            'medium': scan.medium_count or 0,
            'low': scan.low_count or 0,
            'info': scan.info_count or 0,
            'total': scan.total_findings or 0
        },
        'modules': scan.modules_json,
        'findings': scan.findings_json,
        'created_at': scan.created_at.isoformat() if scan.created_at else None
    }

async def run_live_host_scan(db: AsyncSession) -> Dict[str, Any]:
    """Run AMSI, ETW, and API Hook detectors against live host. Persist to DB."""
    from analysis.security.amsi_detector import AMSIDetector
    from analysis.security.etw_detector import ETWDetector
    from analysis.security.api_hook_auditor import APIHookAuditor
    from app.models.security_scan import SecurityScan
    
    scan_id = str(uuid.uuid4())
    start = time.time()
    
    scan = SecurityScan(id=scan_id, scan_type='LIVE_HOST', status='RUNNING', host=platform.node())
    db.add(scan)
    await db.commit()
    
    try:
        amsi_findings = AMSIDetector().scan()
    except Exception as e:
        amsi_findings = [{'detector': 'AMSIDetector', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    try:
        etw_findings = ETWDetector().scan()
    except Exception as e:
        etw_findings = [{'detector': 'ETWDetector', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    try:
        hook_findings = APIHookAuditor().scan()
    except Exception as e:
        hook_findings = [{'detector': 'APIHookAuditor', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
    
    all_findings = amsi_findings + etw_findings + hook_findings
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        sev = f.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    modules = {
        'amsi_detector': {'status': 'THREATS_DETECTED' if amsi_findings else 'CLEAR', 'findings': amsi_findings, 'finding_count': len(amsi_findings)},
        'etw_detector': {'status': 'THREATS_DETECTED' if etw_findings else 'CLEAR', 'findings': etw_findings, 'finding_count': len(etw_findings)},
        'api_hook_auditor': {'status': 'THREATS_DETECTED' if hook_findings else 'CLEAR', 'findings': hook_findings, 'finding_count': len(hook_findings)},
    }
    
    for name, mod_result in modules.items():
        if any(f.get('finding_type') == 'UNSUPPORTED_PLATFORM' for f in mod_result['findings']):
            mod_result['status'] = 'UNSUPPORTED'
    
    duration_ms = int((time.time() - start) * 1000)
    
    scan.status = 'COMPLETED'
    scan.total_findings = len(all_findings)
    scan.critical_count = severity_counts.get('critical', 0)
    scan.high_count = severity_counts.get('high', 0)
    scan.medium_count = severity_counts.get('medium', 0)
    scan.low_count = severity_counts.get('low', 0)
    scan.info_count = severity_counts.get('info', 0)
    scan.findings_json = all_findings
    scan.modules_json = modules
    scan.scan_duration_ms = duration_ms
    await db.commit()
    await db.refresh(scan)
    
    return _serialize_scan(scan)

async def scan_binary_file(db: AsyncSession, file_path: str) -> Dict[str, Any]:
    """Run IAT + Packed detectors on a PE binary file."""
    from analysis.security.iat_scanner import IATScanner
    from analysis.security.packed_detector import PackedBinaryDetector
    from app.models.security_scan import SecurityScan
    
    scan_id = str(uuid.uuid4())
    start = time.time()
    
    scan = SecurityScan(id=scan_id, scan_type='BINARY_ANALYSIS', status='RUNNING', host=platform.node(), target=file_path)
    db.add(scan)
    await db.commit()
    
    try:
        iat_findings = IATScanner().scan_file(file_path)
    except Exception as e:
        iat_findings = [{'detector': 'IATScanner', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    try:
        packed_findings = PackedBinaryDetector().scan_file(file_path)
    except Exception as e:
        packed_findings = [{'detector': 'PackedBinaryDetector', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    all_findings = iat_findings + packed_findings
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        sev = f.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
    modules = {
        'iat_scanner': {'status': 'THREATS_DETECTED' if iat_findings else 'CLEAR', 'findings': iat_findings, 'finding_count': len(iat_findings)},
        'packed_detector': {'status': 'THREATS_DETECTED' if packed_findings else 'CLEAR', 'findings': packed_findings, 'finding_count': len(packed_findings)}
    }
    
    for name, mod_result in modules.items():
        if any(f.get('finding_type') == 'UNSUPPORTED_PLATFORM' for f in mod_result['findings']):
            mod_result['status'] = 'UNSUPPORTED'
            
    duration_ms = int((time.time() - start) * 1000)
    
    scan.status = 'COMPLETED'
    scan.total_findings = len(all_findings)
    scan.critical_count = severity_counts.get('critical', 0)
    scan.high_count = severity_counts.get('high', 0)
    scan.medium_count = severity_counts.get('medium', 0)
    scan.low_count = severity_counts.get('low', 0)
    scan.info_count = severity_counts.get('info', 0)
    scan.findings_json = all_findings
    scan.modules_json = modules
    scan.scan_duration_ms = duration_ms
    scan.scanned_binaries = 1
    await db.commit()
    await db.refresh(scan)
    
    return _serialize_scan(scan)

async def scan_single_process(db: AsyncSession, pid: int) -> Dict[str, Any]:
    """Run AMSI/ETW/Hook detectors against a specific PID."""
    from analysis.security.amsi_detector import AMSIDetector
    from analysis.security.etw_detector import ETWDetector
    from analysis.security.api_hook_auditor import APIHookAuditor
    from app.models.security_scan import SecurityScan
    
    scan_id = str(uuid.uuid4())
    start = time.time()
    
    scan = SecurityScan(id=scan_id, scan_type='PROCESS_SCAN', status='RUNNING', host=platform.node(), target=str(pid))
    db.add(scan)
    await db.commit()
    
    try:
        amsi_findings = AMSIDetector().scan_process(pid)
    except Exception as e:
        amsi_findings = [{'detector': 'AMSIDetector', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    try:
        etw_findings = ETWDetector().scan_process(pid)
    except Exception as e:
        etw_findings = [{'detector': 'ETWDetector', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    try:
        hook_findings = APIHookAuditor().scan_process(pid)
    except Exception as e:
        hook_findings = [{'detector': 'APIHookAuditor', 'finding_type': 'ERROR', 'severity': 'info', 'description': str(e)}]
        
    all_findings = amsi_findings + etw_findings + hook_findings
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        sev = f.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
    modules = {
        'amsi_detector': {'status': 'THREATS_DETECTED' if amsi_findings else 'CLEAR', 'findings': amsi_findings, 'finding_count': len(amsi_findings)},
        'etw_detector': {'status': 'THREATS_DETECTED' if etw_findings else 'CLEAR', 'findings': etw_findings, 'finding_count': len(etw_findings)},
        'api_hook_auditor': {'status': 'THREATS_DETECTED' if hook_findings else 'CLEAR', 'findings': hook_findings, 'finding_count': len(hook_findings)}
    }
    
    for name, mod_result in modules.items():
        if any(f.get('finding_type') == 'UNSUPPORTED_PLATFORM' for f in mod_result['findings']):
            mod_result['status'] = 'UNSUPPORTED'
            
    duration_ms = int((time.time() - start) * 1000)
    
    scan.status = 'COMPLETED'
    scan.total_findings = len(all_findings)
    scan.critical_count = severity_counts.get('critical', 0)
    scan.high_count = severity_counts.get('high', 0)
    scan.medium_count = severity_counts.get('medium', 0)
    scan.low_count = severity_counts.get('low', 0)
    scan.info_count = severity_counts.get('info', 0)
    scan.findings_json = all_findings
    scan.modules_json = modules
    scan.scan_duration_ms = duration_ms
    scan.scanned_processes = 1
    await db.commit()
    await db.refresh(scan)
    
    return _serialize_scan(scan)

async def get_scan_results(db: AsyncSession, limit: int = 20) -> list:
    """Get latest scan results."""
    from app.models.security_scan import SecurityScan
    result = await db.execute(select(SecurityScan).order_by(SecurityScan.created_at.desc()).limit(limit))
    scans = result.scalars().all()
    return [_serialize_scan(s) for s in scans]

async def get_scan_by_id(db: AsyncSession, scan_id: str) -> Optional[Dict]:
    from app.models.security_scan import SecurityScan
    result = await db.execute(select(SecurityScan).filter(SecurityScan.id == scan_id))
    scan = result.scalars().first()
    if not scan: return None
    return _serialize_scan(scan)
