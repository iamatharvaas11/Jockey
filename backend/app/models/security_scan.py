import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, JSON, Text
from app.db.base import Base

class SecurityScan(Base):
    __tablename__ = 'security_scans'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String, nullable=False)  # LIVE_HOST, BINARY_ANALYSIS, PROCESS_SCAN
    status = Column(String, default='RUNNING')  # RUNNING, COMPLETED, FAILED
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    findings_json = Column(JSON, default=list)
    modules_json = Column(JSON, default=dict)  # per-module breakdown
    scanned_processes = Column(Integer, default=0)
    scanned_binaries = Column(Integer, default=0)
    scan_duration_ms = Column(Integer, default=0)
    host = Column(String, default='')
    target = Column(String, default='')  # file path or PID for targeted scans
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
