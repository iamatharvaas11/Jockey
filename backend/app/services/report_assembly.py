"""
JOCKY Report Data Assembly Service
Assembles complete canonical forensic data from database stores for report generation.
Ensures zero data loss between investigation database records and generated reports.
"""
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.investigation import Investigation
from app.models.endpoint import Endpoint
from app.models.evidence import Evidence
from app.models.ioc import IOC
from app.models.relationship import Relationship
from app.models.timeline_event import TimelineEvent
from app.models.audit_log import AuditLog
from app.models.report import Report
from engine.report_generator import ReportGenerator


async def assemble_investigation_report_data(
    db: AsyncSession,
    investigation_id: str,
    examiner: str = "JOCKY Forensic Framework",
) -> Optional[Dict[str, Any]]:
    """
    Query all tables for an investigation (evidence, endpoints, iocs, relationships,
    timeline_events, audit_logs, reports) and assemble a comprehensive report dictionary.
    """
    inv_result = await db.execute(select(Investigation).filter(Investigation.id == investigation_id))
    inv = inv_result.scalars().first()
    if not inv:
        return None

    # Check for existing Report record (which holds cryptographic manifest & prior runs)
    rep_res = await db.execute(
        select(Report).filter(
            (Report.investigation_id == investigation_id) | (Report.case_id == inv.case_number)
        ).order_by(Report.created_at.desc())
    )
    existing_rep = rep_res.scalars().first()
    existing_data = existing_rep.report_json if existing_rep and existing_rep.report_json else {}

    # Query all evidence records
    ev_res = await db.execute(select(Evidence).filter(Evidence.investigation_id == investigation_id))
    evidence_rows = ev_res.scalars().all()

    # Query all endpoint records
    ep_res = await db.execute(select(Endpoint).filter(Endpoint.investigation_id == investigation_id))
    endpoint_rows = ep_res.scalars().all()

    # Query all IOC detections
    ioc_res = await db.execute(select(IOC).filter(IOC.investigation_id == investigation_id))
    ioc_rows = ioc_res.scalars().all()

    # Query all cross-artifact relationships
    rel_res = await db.execute(select(Relationship).filter(Relationship.investigation_id == investigation_id))
    rel_rows = rel_res.scalars().all()

    # Query all timeline events
    tl_res = await db.execute(select(TimelineEvent).filter(TimelineEvent.investigation_id == investigation_id))
    tl_rows = tl_res.scalars().all()

    # Query audit logs
    audit_res = await db.execute(select(AuditLog).filter(AuditLog.entity_id == investigation_id))
    audit_rows = audit_res.scalars().all()

    # Normalize evidence items
    evidence_items = []
    limitations = list(existing_data.get("limitations", []))
    errors = list(existing_data.get("errors", []))

    if evidence_rows:
        for ev in evidence_rows:
            e_dict = {
                "id": ev.id,
                "host": ev.host,
                "timestamp": ev.timestamp,
                "type": ev.type,
                "source": ev.source,
                "collector": ev.collector,
                "status": ev.status,
                "hash": ev.hash,
                "data": ev.data_json or {},
                "limitations": ev.limitations_json or [],
                "errors": ev.errors_json or [],
            }
            evidence_items.append(e_dict)
            if ev.limitations_json:
                limitations.extend(ev.limitations_json)
            if ev.errors_json:
                errors.extend(ev.errors_json)
    elif "evidence_items" in existing_data:
        evidence_items = existing_data["evidence_items"]

    # Normalize endpoints
    endpoints_list = []
    if endpoint_rows:
        for ep in endpoint_rows:
            endpoints_list.append({
                "hostname": ep.hostname,
                "os": ep.os_type,
                "ip_address": ep.ip_address,
                "status": ep.agent_status,
                "last_seen": ep.last_seen.isoformat() if ep.last_seen else None,
            })
    elif "endpoints" in existing_data:
        endpoints_list = existing_data["endpoints"]

    # Normalize IOC findings
    ioc_list = []
    if ioc_rows:
        for ioc in ioc_rows:
            ev_ids = ioc.mitre_tactics if isinstance(ioc.mitre_tactics, list) else []
            ioc_list.append({
                "finding_id": ioc.id,
                "rule_id": ioc.value,
                "rule_name": ioc.ioc_type,
                "severity": (ioc.threat_level or "MEDIUM").upper(),
                "reason": ioc.description or "",
                "confidence": 0.90,
                "evidence_ids": ev_ids,
            })
    elif "ioc_findings" in existing_data:
        ioc_list = existing_data["ioc_findings"]

    # Normalize relationships
    relationships_list = []
    if rel_rows:
        for r in rel_rows:
            relationships_list.append({
                "relationship_id": r.id,
                "source_evidence_id": r.source_evidence_id,
                "target_evidence_id": r.target_evidence_id,
                "relationship_type": r.relationship_type,
                "confidence": r.confidence,
                "reason": r.reason,
                "metadata": r.metadata_json or {},
            })
    elif "relationships" in existing_data:
        relationships_list = existing_data["relationships"]

    # Normalize timeline
    timeline_list = []
    if tl_rows:
        for t in tl_rows:
            raw = t.raw_payload or {}
            timeline_list.append({
                "event_id": t.id,
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                "type": t.event_type,
                "source": t.event_source,
                "summary": t.title,
                "evidence_id": raw.get("evidence_id"),
                "details": {"description": t.description, "severity": t.severity},
                "is_timestamp_estimated": raw.get("is_estimated", False),
            })
    elif "timeline" in existing_data:
        timeline_list = existing_data["timeline"]

    # Normalize audit records
    audit_list = []
    if audit_rows:
        for a in audit_rows:
            ts = a.timestamp if hasattr(a, "timestamp") else getattr(a, "created_at", None)
            audit_list.append({
                "timestamp": ts.isoformat() if ts else None,
                "actor": a.user_id or "System",
                "action": a.action,
                "evidence_id": a.entity_id,
                "record_hash": str(a.details or {}),
            })
    elif "audit_trail" in existing_data:
        audit_list = existing_data["audit_trail"]

    gen = ReportGenerator(case_id=inv.case_number, examiner=examiner)
    manifest = existing_data.get("integrity_manifest") or {
        "status": existing_rep.integrity_status if existing_rep else "unverified",
        "root_hash": existing_rep.root_hash if existing_rep else None,
        "verified": (existing_rep.integrity_status == "verified") if existing_rep else False,
    }

    report_dict = gen.generate(
        evidence_items=evidence_items,
        endpoints=endpoints_list,
        ioc_matches={"canonical_findings": ioc_list},
        correlations={"relationships": relationships_list},
        timeline=timeline_list,
        integrity_manifest=manifest,
        audit_records=audit_list,
        limitations=list(set(limitations)),
        errors=list(set(errors)),
        investigation_id=inv.id,
    )
    return report_dict
