"""
JOCKY Investigation Ingestion Service
Bridges forensic analysis outputs (canonical evidence, IOC detections,
cross-artifact relationships, timeline events, reports) into database records.
"""
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.investigation import Investigation
from app.models.endpoint import Endpoint
from app.models.evidence import Evidence
from app.models.ioc import IOC
from app.models.relationship import Relationship
from app.models.timeline_event import TimelineEvent
from app.models.report import Report
from app.models.audit_log import AuditLog


async def ingest_investigation_payload(
    db: AsyncSession,
    data: Dict[str, Any],
    case_number: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    user_id: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> Investigation:
    """
    Ingest a complete investigation analysis dictionary into database tables:
    investigations, endpoints, evidence, iocs, relationships, timeline_events.
    """
    case_no = case_number or data.get("case_id") or data.get("meta", {}).get("case_id") or f"CAS-{str(uuid.uuid4())[:8].upper()}"
    
    # 1. Retrieve or create Investigation
    inv_res = await db.execute(select(Investigation).filter(Investigation.case_number == case_no))
    inv = inv_res.scalars().first()
    if not inv:
        inv = Investigation(
            case_number=case_no,
            title=title or f"Forensic Investigation // {case_no}",
            description=description or "Automated full-system forensic analysis",
            status="ACTIVE",
            severity="HIGH",
            tags=["FORENSICS", "AUTOMATED_SCAN"],
        )
        db.add(inv)
        await db.flush()

    inv_id = inv.id

    # 2. Ingest Evidence Items & Discover Endpoints
    raw_evidence = data.get("evidence_items", [])
    hosts_seen = set()
    for ev in raw_evidence:
        ev_id = ev.get("id") or str(uuid.uuid4())
        host = ev.get("host") or "localhost"
        hosts_seen.add(host)

        # Check existing
        existing_ev = await db.execute(select(Evidence).filter(Evidence.id == ev_id))
        if not existing_ev.scalars().first():
            db_ev = Evidence(
                id=ev_id,
                investigation_id=inv_id,
                host=host,
                timestamp=ev.get("timestamp"),
                type=ev.get("type", "process"),
                source=ev.get("source", "system"),
                collector=ev.get("collector", "ForensicCollector"),
                status=ev.get("status", "VALID"),
                hash=ev.get("hash"),
                data_json=ev.get("data", {}),
                limitations_json=ev.get("limitations", []),
                errors_json=ev.get("errors", []),
            )
            db.add(db_ev)

    # Ingest Endpoints
    for h in hosts_seen:
        ep_res = await db.execute(select(Endpoint).filter(Endpoint.hostname == h, Endpoint.investigation_id == inv_id))
        if not ep_res.scalars().first():
            new_ep = Endpoint(
                investigation_id=inv_id,
                hostname=h,
                ip_address="127.0.0.1",
                os_type=data.get("meta", {}).get("os") or "Windows / Linux",
                agent_status="ONLINE",
                last_seen=datetime.utcnow(),
            )
            db.add(new_ep)

    # 3. Ingest IOC Findings
    raw_findings = data.get("findings", []) or data.get("ioc_findings", [])
    for f in raw_findings:
        ioc_val = f.get("rule_id") or f.get("reason", "Suspicious Indicator")
        ioc_res = await db.execute(
            select(IOC).filter(IOC.investigation_id == inv_id, IOC.value == ioc_val)
        )
        if not ioc_res.scalars().first():
            new_ioc = IOC(
                investigation_id=inv_id,
                ioc_type=f.get("rule_name") or "BEHAVIORAL_ANOMALY",
                value=ioc_val,
                threat_level=(f.get("severity") or "MEDIUM").upper(),
                description=f.get("explanation") or f.get("reason"),
                mitre_tactics=f.get("evidence_ids", []),
                matched_events_count=len(f.get("evidence_ids", [])),
            )
            db.add(new_ioc)

    # 4. Ingest Relationships
    raw_relationships = data.get("relationships", [])
    for r in raw_relationships:
        s_id = r.get("source_evidence_id")
        t_id = r.get("target_evidence_id")
        rel_type = r.get("relationship_type", "RELATED_TO")
        rel_res = await db.execute(
            select(Relationship).filter(
                Relationship.investigation_id == inv_id,
                Relationship.source_evidence_id == s_id,
                Relationship.target_evidence_id == t_id,
                Relationship.relationship_type == rel_type,
            )
        )
        if not rel_res.scalars().first():
            new_rel = Relationship(
                investigation_id=inv_id,
                source_evidence_id=s_id,
                target_evidence_id=t_id,
                relationship_type=rel_type,
                confidence=float(r.get("confidence", 1.0)),
                reason=r.get("reason", ""),
                metadata_json=r.get("metadata", {}),
            )
            db.add(new_rel)

    # 5. Ingest Timeline Events
    raw_timeline = data.get("timeline", [])
    for t in raw_timeline:
        t_str = t.get("timestamp")
        ts_val = None
        if t_str:
            try:
                ts_val = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
            except Exception:
                ts_val = datetime.utcnow()
        else:
            ts_val = datetime.utcnow()

        t_title = t.get("title") or f"Event {t.get('event_type')}"
        new_te = TimelineEvent(
            investigation_id=inv_id,
            timestamp=ts_val,
            event_source=t.get("evidence_type") or "SYSTEM",
            event_type=t.get("event_type") or "AUDIT",
            title=t_title,
            description=t.get("description") or "",
            severity=(t.get("severity") or "INFO").upper(),
            raw_payload={"evidence_id": t.get("evidence_id"), "is_estimated": t.get("is_estimated_timestamp", False)},
        )
        db.add(new_te)

    # 6. Report record
    if "summary" in data or "integrity_manifest" in data:
        manifest_obj = data.get("integrity_manifest", {})
        root_h = manifest_obj.get("root_hash") if isinstance(manifest_obj, dict) else None
        int_status = (
            manifest_obj.get("status")
            if isinstance(manifest_obj, dict)
            else data.get("summary", {}).get("integrity_status", "unverified")
        )
        rep_res = await db.execute(select(Report).filter(Report.case_id == case_no))
        if not rep_res.scalars().first():
            new_rep = Report(
                investigation_id=inv_id,
                case_id=case_no,
                examiner=data.get("meta", {}).get("examiner", "JOCKY Forensic Framework"),
                integrity_status=int_status or "verified",
                root_hash=root_h,
                report_json=data,
            )
            db.add(new_rep)

    # 7. Audit Log
    audit = AuditLog(
        user_id=user_id,
        entity_id=inv_id,
        entity_type="investigation",
        action="ANALYSIS_INGESTED",
        ip_address=source_ip,
        details={"summary": f"Ingested {len(raw_evidence)} evidence, {len(raw_findings)} IOCs, {len(raw_relationships)} relationships, {len(raw_timeline)} timeline events"},
    )
    db.add(audit)

    await db.commit()
    await db.refresh(inv)
    return inv


async def auto_ingest_latest_output(db: AsyncSession) -> Optional[Investigation]:
    """Check for jocky_output/investigation_report.json or analysis_result.json and ingest if present."""
    for fn in ["jocky_output/investigation_report.json", "jocky_output/analysis_result.json"]:
        output_path = os.path.abspath(fn)
        if os.path.exists(output_path):
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return await ingest_investigation_payload(db, data)
            except Exception as e:
                print(f"[!] auto_ingest_latest_output error for {fn}: {e}")
    return None
