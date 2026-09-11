from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.investigation import Investigation
from app.models.endpoint import Endpoint
from app.models.evidence import Evidence
from app.models.ioc import IOC
from app.models.relationship import Relationship
from app.models.timeline_event import TimelineEvent
from app.models.user import User

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("")
async def get_system_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Retrieve real, calculated statistics directly from the database without mocked placeholders."""
    # Investigations
    inv_res = await db.execute(select(func.count(Investigation.id)))
    total_invs = inv_res.scalar() or 0

    active_inv_res = await db.execute(
        select(func.count(Investigation.id)).filter(Investigation.status.in_(["OPEN", "ACTIVE"]))
    )
    active_invs = active_inv_res.scalar() or 0

    # Endpoints
    ep_res = await db.execute(select(func.count(Endpoint.id)))
    total_endpoints = ep_res.scalar() or 0

    online_ep_res = await db.execute(
        select(func.count(Endpoint.id)).filter(Endpoint.agent_status == "ONLINE")
    )
    online_endpoints = online_ep_res.scalar() or 0

    # Evidence
    ev_res = await db.execute(select(func.count(Evidence.id)))
    total_evidence = ev_res.scalar() or 0

    # IOCs & Alerts
    ioc_res = await db.execute(select(func.count(IOC.id)))
    total_iocs = ioc_res.scalar() or 0

    crit_ioc_res = await db.execute(
        select(func.count(IOC.id)).filter(IOC.threat_level.in_(["CRITICAL", "HIGH"]))
    )
    critical_alerts = crit_ioc_res.scalar() or 0

    # Relationships & Timeline
    rel_res = await db.execute(select(func.count(Relationship.id)))
    total_relationships = rel_res.scalar() or 0

    tl_res = await db.execute(select(func.count(TimelineEvent.id)))
    total_timeline_events = tl_res.scalar() or 0

    # Status breakdown
    statuses = ["OPEN", "ACTIVE", "CONTAINED", "CLOSED"]
    status_counts = {}
    for st in statuses:
        s_res = await db.execute(select(func.count(Investigation.id)).filter(Investigation.status == st))
        status_counts[st] = s_res.scalar() or 0

    # Recent Alerts (from real IOC findings)
    recent_iocs_res = await db.execute(
        select(IOC).order_by(IOC.created_at.desc()).limit(5)
    )
    recent_iocs = recent_iocs_res.scalars().all()
    recent_alerts = [
        {
            "id": i.id,
            "timestamp": i.created_at.isoformat() if i.created_at else None,
            "severity": i.threat_level,
            "description": f"[{i.ioc_type}] {i.description or i.value}",
        }
        for i in recent_iocs
    ]

    return {
        "activeInvestigations": active_invs,
        "totalInvestigations": total_invs,
        "endpoints": total_endpoints,
        "onlineEndpoints": online_endpoints,
        "totalEvidence": total_evidence,
        "criticalAlerts": critical_alerts,
        "iocs": total_iocs,
        "totalRelationships": total_relationships,
        "totalTimelineEvents": total_timeline_events,
        "statusDistribution": status_counts,
        "recentAlerts": recent_alerts,
    }

