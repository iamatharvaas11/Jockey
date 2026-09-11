"""
JOCKY Forensic Analysis Framework
Provides IOC threat evaluation, cross-artifact correlation, and unified timeline generation.
"""
from typing import List, Optional

from .models import (
    EvidenceRelationship,
    IOCFinding,
    InvestigationAnalysis,
    TimelineEvent,
)
from .ioc import IOCEngine, IOCRule, RuleValidationError, RuleValidator
from .correlation import CorrelationEngine
from .timeline import TimelineEngine
from evidence.schema import CanonicalEvidenceItem


def run_investigation_analysis(
    evidence_items: List[CanonicalEvidenceItem],
    case_id: str = "JOCKY-CASE-001",
    ioc_engine: Optional[IOCEngine] = None,
    correlation_engine: Optional[CorrelationEngine] = None,
    timeline_engine: Optional[TimelineEngine] = None,
) -> InvestigationAnalysis:
    """
    Execute full forensic analysis over canonical evidence items:
    IOC detection -> Cross-artifact correlation -> Unified timeline generation.
    Returns a unified InvestigationAnalysis result.
    """
    ioc = ioc_engine or IOCEngine()
    corr = correlation_engine or CorrelationEngine()
    timeline = timeline_engine or TimelineEngine()

    findings = ioc.evaluate_all(evidence_items)
    relationships = corr.correlate(evidence_items)
    timeline_events = timeline.build_timeline(evidence_items)

    analysis = InvestigationAnalysis(
        case_id=case_id,
        findings=findings,
        relationships=relationships,
        timeline=timeline_events,
        statistics={
            "evidence_items": len(evidence_items),
            "ioc_findings": len(findings),
            "relationships": len(relationships),
            "timeline_events": len(timeline_events),
        },
    )
    return analysis


__all__ = [
    "IOCFinding",
    "EvidenceRelationship",
    "TimelineEvent",
    "InvestigationAnalysis",
    "IOCEngine",
    "IOCRule",
    "RuleValidator",
    "RuleValidationError",
    "CorrelationEngine",
    "TimelineEngine",
    "run_investigation_analysis",
]

