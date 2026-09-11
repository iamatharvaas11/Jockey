"""
JOCKY Investigation Analysis Models
Defines structured results for IOC findings, cross-artifact relationships,
unified timeline events, and overall investigation analysis.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class IOCFinding:
    """An explainable, rule-based detection finding for an evidence item."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "medium"  # info, low, medium, high, critical
    reason: str = ""
    host: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_ids: List[str] = field(default_factory=list)
    matched_data: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "reason": self.reason,
            "host": self.host,
            "timestamp": self.timestamp,
            "evidence_ids": self.evidence_ids,
            "matched_data": self.matched_data,
            "explanation": self.explanation,
        }


@dataclass
class EvidenceRelationship:
    """An explicit, validated relationship linking two canonical evidence artifacts."""
    relationship_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_evidence_id: str = ""
    target_evidence_id: str = ""
    relationship_type: str = ""  # SPAWNED_CHILD, EXECUTED_FROM_FILE, OPENED_SOCKET, RECORDED_BY_EVENT, ACCESSED_REGISTRY
    confidence: float = 1.0      # 0.0 to 1.0
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "source_evidence_id": self.source_evidence_id,
            "target_evidence_id": self.target_evidence_id,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "reason": self.reason,
            "metadata": self.metadata,
        }


@dataclass
class TimelineEvent:
    """A normalized chronological event in the unified forensic super-timeline."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None  # ISO-8601 UTC or None if unavailable
    host: str = ""
    type: str = ""                   # PROCESS_START, FILE_MODIFY, FILE_CREATE, NETWORK_CONN, EVENT_LOG, REGISTRY_KEY
    source: str = ""                 # process, file, network, event, registry
    summary: str = ""
    evidence_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    is_timestamp_estimated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "host": self.host,
            "type": self.type,
            "source": self.source,
            "summary": self.summary,
            "evidence_id": self.evidence_id,
            "details": self.details,
            "is_timestamp_estimated": self.is_timestamp_estimated,
        }


@dataclass
class InvestigationAnalysis:
    """Unified result aggregating findings, correlated relationships, and timeline."""
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = "CASE-DEFAULT"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[IOCFinding] = field(default_factory=list)
    relationships: List[EvidenceRelationship] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    statistics: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "case_id": self.case_id,
            "timestamp": self.timestamp,
            "statistics": self.statistics,
            "findings": [f.to_dict() for f in self.findings],
            "relationships": [r.to_dict() for r in self.relationships],
            "timeline": [t.to_dict() for t in self.timeline],
        }

