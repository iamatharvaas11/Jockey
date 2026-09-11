"""
JOCKY Forensic Audit Logging Model
Provides chain-of-custody tracking, logging all lifecycle actions on evidence
(collection, storage, modification attempts, verification passes, and exports).
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Union
import uuid


class AuditAction(str, Enum):
    COLLECT = "COLLECT"
    STORE = "STORE"
    MODIFY_ATTEMPT = "MODIFY_ATTEMPT"
    VERIFY = "VERIFY"
    EXPORT = "EXPORT"
    IMPORT = "IMPORT"


@dataclass
class AuditRecord:
    """Immutable audit trail entry recording an action performed on evidence."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str = "JOCKY"
    action: str = AuditAction.COLLECT.value
    evidence_id: Optional[str] = None
    result: str = "SUCCESS"  # SUCCESS, FAILURE, TAMPER_DETECTED
    details: Dict[str, Any] = field(default_factory=dict)
    record_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "actor": self.actor,
            "action": self.action,
            "evidence_id": self.evidence_id,
            "result": self.result,
            "details": self.details,
        }
        b = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(b).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        if not self.record_hash:
            self.record_hash = self.compute_hash()
        return {
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "actor": self.actor,
            "action": self.action,
            "evidence_id": self.evidence_id,
            "result": self.result,
            "details": self.details,
            "record_hash": self.record_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditRecord":
        rec = cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp_utc=data.get("timestamp_utc", datetime.now(timezone.utc).isoformat()),
            actor=data.get("actor", "JOCKY"),
            action=data.get("action", AuditAction.COLLECT.value),
            evidence_id=data.get("evidence_id"),
            result=data.get("result", "SUCCESS"),
            details=data.get("details", {}),
            record_hash=data.get("record_hash", ""),
        )
        if not rec.record_hash:
            rec.record_hash = rec.compute_hash()
        return rec


class AuditLogger:
    """Manages an audit trail for forensic evidence actions."""

    def __init__(self):
        self._records: List[AuditRecord] = []

    def log(
        self,
        action: Union[AuditAction, str],
        actor: str = "JOCKY",
        evidence_id: Optional[str] = None,
        result: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Create and append an audit record with deterministic hash."""
        action_val = action.value if isinstance(action, AuditAction) else str(action)
        rec = AuditRecord(
            actor=actor,
            action=action_val,
            evidence_id=evidence_id,
            result=result,
            details=details or {},
        )
        rec.record_hash = rec.compute_hash()
        self._records.append(rec)
        return rec

    def get_records(self, evidence_id: Optional[str] = None, action: Optional[str] = None) -> List[AuditRecord]:
        """Query audit records with optional filters."""
        res = []
        for r in self._records:
            if evidence_id and r.evidence_id != evidence_id:
                continue
            if action and r.action != action:
                continue
            res.append(r)
        return res

    def export_audit_log(self, path: str):
        """Export the audit trail to a JSON file."""
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in self._records], f, indent=2)
