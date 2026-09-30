"""
JOCKY IOC Rule Definition and Validation
Defines the configurable rule schema and validator for threat indicators and behavioral detection.
"""
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional


ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_EVIDENCE_TYPES = {"process", "file", "network", "event", "registry", "generic"}


class RuleValidationError(Exception):
    """Raised when an IOC rule specification is malformed or invalid."""
    pass


@dataclass
class IOCRule:
    """A configurable detection rule evaluated against canonical evidence items."""
    rule_id: str
    name: str
    description: str
    severity: str
    enabled: bool
    evidence_types: List[str]
    conditions: Dict[str, Any]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
            "evidence_types": self.evidence_types,
            "conditions": self.conditions,
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IOCRule":
        RuleValidator.validate(data)
        raw_enabled = data.get("enabled", True)
        if isinstance(raw_enabled, str):
            enabled = raw_enabled.strip().lower() in ("true", "1", "yes", "enabled")
        else:
            enabled = bool(raw_enabled)

        return cls(
            rule_id=str(data["rule_id"]),
            name=str(data["name"]),
            description=str(data.get("description", "")),
            severity=str(data["severity"]).lower(),
            enabled=enabled,
            evidence_types=[str(t).lower() for t in data["evidence_types"]],
            conditions=dict(data.get("conditions", {})),
            explanation=str(data.get("explanation", "")),
        )


class RuleValidator:
    """Validates IOC rule dictionaries before instantiation."""

    @staticmethod
    def validate(data: Dict[str, Any]):
        if not isinstance(data, dict):
            raise RuleValidationError("Rule must be a dictionary object.")

        required_keys = ["rule_id", "name", "severity", "evidence_types", "conditions"]
        for key in required_keys:
            if key not in data:
                raise RuleValidationError(f"Missing required rule field: '{key}'")

        if not str(data["rule_id"]).strip():
            raise RuleValidationError("Rule 'rule_id' must not be empty.")

        if not str(data["name"]).strip():
            raise RuleValidationError("Rule 'name' must not be empty.")

        sev = str(data["severity"]).lower()
        if sev not in ALLOWED_SEVERITIES:
            raise RuleValidationError(f"Invalid severity '{sev}'. Must be one of: {ALLOWED_SEVERITIES}")

        ev_types = data["evidence_types"]
        if not isinstance(ev_types, list) or not ev_types:
            raise RuleValidationError("Rule 'evidence_types' must be a non-empty list.")

        for t in ev_types:
            if str(t).lower() not in ALLOWED_EVIDENCE_TYPES:
                raise RuleValidationError(f"Invalid evidence type '{t}'. Allowed: {ALLOWED_EVIDENCE_TYPES}")

        conds = data["conditions"]
        if not isinstance(conds, dict) or not conds:
            raise RuleValidationError("Rule 'conditions' must be a non-empty dictionary.")

