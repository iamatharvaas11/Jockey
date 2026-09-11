"""Models for transparent JOCKY compiler-validation experiments.

This subsystem validates provenance and compiler consistency in an isolated
lab. It does not generate transformations intended to avoid a security control.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class TransformationType(str, Enum):
    """Non-evasive compiler-validation operations available in the lab."""
    PROVENANCE_STAMP = "PROVENANCE_STAMP"
    CANONICAL_FORMAT = "CANONICAL_FORMAT"
    CONTROL_FLOW_VALIDATION = "CONTROL_FLOW_VALIDATION"


@dataclass
class Variant:
    """An isolated, transformed variant of an original JOCKY IR program."""
    variant_id: str = field(default_factory=lambda: f"VAR-{str(uuid.uuid4())[:8]}")
    original_identifier: str = "program"
    original_hash: str = ""
    variant_hash: str = ""
    transformation_type: TransformationType = TransformationType.PROVENANCE_STAMP
    parameters: Dict[str, Any] = field(default_factory=dict)
    transformed_ir: str = ""
    build_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "original_identifier": self.original_identifier,
            "original_hash": self.original_hash,
            "variant_hash": self.variant_hash,
            "transformation_type": self.transformation_type.value,
            "parameters": self.parameters,
            "transformed_ir": self.transformed_ir,
            "build_time_ms": self.build_time_ms,
        }


@dataclass
class LabEnvironment:
    """Configured isolated research lab environment."""
    environment_id: str = "LAB-ISOLATED-01"
    name: str = "Controlled DFIR Evaluation Sandbox"
    os_type: str = "Windows / Ubuntu"
    active_controls: List[str] = field(default_factory=lambda: ["IOC_SIGNATURE_MATCHER", "HEURISTIC_OBSERVER"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "name": self.name,
            "os_type": self.os_type,
            "active_controls": self.active_controls,
        }


@dataclass
class TelemetryObservation:
    """Observed security telemetry, event counts, and detection outcome."""
    observation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    variant_id: str = ""
    category: str = "STATIC_ANALYSIS"
    event_count: int = 0
    detected: bool = False
    detector_name: str = "STATIC_SIGNATURE_ENGINE"
    details: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "variant_id": self.variant_id,
            "category": self.category,
            "event_count": self.event_count,
            "detected": self.detected,
            "detector_name": self.detector_name,
            "details": self.details,
            "execution_time_ms": self.execution_time_ms,
        }


@dataclass
class ExperimentComparison:
    """Comparison metrics between original baseline artifact and generated variant."""
    original_hash: str
    variant_hash: str
    hash_difference: bool
    structural_diff: Dict[str, Any]
    telemetry_diff: Dict[str, Any]
    detection_diff: Dict[str, Any]
    performance_overhead_ratio: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_hash": self.original_hash,
            "variant_hash": self.variant_hash,
            "hash_difference": self.hash_difference,
            "structural_diff": self.structural_diff,
            "telemetry_diff": self.telemetry_diff,
            "detection_diff": self.detection_diff,
            "performance_overhead_ratio": self.performance_overhead_ratio,
        }


@dataclass
class Experiment:
    """Root container for a controlled security-resilience research trial."""
    experiment_id: str = field(default_factory=lambda: f"EXP-{str(uuid.uuid4())[:8]}")
    target_name: str = "InvestigationWorkflow"
    environment: LabEnvironment = field(default_factory=LabEnvironment)
    variants: List[Variant] = field(default_factory=list)
    observations: List[TelemetryObservation] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "target_name": self.target_name,
            "environment": self.environment.to_dict(),
            "variants": [v.to_dict() for v in self.variants],
            "observations": [o.to_dict() for o in self.observations],
            "created_at": self.created_at,
        }
