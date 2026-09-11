"""Transparent JOCKY IR validation helpers.

Only provenance and formatting validation are supported. Identifier renaming,
padding, and control-flow variations that could change detection coverage are
deliberately rejected.
"""
import hashlib
import time
from typing import Any, Dict

from resilience.models import TransformationType, Variant


class UnsafeTransformationError(ValueError):
    """Raised when a request attempts to create an evasion-oriented variant."""


class IRResilienceTransformer:
    """Produces transparent provenance artifacts for authorized lab validation."""

    @staticmethod
    def _compute_sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def generate_variant(
        self,
        ir_text: str,
        transformation_type: TransformationType,
        parameters: Dict[str, Any],
        original_identifier: str = "InvestigationScan",
    ) -> Variant:
        """Apply a non-evasive validation operation and record its provenance."""
        start_time = time.perf_counter()
        orig_hash = self._compute_sha256(ir_text)

        if not isinstance(transformation_type, TransformationType):
            unsafe_names = {"SYMBOL_RENAMING", "REPRESENTATION_PADDING", "CONTROL_FLOW_VARIATION"}
            if str(transformation_type) in unsafe_names:
                raise UnsafeTransformationError(
                    "Evasion-oriented IR transformations are not available in JOCKY. "
                    "Use detection coverage validation instead."
                )
            raise ValueError(f"Unknown validation operation: {transformation_type!r}")

        if transformation_type == TransformationType.PROVENANCE_STAMP:
            transformed = self._apply_provenance_stamp(ir_text, parameters)
        elif transformation_type == TransformationType.CANONICAL_FORMAT:
            transformed = self._apply_canonical_format(ir_text)
        else:  # Control-flow validation preserves executable IR byte-for-byte.
            transformed = ir_text

        build_time = (time.perf_counter() - start_time) * 1000.0
        variant_hash = self._compute_sha256(transformed)

        return Variant(
            original_identifier=original_identifier,
            original_hash=orig_hash,
            variant_hash=variant_hash,
            transformation_type=transformation_type,
            parameters=parameters,
            transformed_ir=transformed,
            build_time_ms=round(build_time, 3),
        )

    def _apply_provenance_stamp(self, ir_text: str, params: Dict[str, Any]) -> str:
        tag = params.get("tag", "VALIDATION_BUILD_01")
        header = f"; === JOCKY PROVENANCE STAMP: {tag} ===\n"
        return header + ir_text

    def _apply_canonical_format(self, ir_text: str) -> str:
        """Normalize line endings and trailing whitespace without changing semantics."""
        return "\n".join(line.rstrip() for line in ir_text.splitlines()) + ("\n" if ir_text else "")
