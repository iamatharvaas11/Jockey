"""Tests for JOCKY's non-evasive compiler-validation lab."""
import pytest

from resilience.models import Experiment, TransformationType
from resilience.transformer import IRResilienceTransformer, UnsafeTransformationError
from resilience.evaluator import ResilienceEvaluator


SAMPLE_JOCKY_IR = """
function @investigation_scan() -> i32 {
block_entry:
  %0 = call @jocky_collect_processes()
  %1 = icmp_gt %0, 0
  br %1, label %block_has_procs, label %block_empty

block_has_procs:
  ret %0

block_empty:
  ret 0
}
"""


class TestResilienceTransformations:
    @pytest.fixture
    def transformer(self):
        return IRResilienceTransformer()

    def test_provenance_stamp_changes_hash_preserves_ir(self, transformer):
        var = transformer.generate_variant(
            SAMPLE_JOCKY_IR,
            TransformationType.PROVENANCE_STAMP,
            {"tag": "BUILD_EXP_ALPHA"},
        )
        assert var.original_hash != var.variant_hash
        assert "BUILD_EXP_ALPHA" in var.transformed_ir
        assert "@investigation_scan" in var.transformed_ir
        assert var.build_time_ms >= 0.0

    def test_canonical_format_normalizes_whitespace_only(self, transformer):
        var = transformer.generate_variant(
            "\r\n".join(line + "  " for line in SAMPLE_JOCKY_IR.splitlines()),
            TransformationType.CANONICAL_FORMAT,
            {},
        )
        assert var.original_hash != var.variant_hash
        assert "  \n" not in var.transformed_ir

    def test_evasion_oriented_transforms_are_rejected(self, transformer):
        with pytest.raises(UnsafeTransformationError):
            transformer.generate_variant(SAMPLE_JOCKY_IR, "SYMBOL_RENAMING", {"prefix": "reg_"})


class TestResilienceEvaluationAndMetrics:
    @pytest.fixture
    def evaluator(self):
        return ResilienceEvaluator()

    def test_comparative_metrics_calculation(self, evaluator):
        transformer = IRResilienceTransformer()
        variant = transformer.generate_variant(
            SAMPLE_JOCKY_IR,
            TransformationType.PROVENANCE_STAMP,
            {"tag": "COVERAGE_CHECK"},
        )

        # Baseline telemetry observation (simulate matching on '%0')
        orig_obs = evaluator.observe_artifact(SAMPLE_JOCKY_IR, "ORIG", signature_blacklist=["%0"])
        assert orig_obs.detected is True
        assert orig_obs.event_count == 1

        # A provenance artifact retains the original detection coverage.
        var_obs = evaluator.observe_artifact(variant.transformed_ir, variant.variant_id, signature_blacklist=["%0"])
        assert var_obs.detected is True
        assert var_obs.event_count == 1

        comparison = evaluator.compare_variants(SAMPLE_JOCKY_IR, variant, orig_obs, var_obs)
        assert comparison.hash_difference is True
        assert comparison.telemetry_diff["original_events"] == 1
        assert comparison.telemetry_diff["candidate_events"] == 1
        assert comparison.detection_diff["original_detected"] is True
        assert comparison.detection_diff["candidate_detected"] is True
        assert comparison.detection_diff["coverage_preserved"] is True

    def test_research_report_generation(self, evaluator):
        transformer = IRResilienceTransformer()
        variant = transformer.generate_variant(
            SAMPLE_JOCKY_IR,
            TransformationType.PROVENANCE_STAMP,
            {"tag": "TEST_TRIAL"},
        )
        orig_obs = evaluator.observe_artifact(SAMPLE_JOCKY_IR, "ORIG")
        var_obs = evaluator.observe_artifact(variant.transformed_ir, variant.variant_id)
        comp = evaluator.compare_variants(SAMPLE_JOCKY_IR, variant, orig_obs, var_obs)

        exp = Experiment(target_name="ProcessScanner", variants=[variant])
        report = evaluator.generate_research_report(exp, [comp])

        assert report["target_name"] == "ProcessScanner"
        assert report["total_variants_evaluated"] == 1
        assert report["safety_boundary_compliance"]["status"] == "COMPLIANT"
        assert report["safety_boundary_compliance"]["prohibited_actions_executed"] is False
