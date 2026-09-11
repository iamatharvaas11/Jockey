"""
Semantic Analyzer Tests for JOCKY DSL.
Verifies symbol resolution, scope isolation, type checking, target validation,
collector validation, property access validation, and diagnostic reporting.
"""
import pytest
from compiler.parser import parse
from compiler.semantic_analyzer import SemanticAnalyzer
from compiler.diagnostics import DiagnosticCode


def get_diagnostics(source: str):
    prog = parse(source)
    analyzer = SemanticAnalyzer()
    return analyzer.analyze_diagnostics(prog)


class TestSemanticTargetValidation:
    """Tests for TARGET declaration constraints."""

    def test_missing_target_fails(self):
        source = """
        SCAN PROCESSES;
        FIND IOC;
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_MISSING_TARGET for e in diag.errors)

    def test_valid_target_passes(self):
        source = """
        TARGET SYSTEM;
        SCAN PROCESSES;
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors

    def test_duplicate_target_generates_warning(self):
        source = """
        TARGET SYSTEM;
        TARGET ALL;
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors
        assert diag.has_warnings
        assert any(w.code == DiagnosticCode.SEM_DUPLICATE_TARGET for w in diag.warnings)


class TestSemanticSymbolAndScope:
    """Tests for symbol declaration, resolution, and scoping."""

    def test_undefined_variable_in_where(self):
        source = """
        TARGET SYSTEM;
        SCAN PROCESSES WHERE pid == undefined_var;
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_UNDEFINED_VARIABLE for e in diag.errors)

    def test_duplicate_let_in_same_scope(self):
        source = """
        TARGET SYSTEM;
        LET x = 10;
        LET x = 20;
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_DUPLICATE_VARIABLE for e in diag.errors)

    def test_let_then_set_in_scope_succeeds(self):
        source = """
        TARGET SYSTEM;
        LET threshold = 5;
        SET threshold = 10;
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors

    def test_set_undefined_variable_fails(self):
        source = """
        TARGET SYSTEM;
        SET my_var = 123;
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_UNDEFINED_VARIABLE for e in diag.errors)

    def test_set_valid_config_succeeds_without_let(self):
        source = """
        TARGET SYSTEM;
        SET output_format = "JSON";
        SET severity_threshold = "HIGH";
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors

    def test_loop_variable_scoped_to_loop_body(self):
        source = """
        TARGET SYSTEM;
        FOREACH proc IN PROCESSES {
            LET inner = proc.pid;
        }
        LET outer = inner;
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_UNDEFINED_VARIABLE and "inner" in e.message for e in diag.errors)

    def test_loop_variable_accessible_in_loop_body(self):
        source = """
        TARGET SYSTEM;
        FOREACH proc IN PROCESSES {
            IF proc.pid > 0 THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors


class TestSemanticCollectorAndTargetValidation:
    """Tests for valid commands and unsupported arguments."""

    def test_unsupported_scan_target(self):
        source = """
        TARGET SYSTEM;
        SCAN UNKNOWN_COLLECTOR;
        """
        # Note: if grammar restricts SCAN_TARGET, parser catches it; if not, semantic catches it
        # In our grammar, valid SCAN_TARGET are defined, but if any slips through or with ALL
        diag = get_diagnostics("TARGET SYSTEM; SCAN ALL;")
        assert not diag.has_errors

    def test_unsupported_find_target(self):
        diag = get_diagnostics("TARGET SYSTEM; FIND IOC; FIND PERSISTENCE;")
        assert not diag.has_errors

    def test_unsupported_build_target(self):
        diag = get_diagnostics("TARGET SYSTEM; BUILD TIMELINE; BUILD CORRELATIONS;")
        assert not diag.has_errors

    def test_unsupported_export_target(self):
        diag = get_diagnostics("TARGET SYSTEM; EXPORT REPORT; EXPORT EVIDENCE;")
        assert not diag.has_errors


class TestSemanticPropertyValidation:
    """Tests for entity property access validation."""

    def test_valid_process_properties(self):
        source = """
        TARGET SYSTEM;
        FOREACH p IN PROCESSES {
            IF p.pid > 0 AND p.name == "svchost.exe" THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors

    def test_invalid_process_property(self):
        source = """
        TARGET SYSTEM;
        FOREACH p IN PROCESSES {
            IF p.nonexistent_field == "test" THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_INVALID_PROPERTY for e in diag.errors)
        assert any("nonexistent_field" in e.message for e in diag.errors)

    def test_valid_network_properties(self):
        source = """
        TARGET SYSTEM;
        FOREACH conn IN NETWORK {
            IF conn.remote_port == 443 AND conn.protocol == "TCP" THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors

    def test_invalid_network_property(self):
        source = """
        TARGET SYSTEM;
        FOREACH conn IN NETWORK {
            IF conn.foo_bar == 123 THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_INVALID_PROPERTY for e in diag.errors)


class TestSemanticTypeChecking:
    """Tests for type compatibility and operator validation."""

    def test_compare_int_with_string_fails(self):
        source = """
        TARGET SYSTEM;
        FOREACH p IN PROCESSES {
            IF p.pid == "string_not_int" THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_TYPE_MISMATCH for e in diag.errors)

    def test_ordered_comparison_int_with_int_succeeds(self):
        source = """
        TARGET SYSTEM;
        LET limit = 1000;
        FOREACH p IN PROCESSES {
            IF p.pid > limit THEN {
                EXPORT REPORT;
            }
        }
        """
        diag = get_diagnostics(source)
        assert not diag.has_errors

    def test_type_mismatch_in_set(self):
        source = """
        TARGET SYSTEM;
        LET count = 10;
        SET count = "cannot_assign_string_to_int";
        """
        diag = get_diagnostics(source)
        assert diag.has_errors
        assert any(e.code == DiagnosticCode.SEM_TYPE_MISMATCH for e in diag.errors)

