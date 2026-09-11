"""
Negative parser tests for the JOCKY compiler.
Verifies that malformed input produces errors rather than silently succeeding.
"""
import pytest
from lark.exceptions import UnexpectedInput, UnexpectedToken, UnexpectedCharacters
from compiler.parser import parse


class TestParserNegative:
    """Tests that verify the parser correctly rejects malformed input."""

    def test_empty_input(self):
        """Empty input should produce a program with no statements."""
        program = parse("")
        assert program is not None
        assert len(program.statements) == 0

    def test_missing_semicolon(self):
        """Statements without semicolons should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse("TARGET SYSTEM")

    def test_invalid_keyword(self):
        """Unrecognized keywords should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse("DESTROY EVERYTHING;")

    def test_scan_missing_target(self):
        """SCAN without a target type should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse("SCAN;")

    def test_incomplete_if_statement(self):
        """IF without THEN or body should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse("IF x == 1;")

    def test_unclosed_string_literal(self):
        """Unclosed string literals should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse('SET x = "unclosed;')

    def test_invalid_operator_in_condition(self):
        """Invalid operators should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse('TARGET SYSTEM; SCAN PROCESSES WHERE name !!! "test";')

    def test_export_missing_type(self):
        """EXPORT without specifying what to export should fail."""
        with pytest.raises(UnexpectedInput):
            parse("EXPORT;")

    def test_build_missing_target(self):
        """BUILD without a target should fail."""
        with pytest.raises(UnexpectedInput):
            parse("BUILD;")

    def test_find_missing_target(self):
        """FIND without a target should fail."""
        with pytest.raises(UnexpectedInput):
            parse("FIND;")

    def test_set_missing_value(self):
        """SET without a value assignment should fail."""
        with pytest.raises(UnexpectedInput):
            parse("SET x;")

    def test_random_garbage(self):
        """Random non-JOCKY text should fail to parse."""
        with pytest.raises(UnexpectedInput):
            parse("this is not valid jocky code at all")

    def test_nested_unclosed_block(self):
        """Unclosed braces in IF should fail."""
        with pytest.raises(UnexpectedInput):
            parse('IF x == 1 THEN { SCAN PROCESSES;')


class TestParserEdgeCases:
    """Tests for parser edge cases that should succeed."""

    def test_multiple_targets(self):
        """Multiple TARGET declarations should parse (semantic check is separate)."""
        program = parse("TARGET SYSTEM; TARGET ALL;")
        assert len(program.statements) == 2

    def test_whitespace_tolerance(self):
        """Parser should handle various whitespace patterns."""
        program = parse("""
            TARGET    SYSTEM  ;
            SCAN   PROCESSES  ;
        """)
        assert len(program.statements) == 2

    def test_comment_handling(self):
        """Comments should be ignored by the parser."""
        program = parse("""
            // This is a comment
            TARGET SYSTEM;
            SCAN PROCESSES;
        """)
        assert len(program.statements) == 2

    def test_valid_scan_targets(self):
        """All documented scan targets should parse."""
        targets = ["PROCESSES", "FILES", "NETWORK", "EVENTLOGS", "REGISTRY"]
        for target in targets:
            program = parse(f"TARGET SYSTEM; SCAN {target};")
            assert program is not None
            assert len(program.statements) == 2

    def test_valid_find_targets(self):
        """All documented find targets should parse."""
        targets = ["IOC", "SUSPICIOUS", "PERSISTENCE", "MALWARE"]
        for target in targets:
            program = parse(f"TARGET SYSTEM; FIND {target};")
            assert program is not None

    def test_valid_build_targets(self):
        """All documented build targets should parse."""
        targets = ["TIMELINE", "CORRELATIONS", "PROCESSGRAPH"]
        for target in targets:
            program = parse(f"TARGET SYSTEM; BUILD {target};")
            assert program is not None
