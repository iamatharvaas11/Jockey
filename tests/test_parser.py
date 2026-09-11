"""
Comprehensive Parser Tests for JOCKY DSL.
Verifies syntax parsing, compound conditions, nested blocks, control flow,
error reporting, and source location tracking on AST nodes.
"""
import pytest
from compiler.parser import parse, ParserError
from compiler.ast_nodes import (
    Program, TargetStmt, ScanStmt, FindStmt, BuildStmt, ExportStmt,
    SetStmt, VarAssign, FilterStmt, IfStmt, ForEachStmt,
    Condition, BinaryExpr, UnaryExpr, PropertyAccess, Identifier,
    StringLiteral, NumberLiteral, BoolLiteral
)
from compiler.diagnostics import DiagnosticCode


class TestParserValidPrograms:
    """Tests for correctly formed programs."""

    def test_basic_program(self):
        source = """
        TARGET SYSTEM;
        SCAN PROCESSES;
        FIND IOC;
        BUILD TIMELINE;
        EXPORT REPORT;
        """
        prog = parse(source)
        assert isinstance(prog, Program)
        assert len(prog.statements) == 5
        assert isinstance(prog.statements[0], TargetStmt)
        assert prog.statements[0].target_type == "SYSTEM"
        assert prog.statements[0].location.line == 2

    def test_remote_target(self):
        source = 'TARGET REMOTE "192.168.1.100";'
        prog = parse(source)
        assert len(prog.statements) == 1
        stmt = prog.statements[0]
        assert isinstance(stmt, TargetStmt)
        assert stmt.target_type == "REMOTE"
        assert stmt.hostname == "192.168.1.100"

    def test_scan_with_simple_where(self):
        source = 'TARGET SYSTEM; SCAN PROCESSES WHERE name == "powershell.exe";'
        prog = parse(source)
        scan = prog.statements[1]
        assert isinstance(scan, ScanStmt)
        assert scan.scan_target == "PROCESSES"
        assert isinstance(scan.condition, Condition)
        assert scan.condition.operator == "=="
        assert isinstance(scan.condition.right, StringLiteral)
        assert scan.condition.right.value == "powershell.exe"

    def test_scan_with_compound_condition(self):
        source = """
        TARGET SYSTEM;
        SCAN PROCESSES WHERE name == "cmd.exe" AND pid > 1000;
        """
        prog = parse(source)
        scan = prog.statements[1]
        assert isinstance(scan, ScanStmt)
        assert isinstance(scan.condition, BinaryExpr)
        assert scan.condition.operator == "AND"

    def test_let_and_set_statements(self):
        source = """
        TARGET SYSTEM;
        LET max_size = 5000;
        SET output_format = "JSON";
        """
        prog = parse(source)
        assert isinstance(prog.statements[1], VarAssign)
        assert prog.statements[1].name == "max_size"
        assert isinstance(prog.statements[1].value, NumberLiteral)
        assert prog.statements[1].value.value == 5000

        assert isinstance(prog.statements[2], SetStmt)
        assert prog.statements[2].name == "output_format"
        assert isinstance(prog.statements[2].value, StringLiteral)
        assert prog.statements[2].value.value == "JSON"

    def test_if_then_block(self):
        source = """
        TARGET SYSTEM;
        IF alert.severity == "HIGH" THEN {
            EXPORT EVIDENCE TO "quarantine/";
            FIND MALWARE;
        }
        """
        prog = parse(source)
        if_stmt = prog.statements[1]
        assert isinstance(if_stmt, IfStmt)
        assert isinstance(if_stmt.condition, Condition)
        assert len(if_stmt.body) == 2
        assert isinstance(if_stmt.body[0], ExportStmt)
        assert isinstance(if_stmt.body[1], FindStmt)

    def test_if_then_else_block(self):
        source = """
        TARGET SYSTEM;
        IF threshold > 10 THEN {
            FIND IOC;
        } ELSE {
            EXPORT REPORT;
        }
        """
        prog = parse(source)
        if_stmt = prog.statements[1]
        assert isinstance(if_stmt, IfStmt)
        assert len(if_stmt.body) == 1
        assert if_stmt.else_body is not None
        assert len(if_stmt.else_body) == 1
        assert isinstance(if_stmt.else_body[0], ExportStmt)

    def test_foreach_loop(self):
        source = """
        TARGET SYSTEM;
        FOREACH proc IN PROCESSES {
            IF proc.name == "malware.exe" THEN {
                EXPORT REPORT;
            }
        }
        """
        prog = parse(source)
        foreach = prog.statements[1]
        assert isinstance(foreach, ForEachStmt)
        assert foreach.var_name == "proc"
        assert foreach.source == "PROCESSES"
        assert len(foreach.body) == 1
        assert isinstance(foreach.body[0], IfStmt)

    def test_nested_blocks(self):
        source = """
        TARGET SYSTEM;
        FOREACH p IN PROCESSES {
            IF p.pid > 100 THEN {
                IF p.name == "test.exe" THEN {
                    EXPORT REPORT;
                }
            }
        }
        """
        prog = parse(source)
        assert len(prog.statements) == 2
        outer_loop = prog.statements[1]
        assert isinstance(outer_loop, ForEachStmt)
        outer_if = outer_loop.body[0]
        assert isinstance(outer_if, IfStmt)
        inner_if = outer_if.body[0]
        assert isinstance(inner_if, IfStmt)

    def test_property_access(self):
        source = 'TARGET SYSTEM; FILTER network.remote_port == 443;'
        prog = parse(source)
        flt = prog.statements[1]
        assert isinstance(flt, FilterStmt)
        cond = flt.condition
        assert isinstance(cond.left, PropertyAccess)
        assert cond.left.obj == "network"
        assert cond.left.prop == "remote_port"


class TestParserErrorHandling:
    """Tests for structured syntax errors and diagnostic locations."""

    def test_missing_semicolon_raises_parser_error(self):
        with pytest.raises(ParserError) as exc_info:
            parse("TARGET SYSTEM\nSCAN PROCESSES;")
        err = exc_info.value
        assert err.code == DiagnosticCode.SYNTAX_MISSING_SEMICOLON
        assert err.location.line >= 1

    def test_unclosed_brace_raises_error(self):
        source = """
        TARGET SYSTEM;
        IF x == 1 THEN {
            SCAN PROCESSES;
        """
        with pytest.raises(ParserError) as exc_info:
            parse(source)
        err = exc_info.value
        assert err.location.line >= 3

    def test_invalid_keyword_raises_error(self):
        with pytest.raises(ParserError) as exc_info:
            parse("DELETE EVERYTHING;")
        err = exc_info.value
        assert err.code in (DiagnosticCode.SYNTAX_ERROR, DiagnosticCode.LEX_INVALID_CHAR)

    def test_malformed_condition_raises_error(self):
        with pytest.raises(ParserError) as exc_info:
            parse("TARGET SYSTEM; SCAN PROCESSES WHERE == 5;")
        err = exc_info.value
        assert err.location.line == 1

    def test_malformed_foreach_raises_error(self):
        with pytest.raises(ParserError):
            parse("TARGET SYSTEM; FOREACH { SCAN PROCESSES; }")

