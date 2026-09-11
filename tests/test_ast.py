"""
Tests for JOCKY Abstract Syntax Tree (AST).
Verifies node types, structural hierarchy, source location preservation,
and deterministic pretty printing.
"""
import pytest
from compiler.parser import parse
from compiler.ast_nodes import (
    Program, TargetStmt, ScanStmt, FindStmt, BuildStmt, ExportStmt,
    SetStmt, VarAssign, FilterStmt, IfStmt, ForEachStmt,
    Condition, BinaryExpr, PropertyAccess, Identifier,
    StringLiteral, NumberLiteral, BoolLiteral
)
from compiler.diagnostics import SourceLocation


class TestASTNodes:
    """Tests for AST structure and source locations."""

    def test_all_statement_nodes_created(self):
        source = """
        TARGET SYSTEM;
        LET x = 10;
        SET output_format = "JSON";
        SCAN PROCESSES;
        FIND IOC;
        BUILD TIMELINE;
        FILTER network.remote_port == 80;
        IF x > 5 THEN {
            EXPORT REPORT TO "report.json";
        }
        FOREACH p IN PROCESSES {
            SCAN FILES;
        }
        """
        prog = parse(source)
        assert isinstance(prog, Program)
        types = [type(s) for s in prog.statements]
        assert TargetStmt in types
        assert VarAssign in types
        assert SetStmt in types
        assert ScanStmt in types
        assert FindStmt in types
        assert BuildStmt in types
        assert FilterStmt in types
        assert IfStmt in types
        assert ForEachStmt in types

    def test_source_locations_preserved_on_all_nodes(self):
        source = """
        TARGET SYSTEM;
        SCAN PROCESSES WHERE name == "cmd.exe";
        """
        prog = parse(source)
        assert prog.location is not None
        assert isinstance(prog.location, SourceLocation)

        target_stmt = prog.statements[0]
        assert target_stmt.location.line == 2
        assert target_stmt.location.column == 9

        scan_stmt = prog.statements[1]
        assert scan_stmt.location.line == 3
        assert scan_stmt.location.column == 9

        cond = scan_stmt.condition
        assert cond.location is not None
        assert cond.location.line == 3

    def test_deterministic_pretty_printing(self):
        source = """
        TARGET SYSTEM;
        SCAN PROCESSES;
        EXPORT REPORT;
        """
        prog1 = parse(source)
        prog2 = parse(source)

        pretty1 = prog1.pretty()
        pretty2 = prog2.pretty()

        assert pretty1 == pretty2
        assert "TargetStmt" in pretty1
        assert "ScanStmt" in pretty1
        assert "ExportStmt" in pretty1

