"""
Tests for 'jocky check' CLI command.
Verifies exit codes, stage progress reporting, error diagnostics, and --ast flag.
"""
import subprocess
import sys
import os
import tempfile
import pytest


def run_jocky_cli(*args) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "compiler.cli"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


class TestCLICheckCommand:
    """Tests for the jocky check CLI subcommand."""

    def test_check_valid_file_succeeds(self):
        result = run_jocky_cli("check", "examples/basic_scan.jky")
        assert result.returncode == 0
        assert "Lexing passed" in result.stdout
        assert "Parsing passed" in result.stdout
        assert "Semantic analysis passed" in result.stdout
        assert "JOCKY program is valid" in result.stdout

    def test_check_with_ast_flag_outputs_tree(self):
        result = run_jocky_cli("check", "examples/basic_scan.jky", "--ast")
        assert result.returncode == 0
        assert "Abstract Syntax Tree" in result.stdout
        assert "TargetStmt" in result.stdout
        assert "ScanStmt" in result.stdout

    def test_check_missing_file_fails(self):
        result = run_jocky_cli("check", "non_existent_file.jky")
        assert result.returncode != 0
        assert "File not found" in result.stdout

    def test_check_syntax_error_file_fails(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jky", delete=False) as f:
            f.write("TARGET SYSTEM\nSCAN PROCESSES;")
            temp_name = f.name

        try:
            result = run_jocky_cli("check", temp_name)
            assert result.returncode != 0
            assert "Syntax error" in result.stdout
        finally:
            if os.path.exists(temp_name):
                os.remove(temp_name)

    def test_check_semantic_error_file_fails(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jky", delete=False) as f:
            # Semantic error: undefined variable in WHERE
            f.write("TARGET SYSTEM;\nSCAN PROCESSES WHERE pid == undefined_var_xyz;")
            temp_name = f.name

        try:
            result = run_jocky_cli("check", temp_name)
            assert result.returncode != 0
            assert "Semantic error" in result.stdout
            assert "E2001" in result.stdout
        finally:
            if os.path.exists(temp_name):
                os.remove(temp_name)

