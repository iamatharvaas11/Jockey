"""
Integration tests for 'jocky compile' CLI command and flags.
"""
import os
import subprocess
import sys
import pytest


def run_cli(*args):
    cmd = [sys.executable, "-m", "compiler.cli"] + list(args)
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res


def test_cli_compile_emit_ir(tmp_path):
    src_file = tmp_path / "test.jky"
    src_file.write_text("TARGET SYSTEM;\nLET a = 5;\nLET b = a + 2;\n")

    res = run_cli("compile", str(src_file), "--emit-ir")
    assert res.returncode == 0
    assert "JOCKY IR generation passed" in res.stdout
    assert "ModuleID" in res.stdout
    assert "store i64 5" in res.stdout


def test_cli_compile_emit_llvm(tmp_path):
    src_file = tmp_path / "test.jky"
    src_file.write_text("TARGET SYSTEM;\nLET x = 10;\n")

    res = run_cli("compile", str(src_file), "--emit-llvm")
    assert res.returncode == 0
    assert "LLVM verification passed" in res.stdout
    assert 'define i32 @"main"()' in res.stdout


def test_cli_compile_emit_object_custom_output(tmp_path):
    src_file = tmp_path / "test.jky"
    src_file.write_text("TARGET SYSTEM;\nSCAN PROCESSES;\n")
    out_obj = tmp_path / "out.obj"

    res = run_cli("compile", str(src_file), "--emit-object", "-o", str(out_obj))
    assert res.returncode == 0
    assert "Code generation passed (native object)" in res.stdout
    assert os.path.exists(out_obj)
    assert os.path.getsize(out_obj) > 100


def test_cli_compile_error_reporting(tmp_path):
    bad_file = tmp_path / "bad.jky"
    # Variable referenced before declaration (semantic error)
    bad_file.write_text("TARGET SYSTEM;\nLET y = undefined_var + 1;\n")

    res = run_cli("compile", str(bad_file))
    assert res.returncode != 0
    assert "Semantic error" in res.stdout
    assert "E2001" in res.stdout

