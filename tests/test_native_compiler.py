"""
Unit tests for Native Compiler and JIT Execution Engine
Verifies object file generation and runtime execution semantics.
"""
import pytest
from compiler.parser import parse
from compiler.ir import ASTToIRConverter
from compiler.llvm_codegen import LLVMCodeGenerator
from compiler.native_compiler import NativeCompiler
from runtime import native_abi


def test_native_object_emission():
    src = """
    TARGET SYSTEM;
    LET x = 42;
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)
    ir_str = codegen.verify(llvm_mod)

    compiler = NativeCompiler()
    obj_bytes = compiler.emit_object(ir_str)
    assert len(obj_bytes) > 100  # Non-trivial binary object
    assert isinstance(obj_bytes, bytes)


def test_toolchain_detection():
    tools = NativeCompiler.check_toolchain()
    assert "clang" in tools
    assert "gcc" in tools
    assert "available" in tools["clang"]


def test_jit_execution_true_branch():
    src = """
    TARGET SYSTEM;
    LET x = 10;
    LET y = x + 5;
    IF y > 12 THEN {
        EXPORT REPORT TO "high.json";
    } ELSE {
        SCAN PROCESSES;
    }
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)
    ir_str = codegen.verify(llvm_mod)

    compiler = NativeCompiler()
    ctx = native_abi.reset_context()

    exit_code = compiler.execute_jit(ir_str)
    assert exit_code == 0
    # True branch should have executed
    assert len(ctx.executed_exports) == 1
    assert ctx.executed_exports[0] == ("REPORT", "high.json")
    # False branch should not have executed
    assert "PROCESSES" not in ctx.executed_scans


def test_jit_execution_false_branch():
    src = """
    TARGET SYSTEM;
    LET x = 2;
    LET y = x + 5;
    IF y > 12 THEN {
        EXPORT REPORT TO "high.json";
    } ELSE {
        SCAN PROCESSES;
    }
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)
    ir_str = codegen.verify(llvm_mod)

    compiler = NativeCompiler()
    ctx = native_abi.reset_context()

    exit_code = compiler.execute_jit(ir_str)
    assert exit_code == 0
    # False branch should have executed
    assert "PROCESSES" in ctx.executed_scans
    # True branch should not have executed
    assert len(ctx.executed_exports) == 0


def test_jit_execution_foreach_loop_filtering():
    src = """
    TARGET SYSTEM;
    FOREACH proc IN PROCESSES {
        IF proc.pid > 1000 THEN {
            EXPORT REPORT TO "alert.json";
        }
    }
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)
    ir_str = codegen.verify(llvm_mod)

    compiler = NativeCompiler()
    ctx = native_abi.reset_context()

    exit_code = compiler.execute_jit(ir_str)
    assert exit_code == 0
    # Exactly 2 processes in test context have pid > 1000 (1004 and 2048, not 4)
    assert len(ctx.executed_exports) == 2
    for exp in ctx.executed_exports:
        assert exp[0] == "REPORT"

