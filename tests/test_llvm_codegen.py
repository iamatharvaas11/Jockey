"""
Unit tests for LLVM IR code generator and verification
"""
import pytest
from compiler.parser import parse
from compiler.ir import ASTToIRConverter
from compiler.llvm_codegen import LLVMCodeGenerator, LLVMVerificationError


def test_llvm_generation_and_verification_basic():
    src = """
    TARGET SYSTEM;
    LET a = 10;
    LET b = 20;
    LET c = a + b;
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)

    # Must pass strict LLVM verification
    ir_str = codegen.verify(llvm_mod)
    assert 'define i32 @"main"()' in ir_str
    assert "add i64" in ir_str
    assert "store i64 10" in ir_str
    assert "store i64 20" in ir_str


def test_llvm_generation_branching():
    src = """
    TARGET SYSTEM;
    LET score = 50;
    IF score >= 50 THEN {
        EXPORT REPORT TO "pass.json";
    } ELSE {
        SCAN ALL;
    }
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)
    ir_str = codegen.verify(llvm_mod)

    assert "icmp sge i64" in ir_str
    assert 'br i1 %"cmp_' in ir_str
    assert "if_then:" in ir_str
    assert "if_else:" in ir_str
    assert "if_merge:" in ir_str
    assert "pass.json" in ir_str


def test_llvm_generation_loop_and_calls():
    src = """
    TARGET SYSTEM;
    FOREACH net IN NETWORK {
        IF net.local_port == 80 THEN {
            EXPORT EVIDENCE TO "evidence.bin";
        }
    }
    """
    ast = parse(src)
    ir_mod = ASTToIRConverter().convert(ast)
    codegen = LLVMCodeGenerator()
    llvm_mod = codegen.generate(ir_mod)
    ir_str = codegen.verify(llvm_mod)

    assert "jocky_get_collection" in ir_str
    assert "jocky_collection_count" in ir_str
    assert "jocky_collection_get_item" in ir_str
    assert "jocky_entity_get_int" in ir_str
    assert "icmp eq i64" in ir_str
    assert "loop_cond:" in ir_str
    assert "loop_body:" in ir_str
    assert "loop_step:" in ir_str
    assert "loop_exit:" in ir_str


def test_llvm_verification_detects_malformed_ir():
    from llvmlite import ir
    m = ir.Module(name="bad_llvm")
    fn = ir.Function(m, ir.FunctionType(ir.IntType(32), []), name="bad_fn")
    # Block with no terminator
    fn.append_basic_block("entry")

    with pytest.raises(LLVMVerificationError):
        LLVMCodeGenerator.verify(m)
