"""
Unit tests for JOCKY Intermediate Representation (IR)
Tests IR data structures, AST to IR conversion, validator, and printer.
"""
import pytest
from compiler.parser import parse
from compiler.ir import (
    IRType,
    TypeKind,
    TYPE_I1,
    TYPE_I32,
    TYPE_I64,
    TYPE_F64,
    TYPE_PTR,
    TYPE_STR,
    ConstantInt,
    ConstantFloat,
    ConstantBool,
    ConstantString,
    Register,
    AllocaInstr,
    LoadInstr,
    StoreInstr,
    BinaryInstr,
    CompareInstr,
    BranchInstr,
    CondBranchInstr,
    CallInstr,
    ReturnInstr,
    BasicBlock,
    IRFunction,
    IRModule,
    ASTToIRConverter,
    IRValidator,
    IRValidationError,
    IRPrinter,
)


def test_ir_types_and_constants():
    assert TYPE_I1.kind == TypeKind.I1
    assert TYPE_I64.is_integer
    assert TYPE_F64.is_float
    assert TYPE_PTR.is_pointer

    ci = ConstantInt(42, TYPE_I64)
    assert ci.value == 42
    assert ci.type == TYPE_I64

    cb = ConstantBool(True)
    assert cb.value is True

    cf = ConstantFloat(3.14)
    assert cf.value == 3.14


def test_ir_validator_detects_missing_terminator():
    module = IRModule(name="bad_module")
    fn = module.get_or_create_function("main")
    bb = fn.create_block("entry")
    # Add non-terminating instruction only
    bb.add_instruction(AllocaInstr(Register(TYPE_PTR, "x"), TYPE_I64))

    errors = IRValidator.validate(module)
    assert len(errors) > 0
    assert any("does not end with a terminator" in e for e in errors)

    with pytest.raises(IRValidationError):
        IRValidator.verify(module)


def test_ir_validator_detects_invalid_branch_target():
    module = IRModule(name="bad_branch")
    fn = module.get_or_create_function("main")
    bb = fn.create_block("entry")
    bb.add_instruction(BranchInstr("non_existent_block"))

    errors = IRValidator.validate(module)
    assert len(errors) > 0
    assert any("targets non-existent block" in e for e in errors)


def test_ir_printer_deterministic_output():
    module = IRModule(name="test_mod")
    fn = module.get_or_create_function("main", TYPE_I32)
    bb = fn.create_block("entry")
    bb.add_instruction(ReturnInstr(ConstantInt(0, TYPE_I32)))

    text = IRPrinter.print_module(module)
    assert "ModuleID = 'test_mod'" in text
    assert "define i32 @main() {" in text
    assert "entry:" in text
    assert "ret i32 0" in text


def test_ast_to_ir_variables_and_expressions():
    src = """
    TARGET SYSTEM;
    LET x = 10;
    LET y = x + 5;
    """
    ast = parse(src)
    converter = ASTToIRConverter()
    ir_mod = converter.convert(ast)
    IRValidator.verify(ir_mod)

    ir_text = IRPrinter.print_module(ir_mod)
    # Check variables are preserved and not zero
    assert "store i64 10" in ir_text
    assert "+ i64" in ir_text
    assert "call void @jocky_rt_init()" in ir_text
    assert "call void @jocky_set_target" in ir_text


def test_ast_to_ir_if_else_branches():
    src = """
    TARGET SYSTEM;
    LET val = 20;
    IF val > 15 THEN {
        SCAN PROCESSES;
    } ELSE {
        SCAN FILES;
    }
    """
    ast = parse(src)
    converter = ASTToIRConverter()
    ir_mod = converter.convert(ast)
    IRValidator.verify(ir_mod)

    fn = ir_mod.functions["main"]
    block_names = [b.name for b in fn.blocks]
    assert "entry" in block_names
    assert "if_then" in block_names
    assert "if_else" in block_names
    assert "if_merge" in block_names

    ir_text = IRPrinter.print_module(ir_mod)
    assert "br i1" in ir_text
    assert "jocky_scan_processes" in ir_text
    assert "jocky_scan_files" in ir_text


def test_ast_to_ir_foreach_loop_structure():
    src = """
    TARGET SYSTEM;
    FOREACH p IN PROCESSES {
        IF p.pid > 100 THEN {
            EXPORT REPORT TO "report.json";
        }
    }
    """
    ast = parse(src)
    converter = ASTToIRConverter()
    ir_mod = converter.convert(ast)
    IRValidator.verify(ir_mod)

    fn = ir_mod.functions["main"]
    block_names = [b.name for b in fn.blocks]
    assert "loop_cond" in block_names
    assert "loop_body" in block_names
    assert "loop_step" in block_names
    assert "loop_exit" in block_names

    ir_text = IRPrinter.print_module(ir_mod)
    assert "call ptr @jocky_get_collection" in ir_text
    assert "call i64 @jocky_collection_count" in ir_text
    assert "call ptr @jocky_collection_get_item" in ir_text
    assert "call i64 @jocky_entity_get_int" in ir_text

