"""
JOCKY Intermediate Representation (IR) Package
Provides type definitions, instruction models, IR modules, AST to IR translation,
and IR validation.
"""
from .types import (
    IRType,
    TypeKind,
    TYPE_VOID,
    TYPE_I1,
    TYPE_I32,
    TYPE_I64,
    TYPE_F64,
    TYPE_PTR,
    TYPE_STR,
)
from .instructions import (
    IRValue,
    Register,
    ConstantInt,
    ConstantFloat,
    ConstantBool,
    ConstantString,
    ConstantNull,
    IRInstruction,
    AllocaInstr,
    LoadInstr,
    StoreInstr,
    BinaryInstr,
    CompareInstr,
    BranchInstr,
    CondBranchInstr,
    CallInstr,
    ReturnInstr,
)
from .module import BasicBlock, IRFunction, IRModule, RuntimeDeclaration
from .builder import ASTToIRConverter
from .validator import IRValidator, IRValidationError
from .printer import IRPrinter

__all__ = [
    "IRType",
    "TypeKind",
    "TYPE_VOID",
    "TYPE_I1",
    "TYPE_I32",
    "TYPE_I64",
    "TYPE_F64",
    "TYPE_PTR",
    "TYPE_STR",
    "IRValue",
    "Register",
    "ConstantInt",
    "ConstantFloat",
    "ConstantBool",
    "ConstantString",
    "ConstantNull",
    "IRInstruction",
    "AllocaInstr",
    "LoadInstr",
    "StoreInstr",
    "BinaryInstr",
    "CompareInstr",
    "BranchInstr",
    "CondBranchInstr",
    "CallInstr",
    "ReturnInstr",
    "BasicBlock",
    "IRFunction",
    "IRModule",
    "RuntimeDeclaration",
    "ASTToIRConverter",
    "IRValidator",
    "IRValidationError",
    "IRPrinter",
]

