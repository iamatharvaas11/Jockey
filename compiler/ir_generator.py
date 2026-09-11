"""
JOCKY IR Generator Pipeline
Coordinates translation from JOCKY AST to JOCKY Intermediate Representation (IR),
runs IR validation, and generates verified LLVM IR.
"""
from .ast_nodes import Program
from .ir.builder import ASTToIRConverter
from .ir.module import IRModule
from .ir.validator import IRValidator
from .llvm_codegen import LLVMCodeGenerator, LLVMVerificationError


class IRGenerator:
    """Generates verified LLVM IR from a JOCKY Program AST."""

    def __init__(self):
        self.llvm_codegen = LLVMCodeGenerator()

    def build_jocky_ir(self, ast: Program, module_name: str = "jocky_program") -> IRModule:
        """Convert AST into validated JOCKY IR."""
        converter = ASTToIRConverter(module_name=module_name)
        ir_module = converter.convert(ast)
        IRValidator.verify(ir_module)
        return ir_module

    def generate(self, ast: Program, module_name: str = "jocky_program") -> str:
        """Translate AST through JOCKY IR into verified LLVM IR assembly string."""
        ir_module = self.build_jocky_ir(ast, module_name=module_name)
        llvm_module = self.llvm_codegen.generate(ir_module)
        return self.llvm_codegen.verify(llvm_module)
