"""
JOCKY Compiler Orchestrator
Coordinates lexing, parsing, semantic analysis, JOCKY IR generation,
LLVM IR code generation and verification, and native object compilation.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from .ast_nodes import Program
from .diagnostics import DiagnosticBag
from .parser import parse, ParserError
from .semantic_analyzer import SemanticAnalyzer
from .ir.module import IRModule
from .ir_generator import IRGenerator
from .native_compiler import NativeCompiler


@dataclass
class CompileResult:
    success: bool
    ast: Optional[Program] = None
    jocky_ir: Optional[IRModule] = None
    ir_code: Optional[str] = None
    object_bytes: Optional[bytes] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    diagnostics: Optional[DiagnosticBag] = None

    @property
    def llvm_ir(self) -> Optional[str]:
        return self.ir_code


class JockyCompiler:
    def __init__(self):
        self.semantic_analyzer = SemanticAnalyzer()
        self.ir_generator = IRGenerator()
        self.native_compiler = NativeCompiler()

    def compile(
        self,
        source: str,
        filename: Optional[str] = None,
        emit_object: bool = False,
    ) -> CompileResult:
        # Phase 1: Parse AST
        try:
            ast = parse(source, filename=filename)
        except ParserError as pe:
            return CompileResult(
                success=False,
                ast=None,
                errors=[pe.diagnostic.format()],
                warnings=[],
            )
        except Exception as e:
            return CompileResult(False, None, errors=[str(e)])

        # Phase 2: Semantic Analysis
        diag_bag = self.semantic_analyzer.analyze_diagnostics(ast)
        errors = [d.format() for d in diag_bag.errors]
        warnings = [d.format() for d in diag_bag.warnings]

        if diag_bag.has_errors:
            return CompileResult(
                success=False,
                ast=ast,
                errors=errors,
                warnings=warnings,
                diagnostics=diag_bag,
            )

        # Phase 3: JOCKY IR Generation & Verification
        try:
            jocky_ir = self.ir_generator.build_jocky_ir(ast)
        except Exception as e:
            return CompileResult(
                success=False,
                ast=ast,
                errors=[f"JOCKY IR generation failed: {e}"],
                warnings=warnings,
                diagnostics=diag_bag,
            )

        # Phase 4: LLVM IR Generation & Verification
        try:
            llvm_module = self.ir_generator.llvm_codegen.generate(jocky_ir)
            llvm_ir_str = self.ir_generator.llvm_codegen.verify(llvm_module)
        except Exception as e:
            return CompileResult(
                success=False,
                ast=ast,
                jocky_ir=jocky_ir,
                errors=[f"LLVM generation or verification failed: {e}"],
                warnings=warnings,
                diagnostics=diag_bag,
            )

        # Phase 5: Optional Native Object Code Emission
        obj_bytes = None
        if emit_object:
            try:
                obj_bytes = self.native_compiler.emit_object(llvm_ir_str)
            except Exception as e:
                return CompileResult(
                    success=False,
                    ast=ast,
                    jocky_ir=jocky_ir,
                    ir_code=llvm_ir_str,
                    errors=[f"Native object compilation failed: {e}"],
                    warnings=warnings,
                    diagnostics=diag_bag,
                )

        return CompileResult(
            success=True,
            ast=ast,
            jocky_ir=jocky_ir,
            ir_code=llvm_ir_str,
            object_bytes=obj_bytes,
            errors=errors,
            warnings=warnings,
            diagnostics=diag_bag,
        )

    def compile_file(
        self,
        filepath: str,
        emit_object: bool = False,
    ) -> CompileResult:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        return self.compile(source, filename=filepath, emit_object=emit_object)
