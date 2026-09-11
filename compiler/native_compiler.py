"""
JOCKY Native Compiler and Toolchain Integration
Handles object code generation, assembly emission, toolchain detection,
and JIT execution using llvmlite and native platform tools.
"""
import ctypes
import os
import shutil
import subprocess
from typing import Dict, Optional, Tuple, Any

import llvmlite.binding as llvm_binding

from .diagnostics import DiagnosticCode
from runtime.native_abi import ABI_SYMBOLS, reset_context, CURRENT_CONTEXT


class NativeCompilerError(Exception):
    """Raised when native compilation fails."""
    def __init__(self, message: str, code: DiagnosticCode = DiagnosticCode.SYNTAX_ERROR):
        super().__init__(message)
        self.message = message
        self.code = code


class NativeCompiler:
    """Manages machine code generation, toolchain detection, and execution."""

    def __init__(self):
        self._init_llvm()

    def _init_llvm(self):
        llvm_binding.initialize_native_target()
        llvm_binding.initialize_native_asmprinter()
        self._register_abi_symbols()

    def _register_abi_symbols(self):
        """Register runtime ABI callbacks with the LLVM dynamic loader."""
        for name, func in ABI_SYMBOLS.items():
            try:
                addr = ctypes.cast(func, ctypes.c_void_p).value
                if addr:
                    llvm_binding.add_symbol(name, addr)
            except Exception:
                pass

    @classmethod
    def check_toolchain(cls) -> Dict[str, Dict[str, Any]]:
        """Detect available system compilation tools."""
        tools = {}
        for tool in ["clang", "llc", "lld", "gcc"]:
            path = shutil.which(tool)
            if path:
                try:
                    res = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
                    first_line = res.stdout.splitlines()[0] if res.stdout else "available"
                    tools[tool] = {"available": True, "path": path, "version": first_line}
                except Exception:
                    tools[tool] = {"available": True, "path": path, "version": "unknown"}
            else:
                tools[tool] = {"available": False, "path": None, "version": None}
        return tools

    def emit_object(self, llvm_ir_str: str, opt_level: int = 2) -> bytes:
        """Compile verified LLVM IR to native object file bytes (.obj on Windows, .o on Linux)."""
        parsed = llvm_binding.parse_assembly(llvm_ir_str)
        target = llvm_binding.Target.from_default_triple()
        machine = target.create_target_machine(opt=opt_level)
        return machine.emit_object(parsed)

    def emit_assembly(self, llvm_ir_str: str, opt_level: int = 2) -> str:
        """Compile verified LLVM IR to target assembly text (.asm / .s)."""
        parsed = llvm_binding.parse_assembly(llvm_ir_str)
        target = llvm_binding.Target.from_default_triple()
        machine = target.create_target_machine(opt=opt_level)
        return machine.emit_assembly(parsed)

    def execute_jit(self, llvm_ir_str: str) -> int:
        """
        Execute compiled LLVM IR in-process via MCJIT compiler,
        linked against the native runtime ABI.
        Returns the integer exit code of main().
        """
        self._register_abi_symbols()
        parsed = llvm_binding.parse_assembly(llvm_ir_str)
        target = llvm_binding.Target.from_default_triple()
        machine = target.create_target_machine()
        engine = llvm_binding.create_mcjit_compiler(parsed, machine)
        engine.finalize_object()

        main_ptr = engine.get_function_address("main")
        if not main_ptr:
            raise NativeCompilerError("Entry point 'main' not found in compiled module.")

        main_func = ctypes.CFUNCTYPE(ctypes.c_int32)(main_ptr)
        return main_func()

    def compile_to_file(
        self,
        llvm_ir_str: str,
        output_path: str,
        emit_type: str = "object",
    ) -> str:
        """
        Write compiled artifact to disk.

        Args:
            llvm_ir_str: Verified LLVM IR assembly string.
            output_path: Target filepath.
            emit_type: 'llvm' (.ll), 'object' (.obj/.o), or 'asm' (.s/.asm).
        """
        if emit_type == "llvm":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(llvm_ir_str)
            return output_path

        elif emit_type == "asm":
            asm_text = self.emit_assembly(llvm_ir_str)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(asm_text)
            return output_path

        elif emit_type == "object":
            obj_bytes = self.emit_object(llvm_ir_str)
            with open(output_path, "wb") as f:
                f.write(obj_bytes)
            return output_path

        else:
            raise NativeCompilerError(f"Unsupported emit type '{emit_type}'.")
