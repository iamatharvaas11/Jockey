"""
JOCKY IR Text Printer
Formats an IRModule into a deterministic, human-readable assembly-like string.
"""
from .module import IRModule, IRFunction, BasicBlock
from .instructions import (
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


class IRPrinter:
    """Formats an IRModule into a deterministic string representation."""

    @classmethod
    def print_module(cls, module: IRModule) -> str:
        lines = [f"; ModuleID = '{module.name}'", ""]

        # 1. Global strings
        if module.global_strings:
            lines.append("; --- Global Constants ---")
            for gid, cstr in sorted(module.global_strings.items()):
                escaped = cstr.value.replace("\n", "\\n").replace('"', '\\"')
                lines.append(f'@{gid} = private constant string "{escaped}"')
            lines.append("")

        # 2. Runtime declarations
        if module.runtime_declarations:
            lines.append("; --- External Runtime Declarations ---")
            for name, decl in sorted(module.runtime_declarations.items()):
                args_str = ", ".join(str(t) for t in decl.arg_types)
                lines.append(f"declare {decl.return_type} @{name}({args_str})")
            lines.append("")

        # 3. Function definitions
        for fname, func in module.functions.items():
            args_str = ", ".join(f"{t} %{arg}" for arg, t in func.arguments)
            lines.append(f"define {func.return_type} @{fname}({args_str}) {{")

            for block in func.blocks:
                lines.append(f"{block.name}:")
                for instr in block.instructions:
                    lines.append(f"  {cls._format_instruction(instr)}")
            lines.append("}")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def _format_instruction(cls, instr: IRInstruction) -> str:
        if isinstance(instr, AllocaInstr):
            return f"{instr.result} = alloca {instr.allocated_type}"
        elif isinstance(instr, LoadInstr):
            return f"{instr.result} = load {instr.result.type}, ptr {instr.ptr}"
        elif isinstance(instr, StoreInstr):
            return f"store {instr.value.type} {cls._val(instr.value)}, ptr {instr.ptr}"
        elif isinstance(instr, BinaryInstr):
            return f"{instr.result} = {instr.op} {instr.left.type} {cls._val(instr.left)}, {cls._val(instr.right)}"
        elif isinstance(instr, CompareInstr):
            return f"{instr.result} = cmp {instr.op} {instr.left.type} {cls._val(instr.left)}, {cls._val(instr.right)}"
        elif isinstance(instr, BranchInstr):
            return f"br label %{instr.target}"
        elif isinstance(instr, CondBranchInstr):
            return f"br i1 {cls._val(instr.condition)}, label %{instr.true_target}, label %{instr.false_target}"
        elif isinstance(instr, CallInstr):
            args_str = ", ".join(f"{arg.type} {cls._val(arg)}" for arg in instr.args)
            if instr.result:
                return f"{instr.result} = call {instr.return_type} @{instr.func_name}({args_str})"
            return f"call {instr.return_type} @{instr.func_name}({args_str})"
        elif isinstance(instr, ReturnInstr):
            if instr.value is not None:
                return f"ret {instr.value.type} {cls._val(instr.value)}"
            return "ret void"
        return str(instr)

    @classmethod
    def _val(cls, val) -> str:
        if hasattr(val, "global_id"):
            return f"@{val.global_id}"
        if hasattr(val, "name"):
            return f"%{val.name}"
        if hasattr(val, "value"):
            if isinstance(val.value, bool):
                return "true" if val.value else "false"
            return str(val.value)
        return str(val)
