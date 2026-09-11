"""
JOCKY IR Module Structure
Defines basic blocks, functions, and the top-level module container.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .types import IRType, TYPE_I32, TYPE_VOID
from .instructions import (
    IRInstruction,
    ConstantString,
    BranchInstr,
    CondBranchInstr,
    ReturnInstr,
)


@dataclass
class BasicBlock:
    """A sequence of linear IR instructions terminated by a branch or return."""
    name: str
    instructions: List[IRInstruction] = field(default_factory=list)

    @property
    def has_terminator(self) -> bool:
        return bool(self.instructions and self.instructions[-1].is_terminator)

    def add_instruction(self, instr: IRInstruction):
        if self.has_terminator:
            # Cannot append after terminator
            return
        self.instructions.append(instr)


@dataclass
class IRFunction:
    """A function definition in JOCKY IR."""
    name: str
    return_type: IRType = field(default=TYPE_I32)
    arguments: List[tuple] = field(default_factory=list)  # (name, IRType)
    blocks: List[BasicBlock] = field(default_factory=list)

    @property
    def entry_block(self) -> Optional[BasicBlock]:
        return self.blocks[0] if self.blocks else None

    def create_block(self, name: str) -> BasicBlock:
        # Ensure unique block name
        base_name = name
        idx = 1
        existing_names = {b.name for b in self.blocks}
        while name in existing_names:
            name = f"{base_name}_{idx}"
            idx += 1
        block = BasicBlock(name=name)
        self.blocks.append(block)
        return block


@dataclass
class RuntimeDeclaration:
    """Declaration of an external C runtime ABI function."""
    name: str
    return_type: IRType
    arg_types: List[IRType]


@dataclass
class IRModule:
    """The root container for a JOCKY compiled program."""
    name: str = "jocky_module"
    global_strings: Dict[str, ConstantString] = field(default_factory=dict)
    runtime_declarations: Dict[str, RuntimeDeclaration] = field(default_factory=dict)
    functions: Dict[str, IRFunction] = field(default_factory=dict)

    def add_string(self, text: str) -> ConstantString:
        """Intern a string literal and return its constant reference."""
        for c in self.global_strings.values():
            if c.value == text:
                return c
        global_id = f"str_{len(self.global_strings)}"
        const_str = ConstantString(value=text, global_id=global_id)
        self.global_strings[global_id] = const_str
        return const_str

    def declare_runtime_func(self, name: str, return_type: IRType, arg_types: List[IRType]):
        self.runtime_declarations[name] = RuntimeDeclaration(name, return_type, arg_types)

    def get_or_create_function(self, name: str, return_type: IRType = TYPE_I32) -> IRFunction:
        if name not in self.functions:
            self.functions[name] = IRFunction(name=name, return_type=return_type)
        return self.functions[name]

