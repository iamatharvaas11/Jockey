"""
JOCKY IR Values and Instructions
Defines the instruction set and operands for the intermediate representation.
"""
from dataclasses import dataclass, field
from typing import Any, List, Optional
from .types import IRType, TYPE_I1, TYPE_I32, TYPE_I64, TYPE_F64, TYPE_STR, TYPE_PTR, TYPE_VOID


@dataclass
class IRValue:
    """Base class for values in JOCKY IR."""
    type: IRType = field(default=TYPE_VOID)


@dataclass
class Register(IRValue):
    """A virtual SSA register (%0, %1, %x, etc.)."""
    name: str = ""
    type: IRType = field(default=TYPE_I64)

    def __init__(self, type: IRType = TYPE_I64, name: str = ""):
        self.type = type
        self.name = name

    def __str__(self) -> str:
        return f"%{self.name}"


@dataclass
class ConstantInt(IRValue):
    """An integer constant."""
    value: int = 0
    type: IRType = field(default=TYPE_I64)

    def __init__(self, value: int = 0, type: IRType = TYPE_I64):
        self.value = value
        self.type = type

    def __str__(self) -> str:
        return f"{self.type} {self.value}"


@dataclass
class ConstantFloat(IRValue):
    """A floating-point constant."""
    value: float = 0.0
    type: IRType = field(default=TYPE_F64)

    def __init__(self, value: float = 0.0, type: IRType = TYPE_F64):
        self.value = value
        self.type = type

    def __str__(self) -> str:
        return f"{self.type} {self.value}"


@dataclass
class ConstantBool(IRValue):
    """A boolean constant."""
    value: bool = False
    type: IRType = field(default=TYPE_I1)

    def __init__(self, value: bool = False, type: IRType = TYPE_I1):
        self.value = value
        self.type = type

    def __str__(self) -> str:
        val_str = "true" if self.value else "false"
        return f"{self.type} {val_str}"


@dataclass
class ConstantString(IRValue):
    """A pointer to a string constant in the global string table."""
    value: str = ""
    global_id: str = ""
    type: IRType = field(default=TYPE_STR)

    def __init__(self, value: str = "", global_id: str = "", type: IRType = TYPE_STR):
        self.value = value
        self.global_id = global_id
        self.type = type

    def __str__(self) -> str:
        escaped = self.value.replace("\n", "\\n").replace('"', '\\"')
        return f'@{self.global_id} = "{escaped}"'


@dataclass
class ConstantNull(IRValue):
    """A null pointer constant."""
    type: IRType = field(default=TYPE_PTR)

    def __str__(self) -> str:
        return f"{self.type} null"


# ============================================================================
# Instructions
# ============================================================================

@dataclass
class IRInstruction:
    """Base class for all IR instructions."""
    result: Optional[Register] = None

    @property
    def is_terminator(self) -> bool:
        return False


@dataclass
class AllocaInstr(IRInstruction):
    """Stack allocation instruction: %res = alloca <type>"""
    allocated_type: IRType = field(default=TYPE_I64)

    def __str__(self) -> str:
        return f"{self.result} = alloca {self.allocated_type}"


@dataclass
class LoadInstr(IRInstruction):
    """Memory load instruction: %res = load <type>, ptr %ptr"""
    ptr: Register = field(default_factory=lambda: Register(TYPE_PTR, ""))

    def __str__(self) -> str:
        return f"{self.result} = load {self.result.type}, ptr {self.ptr}"


@dataclass
class StoreInstr(IRInstruction):
    """Memory store instruction: store <type> %val, ptr %ptr"""
    value: IRValue = field(default_factory=lambda: ConstantInt(0))
    ptr: Register = field(default_factory=lambda: Register(TYPE_PTR, ""))

    def __init__(self, value: IRValue, ptr: Register):
        super().__init__(result=None)
        self.value = value
        self.ptr = ptr

    def __str__(self) -> str:
        return f"store {self.value.type} {self.value}, ptr {self.ptr}"


@dataclass
class BinaryInstr(IRInstruction):
    """Binary arithmetic and logical instruction: %res = <op> <type> %left, %right"""
    op: str = "+"  # +, -, *, /, AND, OR
    left: IRValue = field(default_factory=lambda: ConstantInt(0))
    right: IRValue = field(default_factory=lambda: ConstantInt(0))

    def __str__(self) -> str:
        return f"{self.result} = {self.op} {self.left.type} {self.left}, {self.right}"


@dataclass
class CompareInstr(IRInstruction):
    """Comparison instruction: %res = cmp <op> <type> %left, %right"""
    op: str = "=="  # ==, !=, <, <=, >, >=, CONTAINS
    left: IRValue = field(default_factory=lambda: ConstantInt(0))
    right: IRValue = field(default_factory=lambda: ConstantInt(0))

    def __str__(self) -> str:
        return f"{self.result} = cmp {self.op} {self.left.type} {self.left}, {self.right}"


@dataclass
class BranchInstr(IRInstruction):
    """Unconditional branch: br label %target"""
    target: str = ""

    def __init__(self, target: str = ""):
        super().__init__(result=None)
        self.target = target

    @property
    def is_terminator(self) -> bool:
        return True

    def __str__(self) -> str:
        return f"br label %{self.target}"


@dataclass
class CondBranchInstr(IRInstruction):
    """Conditional branch: br i1 %cond, label %true_target, label %false_target"""
    condition: IRValue = field(default_factory=lambda: ConstantBool(True))
    true_target: str = ""
    false_target: str = ""

    def __init__(self, condition: IRValue, true_target: str = "", false_target: str = ""):
        super().__init__(result=None)
        self.condition = condition
        self.true_target = true_target
        self.false_target = false_target

    @property
    def is_terminator(self) -> bool:
        return True

    def __str__(self) -> str:
        return f"br i1 {self.condition}, label %{self.true_target}, label %{self.false_target}"


@dataclass
class CallInstr(IRInstruction):
    """Function call instruction: %res = call <ret_type> @func(args...)"""
    func_name: str = ""
    args: List[IRValue] = field(default_factory=list)
    return_type: IRType = field(default=TYPE_VOID)

    def __str__(self) -> str:
        arg_str = ", ".join(f"{arg.type} {arg}" for arg in self.args)
        if self.result:
            return f"{self.result} = call {self.return_type} @{self.func_name}({arg_str})"
        return f"call {self.return_type} @{self.func_name}({arg_str})"


@dataclass
class ReturnInstr(IRInstruction):
    """Function return instruction: ret <type> %val or ret void"""
    value: Optional[IRValue] = None

    def __init__(self, value: Optional[IRValue] = None):
        super().__init__(result=None)
        self.value = value

    @property
    def is_terminator(self) -> bool:
        return True

    def __str__(self) -> str:
        if self.value is not None:
            return f"ret {self.value.type} {self.value}"
        return "ret void"
