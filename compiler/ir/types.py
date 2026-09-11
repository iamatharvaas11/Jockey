"""
JOCKY IR Type System
Represents intermediate representation types.
"""
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional


class TypeKind(Enum):
    VOID = "void"
    I1 = "i1"          # Boolean
    I32 = "i32"        # 32-bit integer
    I64 = "i64"        # 64-bit integer
    F64 = "double"     # 64-bit float
    PTR = "ptr"        # Generic pointer (opaque pointer or i8*)
    STR = "ptr"        # String pointer


@dataclass(frozen=True)
class IRType:
    kind: TypeKind
    element_type: Optional["IRType"] = None

    @property
    def is_numeric(self) -> bool:
        return self.kind in (TypeKind.I32, TypeKind.I64, TypeKind.F64)

    @property
    def is_integer(self) -> bool:
        return self.kind in (TypeKind.I1, TypeKind.I32, TypeKind.I64)

    @property
    def is_float(self) -> bool:
        return self.kind == TypeKind.F64

    @property
    def is_pointer(self) -> bool:
        return self.kind in (TypeKind.PTR, TypeKind.STR)

    def __str__(self) -> str:
        return self.kind.value


# Singleton standard types
TYPE_VOID = IRType(TypeKind.VOID)
TYPE_I1 = IRType(TypeKind.I1)
TYPE_I32 = IRType(TypeKind.I32)
TYPE_I64 = IRType(TypeKind.I64)
TYPE_F64 = IRType(TypeKind.F64)
TYPE_PTR = IRType(TypeKind.PTR)
TYPE_STR = IRType(TypeKind.STR)

