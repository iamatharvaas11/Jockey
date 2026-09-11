"""
JOCKY Abstract Syntax Tree (AST) Node Definitions.
Every AST node represents a structural element of the JOCKY DSL and
preserves its SourceLocation for diagnostics and debugging.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Any, Union
from .diagnostics import SourceLocation


@dataclass
class ASTNode:
    """Base class for all AST nodes."""
    location: Optional[SourceLocation] = field(default=None, compare=False)

    def pretty(self, indent: int = 0) -> str:
        """Pretty-print the AST node and its children deterministically."""
        prefix = "  " * indent
        loc_str = f" @ [{self.location.line}:{self.location.column}]" if self.location else ""
        fields = []
        for k, v in self.__dict__.items():
            if k == "location":
                continue
            if isinstance(v, list):
                if not v:
                    fields.append(f"{k}=[]")
                else:
                    lines = [f"{prefix}  {k}=["]
                    for item in v:
                        if isinstance(item, ASTNode):
                            lines.append(item.pretty(indent + 2))
                        else:
                            lines.append(f"{prefix}    {repr(item)}")
                    lines.append(f"{prefix}  ]")
                    fields.append("\n" + "\n".join(lines))
            elif isinstance(v, ASTNode):
                fields.append(f"\n{prefix}  {k}=" + v.pretty(indent + 1).lstrip())
            else:
                fields.append(f"{k}={repr(v)}")
        
        field_str = ", ".join(f for f in fields if not f.startswith("\n"))
        multiline_fields = [f for f in fields if f.startswith("\n")]
        res = f"{prefix}{self.__class__.__name__}({field_str}){loc_str}"
        if multiline_fields:
            res += "".join(multiline_fields)
        return res


@dataclass
class Program(ASTNode):
    """Root node of a JOCKY program."""
    statements: List[ASTNode] = field(default_factory=list)


@dataclass
class TargetStmt(ASTNode):
    """TARGET statement declaring the host environment."""
    target_type: str = "SYSTEM"  # SYSTEM, ALL, REMOTE
    hostname: Optional[str] = None


@dataclass
class Condition(ASTNode):
    """Condition node for filters and conditional branching."""
    left: Any = None
    operator: str = "=="
    right: Any = None


@dataclass
class BinaryExpr(ASTNode):
    """Binary expression (logical, comparison, arithmetic)."""
    left: Any = None
    operator: str = "=="
    right: Any = None


@dataclass
class UnaryExpr(ASTNode):
    """Unary expression (e.g. NOT)."""
    operator: str = "NOT"
    operand: Any = None


@dataclass
class ScanStmt(ASTNode):
    """SCAN statement to collect forensic data."""
    scan_target: str = "PROCESSES"
    condition: Optional[Condition] = None


@dataclass
class FindStmt(ASTNode):
    """FIND statement to match IOCs, malware, or suspicious patterns."""
    find_target: str = "IOC"


@dataclass
class BuildStmt(ASTNode):
    """BUILD statement to construct timeline, correlations, or process graphs."""
    build_target: str = "TIMELINE"


@dataclass
class ExportStmt(ASTNode):
    """EXPORT statement to output reports, evidence manifests, or timelines."""
    export_target: str = "REPORT"
    path: Optional[str] = None


@dataclass
class SetStmt(ASTNode):
    """SET statement to modify configuration variables."""
    name: str = ""
    value: Any = None


@dataclass
class VarAssign(ASTNode):
    """LET statement to declare a new local variable."""
    name: str = ""
    value: Any = None


@dataclass
class FilterStmt(ASTNode):
    """FILTER statement to refine evidence collections."""
    condition: Condition = field(default_factory=Condition)


@dataclass
class IfStmt(ASTNode):
    """IF statement for conditional workflow logic."""
    condition: Condition = field(default_factory=Condition)
    body: List[ASTNode] = field(default_factory=list)
    else_body: Optional[List[ASTNode]] = None


@dataclass
class ForEachStmt(ASTNode):
    """FOREACH loop iterating over an evidence collection."""
    var_name: str = ""
    source: str = ""
    body: List[ASTNode] = field(default_factory=list)


@dataclass
class Identifier(ASTNode):
    """Variable or entity reference."""
    name: str = ""


@dataclass
class PropertyAccess(ASTNode):
    """Property access on an object (e.g. proc.pid, conn.remote_ip)."""
    obj: str = ""
    prop: str = ""


@dataclass
class StringLiteral(ASTNode):
    """String literal."""
    value: str = ""


@dataclass
class NumberLiteral(ASTNode):
    """Numeric literal (integer or floating point)."""
    value: Union[int, float] = 0


@dataclass
class BoolLiteral(ASTNode):
    """Boolean literal."""
    value: bool = False
