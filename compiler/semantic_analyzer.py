"""
JOCKY Semantic Analyzer
Performs symbol resolution, scope management, type checking, target validation,
collector validation, and property access verification.
Reports structured diagnostics with line, column, error code, and hints.
"""
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

from .ast_nodes import (
    ASTNode,
    BinaryExpr,
    BoolLiteral,
    BuildStmt,
    Condition,
    ExportStmt,
    FilterStmt,
    FindStmt,
    ForEachStmt,
    Identifier,
    IfStmt,
    NumberLiteral,
    Program,
    PropertyAccess,
    ScanStmt,
    SetStmt,
    StringLiteral,
    TargetStmt,
    UnaryExpr,
    VarAssign,
)
from .diagnostics import (
    Diagnostic,
    DiagnosticBag,
    DiagnosticCode,
    DiagnosticSeverity,
    SourceLocation,
)


class JockyType(Enum):
    STRING = "STRING"
    INT = "INT"
    FLOAT = "FLOAT"
    BOOL = "BOOL"
    COLLECTION = "COLLECTION"
    PROCESS_ENTITY = "PROCESS"
    NETWORK_ENTITY = "NETWORK"
    FILE_ENTITY = "FILE"
    EVENTLOG_ENTITY = "EVENTLOG"
    REGISTRY_ENTITY = "REGISTRY"
    ALERT_ENTITY = "ALERT"
    ANY = "ANY"
    UNKNOWN = "UNKNOWN"

    def is_numeric(self) -> bool:
        return self in (JockyType.INT, JockyType.FLOAT)


# Supported collectors and targets
VALID_SCAN_TARGETS: Set[str] = {"PROCESSES", "FILES", "NETWORK", "EVENTLOGS", "REGISTRY", "ALL"}
VALID_FIND_TARGETS: Set[str] = {"IOC", "SUSPICIOUS", "MALWARE", "PERSISTENCE"}
VALID_BUILD_TARGETS: Set[str] = {"TIMELINE", "CORRELATIONS", "PROCESSGRAPH"}
VALID_EXPORT_TARGETS: Set[str] = {"REPORT", "EVIDENCE", "TIMELINE"}
VALID_LOOP_SOURCES: Set[str] = {"PROCESSES", "FILES", "NETWORK", "EVENTLOGS", "REGISTRY"}

# Supported configuration settings for SET
VALID_CONFIG_SETTINGS: Set[str] = {
    "output_format",
    "severity_threshold",
    "timeout",
    "hash_algorithm",
    "max_depth",
    "case_id",
    "investigator",
}

# Property definitions for evidence entities
ENTITY_PROPERTIES: Dict[JockyType, Dict[str, JockyType]] = {
    JockyType.PROCESS_ENTITY: {
        "pid": JockyType.INT,
        "ppid": JockyType.INT,
        "name": JockyType.STRING,
        "exe_path": JockyType.STRING,
        "cmdline": JockyType.STRING,
        "username": JockyType.STRING,
        "created_time": JockyType.STRING,
        "status": JockyType.STRING,
        "threads": JockyType.INT,
        "memory_bytes": JockyType.INT,
    },
    JockyType.NETWORK_ENTITY: {
        "protocol": JockyType.STRING,
        "local_ip": JockyType.STRING,
        "local_port": JockyType.INT,
        "remote_ip": JockyType.STRING,
        "remote_port": JockyType.INT,
        "status": JockyType.STRING,
        "pid": JockyType.INT,
    },
    JockyType.FILE_ENTITY: {
        "path": JockyType.STRING,
        "size": JockyType.INT,
        "created_time": JockyType.STRING,
        "modified_time": JockyType.STRING,
        "accessed_time": JockyType.STRING,
        "permissions": JockyType.STRING,
        "md5": JockyType.STRING,
        "sha256": JockyType.STRING,
    },
    JockyType.EVENTLOG_ENTITY: {
        "source": JockyType.STRING,
        "event_id": JockyType.INT,
        "timestamp": JockyType.STRING,
        "level": JockyType.STRING,
        "message": JockyType.STRING,
    },
    JockyType.REGISTRY_ENTITY: {
        "key": JockyType.STRING,
        "value_name": JockyType.STRING,
        "value_data": JockyType.STRING,
        "value_type": JockyType.STRING,
        "modified_time": JockyType.STRING,
    },
    JockyType.ALERT_ENTITY: {
        "type": JockyType.STRING,
        "severity": JockyType.STRING,
        "details": JockyType.STRING,
        "timestamp": JockyType.STRING,
    },
}

SOURCE_TO_ENTITY_TYPE: Dict[str, JockyType] = {
    "PROCESSES": JockyType.PROCESS_ENTITY,
    "NETWORK": JockyType.NETWORK_ENTITY,
    "FILES": JockyType.FILE_ENTITY,
    "EVENTLOGS": JockyType.EVENTLOG_ENTITY,
    "REGISTRY": JockyType.REGISTRY_ENTITY,
}


@dataclass
class Symbol:
    """Symbol entry in symbol table."""
    name: str
    type: JockyType
    location: Optional[SourceLocation] = None
    is_constant: bool = False
    is_used: bool = False


class Scope:
    """Lexical scope with parent chain for variable lookup."""

    def __init__(self, name: str, parent: Optional["Scope"] = None):
        self.name = name
        self.parent = parent
        self.symbols: Dict[str, Symbol] = {}

    def define(self, symbol: Symbol) -> bool:
        """Define a symbol in this scope. Returns False if already defined locally."""
        if symbol.name in self.symbols:
            return False
        self.symbols[symbol.name] = symbol
        return True

    def lookup(self, name: str) -> Optional[Symbol]:
        """Search current scope and parent scopes recursively."""
        if name in self.symbols:
            self.symbols[name].is_used = True
            return self.symbols[name]
        if self.parent:
            return self.parent.lookup(name)
        return None

    def lookup_local(self, name: str) -> Optional[Symbol]:
        """Search only the local scope."""
        return self.symbols.get(name)


class SemanticAnalyzer:
    """
    Validates JOCKY Abstract Syntax Trees against language rules,
    type compatibility, scoping constraints, and forensic target requirements.
    """

    def __init__(self):
        self.diagnostics = DiagnosticBag()
        self.current_scope: Scope = Scope("global")
        self.has_target: bool = False
        self.target_type: Optional[str] = None
        self._current_scan_target: Optional[str] = None

    def analyze(self, ast: Program) -> Tuple[List[str], List[str]]:
        """
        Backwards-compatible interface returning string lists of errors and warnings.
        """
        diag_bag = self.analyze_diagnostics(ast)
        errors = [d.format() for d in diag_bag.errors]
        warnings = [d.format() for d in diag_bag.warnings]
        return errors, warnings

    def analyze_diagnostics(self, ast: Program) -> DiagnosticBag:
        """Analyze AST and return full diagnostic bag."""
        self.diagnostics = DiagnosticBag()
        self.current_scope = Scope("global")
        self.has_target = False
        self.target_type = None
        self._current_scan_target = None

        self.visit(ast)
        return self.diagnostics

    def visit(self, node: Any):
        if node is None:
            return
        method_name = f"visit_{node.__class__.__name__}"
        visitor = getattr(self, method_name, self.generic_visit)
        visitor(node)

    def generic_visit(self, node: Any):
        if hasattr(node, "__dict__"):
            for child in node.__dict__.values():
                if isinstance(child, list):
                    for item in child:
                        if isinstance(item, ASTNode):
                            self.visit(item)
                elif isinstance(child, ASTNode):
                    self.visit(child)

    def visit_Program(self, node: Program):
        for stmt in node.statements:
            self.visit(stmt)

        # Check if any forensic command occurred without target
        if not self.has_target and any(
            isinstance(s, (ScanStmt, FindStmt, BuildStmt, ExportStmt))
            for s in node.statements
        ):
            loc = node.statements[0].location if node.statements else node.location
            self.diagnostics.error(
                DiagnosticCode.SEM_MISSING_TARGET,
                "Program contains forensic operations but is missing a TARGET declaration.",
                loc,
                hint="Add 'TARGET SYSTEM;' or 'TARGET REMOTE \"host\";' at the beginning of the workflow.",
            )

    def visit_TargetStmt(self, node: TargetStmt):
        if self.has_target:
            self.diagnostics.warning(
                DiagnosticCode.SEM_DUPLICATE_TARGET,
                f"Redundant TARGET statement. Target was already set to '{self.target_type}'.",
                node.location,
                hint="Specify TARGET only once per investigation script.",
            )

        valid_types = {"SYSTEM", "ALL", "REMOTE"}
        if node.target_type not in valid_types:
            self.diagnostics.error(
                DiagnosticCode.SEM_INVALID_TARGET,
                f"Invalid target type '{node.target_type}'. Expected one of: {', '.join(sorted(valid_types))}.",
                node.location,
                hint="Use 'TARGET SYSTEM;' or 'TARGET REMOTE \"<host>\";'.",
            )
        else:
            self.has_target = True
            self.target_type = node.target_type

    def visit_ScanStmt(self, node: ScanStmt):
        if not self.has_target:
            self.diagnostics.error(
                DiagnosticCode.SEM_MISSING_TARGET,
                f"SCAN {node.scan_target} executed before TARGET is defined.",
                node.location,
                hint="Declare 'TARGET SYSTEM;' before performing scans.",
            )

        if node.scan_target not in VALID_SCAN_TARGETS:
            self.diagnostics.error(
                DiagnosticCode.SEM_UNSUPPORTED_COLLECTOR,
                f"Unsupported scan target '{node.scan_target}'. Supported: {', '.join(sorted(VALID_SCAN_TARGETS))}.",
                node.location,
                hint=f"Use one of: {', '.join(sorted(VALID_SCAN_TARGETS))}.",
            )

        if node.condition:
            self._current_scan_target = node.scan_target
            self.visit(node.condition)
            self._current_scan_target = None

    def visit_FindStmt(self, node: FindStmt):
        if not self.has_target:
            self.diagnostics.error(
                DiagnosticCode.SEM_MISSING_TARGET,
                f"FIND {node.find_target} executed before TARGET is defined.",
                node.location,
                hint="Declare 'TARGET SYSTEM;' before searching for artifacts.",
            )

        if node.find_target not in VALID_FIND_TARGETS:
            self.diagnostics.error(
                DiagnosticCode.SEM_UNSUPPORTED_FIND_TARGET,
                f"Unsupported find target '{node.find_target}'. Supported: {', '.join(sorted(VALID_FIND_TARGETS))}.",
                node.location,
                hint=f"Use one of: {', '.join(sorted(VALID_FIND_TARGETS))}.",
            )

    def visit_BuildStmt(self, node: BuildStmt):
        if not self.has_target:
            self.diagnostics.error(
                DiagnosticCode.SEM_MISSING_TARGET,
                f"BUILD {node.build_target} executed before TARGET is defined.",
                node.location,
                hint="Declare 'TARGET SYSTEM;' before building correlation models.",
            )

        if node.build_target not in VALID_BUILD_TARGETS:
            self.diagnostics.error(
                DiagnosticCode.SEM_UNSUPPORTED_BUILD_TARGET,
                f"Unsupported build target '{node.build_target}'. Supported: {', '.join(sorted(VALID_BUILD_TARGETS))}.",
                node.location,
                hint=f"Use one of: {', '.join(sorted(VALID_BUILD_TARGETS))}.",
            )

    def visit_ExportStmt(self, node: ExportStmt):
        if not self.has_target:
            self.diagnostics.error(
                DiagnosticCode.SEM_MISSING_TARGET,
                f"EXPORT {node.export_target} executed before TARGET is defined.",
                node.location,
                hint="Declare 'TARGET SYSTEM;' before exporting artifacts.",
            )

        if node.export_target not in VALID_EXPORT_TARGETS:
            self.diagnostics.error(
                DiagnosticCode.SEM_UNSUPPORTED_EXPORT_TARGET,
                f"Unsupported export target '{node.export_target}'. Supported: {', '.join(sorted(VALID_EXPORT_TARGETS))}.",
                node.location,
                hint=f"Use one of: {', '.join(sorted(VALID_EXPORT_TARGETS))}.",
            )

    def visit_VarAssign(self, node: VarAssign):
        """LET statement: defines a new variable in the current scope."""
        val_type = self._infer_type(node.value)
        symbol = Symbol(name=node.name, type=val_type, location=node.location)

        if not self.current_scope.define(symbol):
            self.diagnostics.error(
                DiagnosticCode.SEM_DUPLICATE_VARIABLE,
                f"Duplicate variable declaration '{node.name}'. Variable is already declared in this scope.",
                node.location,
                hint="Choose a different variable name or use 'SET' to update an existing variable.",
            )

    def visit_SetStmt(self, node: SetStmt):
        """SET statement: updates existing variable or config setting."""
        val_type = self._infer_type(node.value)

        # Check if it's a known configuration setting
        if node.name.lower() in VALID_CONFIG_SETTINGS:
            return

        # Otherwise must be an already defined variable
        sym = self.current_scope.lookup(node.name)
        if not sym:
            self.diagnostics.error(
                DiagnosticCode.SEM_UNDEFINED_VARIABLE,
                f"Cannot SET undefined variable '{node.name}'.",
                node.location,
                hint=f"Declare '{node.name}' using 'LET {node.name} = ...;' before setting it.",
            )
        else:
            # Check type compatibility
            if sym.type != JockyType.ANY and val_type != JockyType.ANY:
                if sym.type != val_type and not (sym.type.is_numeric() and val_type.is_numeric()):
                    self.diagnostics.error(
                        DiagnosticCode.SEM_TYPE_MISMATCH,
                        f"Type mismatch: cannot assign {val_type.value} to variable '{node.name}' of type {sym.type.value}.",
                        node.location,
                        hint=f"Variable '{node.name}' is of type {sym.type.value}.",
                    )

    def visit_FilterStmt(self, node: FilterStmt):
        self.visit(node.condition)

    def visit_IfStmt(self, node: IfStmt):
        self.visit(node.condition)

        # Create block scope for body
        then_scope = Scope("if_then", parent=self.current_scope)
        self.current_scope = then_scope
        for stmt in node.body:
            self.visit(stmt)
        self.current_scope = then_scope.parent

        if node.else_body:
            else_scope = Scope("if_else", parent=self.current_scope)
            self.current_scope = else_scope
            for stmt in node.else_body:
                self.visit(stmt)
            self.current_scope = else_scope.parent

    def visit_ForEachStmt(self, node: ForEachStmt):
        if node.source not in VALID_LOOP_SOURCES:
            self.diagnostics.error(
                DiagnosticCode.SEM_UNSUPPORTED_SOURCE,
                f"Unsupported loop source '{node.source}'. Supported: {', '.join(sorted(VALID_LOOP_SOURCES))}.",
                node.location,
                hint=f"Use one of: {', '.join(sorted(VALID_LOOP_SOURCES))}.",
            )

        # Determine entity type for the loop variable
        elem_type = SOURCE_TO_ENTITY_TYPE.get(node.source, JockyType.UNKNOWN)

        # Loop body has its own scope with the loop variable defined
        loop_scope = Scope(f"foreach_{node.var_name}", parent=self.current_scope)
        loop_var_sym = Symbol(name=node.var_name, type=elem_type, location=node.location)
        loop_scope.define(loop_var_sym)

        self.current_scope = loop_scope
        for stmt in node.body:
            self.visit(stmt)
        self.current_scope = loop_scope.parent

    def visit_Condition(self, node: Condition):
        left_type = self._infer_type(node.left)
        right_type = self._infer_type(node.right)

        valid_ops = {"==", "!=", "<", "<=", ">", ">=", "CONTAINS"}
        if node.operator not in valid_ops:
            self.diagnostics.error(
                DiagnosticCode.SEM_INVALID_OPERATOR,
                f"Unsupported comparison operator '{node.operator}'.",
                node.location,
                hint=f"Use one of: {', '.join(sorted(valid_ops))}.",
            )

        # Type checking between operands
        if left_type != JockyType.UNKNOWN and right_type != JockyType.UNKNOWN:
            if node.operator == "CONTAINS":
                if left_type not in (JockyType.STRING, JockyType.COLLECTION, JockyType.ANY):
                    self.diagnostics.error(
                        DiagnosticCode.SEM_TYPE_MISMATCH,
                        f"CONTAINS operator requires a string or collection left operand, got {left_type.value}.",
                        node.location,
                    )
            elif node.operator in ("<", "<=", ">", ">="):
                # Ordered comparison requires compatible ordered types
                if not (left_type.is_numeric() and right_type.is_numeric()):
                    if not (left_type == JockyType.STRING and right_type == JockyType.STRING):
                        self.diagnostics.error(
                            DiagnosticCode.SEM_TYPE_MISMATCH,
                            f"Ordered comparison '{node.operator}' not supported between {left_type.value} and {right_type.value}.",
                            node.location,
                            hint="Ordered comparisons require numeric or string operands on both sides.",
                        )
            elif node.operator in ("==", "!="):
                # Equality comparison
                if left_type.is_numeric() and right_type.is_numeric():
                    pass  # ok, int and float
                elif left_type != right_type and left_type != JockyType.ANY and right_type != JockyType.ANY:
                    self.diagnostics.error(
                        DiagnosticCode.SEM_TYPE_MISMATCH,
                        f"Cannot compare different types: {left_type.value} {node.operator} {right_type.value}.",
                        node.location,
                        hint="Ensure both sides of comparison have compatible types.",
                    )

    def visit_BinaryExpr(self, node: BinaryExpr):
        self.visit(node.left)
        self.visit(node.right)

    def visit_UnaryExpr(self, node: UnaryExpr):
        self.visit(node.operand)

    def visit_PropertyAccess(self, node: PropertyAccess):
        self._check_property_access(node)

    def visit_Identifier(self, node: Identifier):
        self._check_identifier(node)

    def _check_property_access(self, node: PropertyAccess) -> JockyType:
        # Check if obj is a declared variable
        sym = self.current_scope.lookup(node.obj)
        if sym:
            entity_type = sym.type
            if entity_type in ENTITY_PROPERTIES:
                props = ENTITY_PROPERTIES[entity_type]
                if node.prop not in props:
                    valid_props = ", ".join(sorted(props.keys()))
                    self.diagnostics.error(
                        DiagnosticCode.SEM_INVALID_PROPERTY,
                        f"Unknown property '{node.prop}' on {entity_type.value}. Valid properties: {valid_props}.",
                        node.location,
                        hint=f"Use one of the valid properties: {valid_props}.",
                    )
                    return JockyType.UNKNOWN
                return props[node.prop]
            else:
                self.diagnostics.error(
                    DiagnosticCode.SEM_NOT_AN_OBJECT,
                    f"Variable '{node.obj}' of type {entity_type.value} does not have properties.",
                    node.location,
                )
                return JockyType.UNKNOWN

        # Check if obj refers to singular target name (e.g. process.name in SCAN PROCESSES)
        singular_map = {
            "process": JockyType.PROCESS_ENTITY,
            "network": JockyType.NETWORK_ENTITY,
            "file": JockyType.FILE_ENTITY,
            "event": JockyType.EVENTLOG_ENTITY,
            "registry": JockyType.REGISTRY_ENTITY,
            "alert": JockyType.ALERT_ENTITY,
        }
        obj_lower = node.obj.lower()
        if obj_lower in singular_map:
            entity_type = singular_map[obj_lower]
            props = ENTITY_PROPERTIES[entity_type]
            if node.prop not in props:
                valid_props = ", ".join(sorted(props.keys()))
                self.diagnostics.error(
                    DiagnosticCode.SEM_INVALID_PROPERTY,
                    f"Unknown property '{node.prop}' on {entity_type.value}. Valid properties: {valid_props}.",
                    node.location,
                    hint=f"Use one of: {valid_props}.",
                )
                return JockyType.UNKNOWN
            return props[node.prop]

        # Undefined variable/object
        self.diagnostics.error(
            DiagnosticCode.SEM_UNDEFINED_VARIABLE,
            f"Undefined object or variable '{node.obj}'.",
            node.location,
            hint=f"Declare '{node.obj}' using 'LET {node.obj} = ...;' or iterate over a collection.",
        )
        return JockyType.UNKNOWN

    def _check_identifier(self, node: Identifier) -> JockyType:
        # If we are inside SCAN <target> WHERE <cond>, unqualified identifiers
        # can refer to properties of that scan target!
        if self._current_scan_target:
            entity_type = SOURCE_TO_ENTITY_TYPE.get(self._current_scan_target)
            if entity_type and entity_type in ENTITY_PROPERTIES:
                props = ENTITY_PROPERTIES[entity_type]
                if node.name in props:
                    return props[node.name]

        # Otherwise check scope
        sym = self.current_scope.lookup(node.name)
        if sym:
            return sym.type

        # If not found, report undefined variable
        scan_hint = f" or property of {self._current_scan_target}" if self._current_scan_target else ""
        self.diagnostics.error(
            DiagnosticCode.SEM_UNDEFINED_VARIABLE,
            f"Undefined variable{scan_hint} '{node.name}'.",
            node.location,
            hint=f"Declare '{node.name}' with 'LET {node.name} = ...;' before referencing it.",
        )
        return JockyType.UNKNOWN

    def _infer_type(self, node: Any) -> JockyType:
        if node is None:
            return JockyType.UNKNOWN
        if isinstance(node, StringLiteral):
            return JockyType.STRING
        if isinstance(node, NumberLiteral):
            return JockyType.INT if isinstance(node.value, int) else JockyType.FLOAT
        if isinstance(node, BoolLiteral):
            return JockyType.BOOL
        if isinstance(node, PropertyAccess):
            return self._check_property_access(node)
        if isinstance(node, Identifier):
            return self._check_identifier(node)
        if isinstance(node, Condition):
            self.visit(node)
            return JockyType.BOOL
        if isinstance(node, BinaryExpr):
            if node.operator in ("+", "-", "*", "/"):
                left_t = self._infer_type(node.left)
                right_t = self._infer_type(node.right)
                if left_t != JockyType.UNKNOWN and right_t != JockyType.UNKNOWN:
                    if not (left_t.is_numeric() and right_t.is_numeric()):
                        self.diagnostics.error(
                            DiagnosticCode.SEM_TYPE_MISMATCH,
                            f"Arithmetic operator '{node.operator}' requires numeric operands, got {left_t.value} and {right_t.value}.",
                            node.location,
                        )
                        return JockyType.UNKNOWN
                    if left_t == JockyType.FLOAT or right_t == JockyType.FLOAT:
                        return JockyType.FLOAT
                    return JockyType.INT
            self.visit(node)
            return JockyType.BOOL
        if isinstance(node, UnaryExpr):
            self.visit(node)
            return JockyType.BOOL
        if isinstance(node, str):
            # Raw string literal
            return JockyType.STRING
        if isinstance(node, bool):
            return JockyType.BOOL
        if isinstance(node, (int, float)):
            return JockyType.INT if isinstance(node, int) else JockyType.FLOAT

        return JockyType.UNKNOWN
