"""
JOCKY DSL Parser
Parses .jky source code into an Abstract Syntax Tree (AST) using Lark.
Extracts source locations for all nodes and converts syntax errors
into structured diagnostics with line and column information.
"""
import os
import re
from typing import Any, List, Optional, Union

from lark import Lark, Transformer, v_args, Token as LarkToken
from lark.exceptions import (
    LarkError,
    UnexpectedCharacters,
    UnexpectedEOF,
    UnexpectedInput,
    UnexpectedToken,
)

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
from .diagnostics import Diagnostic, DiagnosticCode, DiagnosticSeverity, SourceLocation


class ParserError(UnexpectedInput):
    """Exception raised when parsing fails with diagnostic context."""

    def __init__(self, message: str, location: SourceLocation, code: DiagnosticCode = DiagnosticCode.SYNTAX_ERROR, hint: Optional[str] = None):
        super().__init__()
        self.message = message
        self.location = location
        self.code = code
        self.hint = hint
        self.diagnostic = Diagnostic(
            code=code,
            severity=DiagnosticSeverity.ERROR,
            message=message,
            location=location,
            hint=hint,
        )

    def __str__(self) -> str:
        return self.diagnostic.format()


@v_args(meta=True)
class JockyTransformer(Transformer):
    """Transforms Lark parse tree into JOCKY AST nodes with source locations."""

    def __init__(self, filename: Optional[str] = None):
        super().__init__()
        self.filename = filename

    def _get_loc(self, meta) -> SourceLocation:
        return SourceLocation(
            line=meta.line,
            column=meta.column,
            end_line=getattr(meta, "end_line", meta.line),
            end_column=getattr(meta, "end_column", meta.column),
            file=self.filename,
        )

    def STRING(self, token: LarkToken) -> str:
        """Strip surrounding quotes and unescape characters."""
        s = str(token)[1:-1]
        escape_map = {'\\n': '\n', '\\t': '\t', '\\r': '\r', '\\"': '"', '\\\\': '\\'}
        for esc, val in escape_map.items():
            s = s.replace(esc, val)
        return s

    def NUMBER(self, token: LarkToken) -> Union[int, float]:
        s = str(token)
        if '.' in s or 'e' in s or 'E' in s:
            return float(s)
        try:
            return int(s)
        except ValueError:
            return float(s)

    def BOOL(self, token: LarkToken) -> bool:
        return str(token).lower() == "true"

    def ID(self, token: LarkToken) -> str:
        return str(token)

    def TARGET_TYPE(self, token: LarkToken) -> str:
        return str(token)

    def SCAN_TARGET(self, token: LarkToken) -> str:
        return str(token)

    def FIND_TARGET(self, token: LarkToken) -> str:
        return str(token)

    def BUILD_TARGET(self, token: LarkToken) -> str:
        return str(token)

    def EXPORT_TARGET(self, token: LarkToken) -> str:
        return str(token)

    def SOURCE(self, token: LarkToken) -> str:
        return str(token)

    def OPERATOR(self, token: LarkToken) -> str:
        return str(token)

    def program(self, meta, children: List[Any]) -> Program:
        return Program(statements=list(children), location=self._get_loc(meta))

    def target_stmt(self, meta, children: List[Any]) -> TargetStmt:
        loc = self._get_loc(meta)
        if len(children) == 1:
            val = children[0]
            if isinstance(val, str) and val in ("SYSTEM", "ALL"):
                return TargetStmt(target_type=val, location=loc)
            else:
                return TargetStmt(target_type="REMOTE", hostname=str(val), location=loc)
        return TargetStmt(target_type=str(children[0]), location=loc)

    def scan_stmt(self, meta, children: List[Any]) -> ScanStmt:
        target = str(children[0])
        cond = children[1] if len(children) > 1 else None
        return ScanStmt(scan_target=target, condition=cond, location=self._get_loc(meta))

    def find_stmt(self, meta, children: List[Any]) -> FindStmt:
        return FindStmt(find_target=str(children[0]), location=self._get_loc(meta))

    def build_stmt(self, meta, children: List[Any]) -> BuildStmt:
        return BuildStmt(build_target=str(children[0]), location=self._get_loc(meta))

    def export_stmt(self, meta, children: List[Any]) -> ExportStmt:
        target = str(children[0])
        path = children[1] if len(children) > 1 else None
        return ExportStmt(export_target=target, path=path, location=self._get_loc(meta))

    def set_stmt(self, meta, children: List[Any]) -> SetStmt:
        return SetStmt(name=str(children[0]), value=children[1], location=self._get_loc(meta))

    def let_stmt(self, meta, children: List[Any]) -> VarAssign:
        return VarAssign(name=str(children[0]), value=children[1], location=self._get_loc(meta))

    def filter_stmt(self, meta, children: List[Any]) -> FilterStmt:
        return FilterStmt(condition=children[0], location=self._get_loc(meta))

    def block(self, meta, children: List[Any]) -> List[ASTNode]:
        return [stmt for stmt in children if isinstance(stmt, ASTNode)]

    def if_stmt(self, meta, children: List[Any]) -> IfStmt:
        cond = children[0]
        body = children[1] if len(children) > 1 and isinstance(children[1], list) else []
        else_body = children[2] if len(children) > 2 and isinstance(children[2], list) else None
        return IfStmt(condition=cond, body=body, else_body=else_body, location=self._get_loc(meta))

    def foreach_stmt(self, meta, children: List[Any]) -> ForEachStmt:
        var_name = str(children[0])
        source = str(children[1])
        body = children[2] if len(children) > 2 and isinstance(children[2], list) else []
        return ForEachStmt(var_name=var_name, source=source, body=body, location=self._get_loc(meta))

    def condition(self, meta, children: List[Any]) -> Any:
        return children[0]

    def or_condition(self, meta, children: List[Any]) -> Any:
        if len(children) == 1:
            return children[0]
        left = children[0]
        for right in children[1:]:
            left = BinaryExpr(left=left, operator="OR", right=right, location=self._get_loc(meta))
        return left

    def and_condition(self, meta, children: List[Any]) -> Any:
        if len(children) == 1:
            return children[0]
        left = children[0]
        for right in children[1:]:
            left = BinaryExpr(left=left, operator="AND", right=right, location=self._get_loc(meta))
        return left

    def not_cond(self, meta, children: List[Any]) -> UnaryExpr:
        return UnaryExpr(operator="NOT", operand=children[0], location=self._get_loc(meta))

    def comparison(self, meta, children: List[Any]) -> Any:
        loc = self._get_loc(meta)
        if len(children) == 3:
            return Condition(left=children[0], operator=str(children[1]), right=children[2], location=loc)
        return children[0]

    def ADD_OP(self, token: LarkToken) -> str:
        return str(token)

    def MUL_OP(self, token: LarkToken) -> str:
        return str(token)

    def add_expr(self, meta, children: List[Any]) -> Any:
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = str(children[i])
            right = children[i + 1]
            left = BinaryExpr(left=left, operator=op, right=right, location=self._get_loc(meta))
            i += 2
        return left

    def mul_expr(self, meta, children: List[Any]) -> Any:
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = str(children[i])
            right = children[i + 1]
            left = BinaryExpr(left=left, operator=op, right=right, location=self._get_loc(meta))
            i += 2
        return left

    def id_expr(self, meta, children: List[Any]) -> Any:
        name = str(children[0])
        if name.lower() in ("true", "false"):
            return BoolLiteral(value=(name.lower() == "true"), location=self._get_loc(meta))
        return Identifier(name=name, location=self._get_loc(meta))

    def property(self, meta, children: List[Any]) -> PropertyAccess:
        return PropertyAccess(obj=str(children[0]), prop=str(children[1]), location=self._get_loc(meta))

    def value(self, meta, children: List[Any]) -> ASTNode:
        val = children[0]
        loc = self._get_loc(meta)
        if isinstance(val, bool):
            return BoolLiteral(value=val, location=loc)
        elif isinstance(val, (int, float)):
            return NumberLiteral(value=val, location=loc)
        elif isinstance(val, str):
            return StringLiteral(value=val, location=loc)
        return val


_grammar_cache: Optional[str] = None

def get_grammar() -> str:
    global _grammar_cache
    if _grammar_cache is None:
        grammar_path = os.path.join(os.path.dirname(__file__), "grammar.lark")
        with open(grammar_path, "r", encoding="utf-8") as f:
            _grammar_cache = f.read()
    return _grammar_cache


def parse(source_code: str, filename: Optional[str] = None) -> Program:
    """
    Parse JOCKY DSL source code into an Abstract Syntax Tree.

    Args:
        source_code: The JOCKY source string.
        filename: Optional filename for diagnostic location tracking.

    Returns:
        Program AST node.

    Raises:
        ParserError: On syntax errors, with line, column, error code, and hint.
    """
    if not source_code.strip():
        return Program(statements=[], location=SourceLocation(1, 1, file=filename))

    grammar = get_grammar()
    lark_parser = Lark(grammar, parser="earley", start="program", propagate_positions=True)

    try:
        tree = lark_parser.parse(source_code)
    except UnexpectedToken as e:
        loc = SourceLocation(line=e.line, column=e.column, file=filename)
        expected = [t for t in getattr(e, "expected", []) if not t.startswith("_")]
        expected_str = ", ".join(repr(t) for t in expected[:5]) if expected else "valid token"
        
        hint = None
        code = DiagnosticCode.SYNTAX_ERROR
        msg = f"Unexpected token {repr(str(e.token))} (expected {expected_str})"
        
        if str(e.token) == "}":
            code = DiagnosticCode.SYNTAX_UNCLOSED_BLOCK
            hint = "Check for matching opening brace '{'."
        elif "SEMICOLON" in [str(x) for x in getattr(e, "expected", [])]:
            code = DiagnosticCode.SYNTAX_MISSING_SEMICOLON
            msg = f"Missing semicolon ';' after statement"
            hint = "All non-block statements in JOCKY must terminate with a semicolon ';'."

        raise ParserError(msg, loc, code=code, hint=hint) from e

    except UnexpectedCharacters as e:
        loc = SourceLocation(line=e.line, column=e.column, file=filename)
        char = source_code[e.pos_in_stream] if e.pos_in_stream < len(source_code) else "EOF"
        hint = "Check for typos or unsupported syntax."
        
        # Check if missing semicolon before next keyword
        remaining = source_code[e.pos_in_stream:]
        if any(remaining.strip().startswith(kw) for kw in ["SCAN", "TARGET", "FIND", "BUILD", "EXPORT", "SET", "LET", "IF", "FOREACH", "FILTER"]):
            code = DiagnosticCode.SYNTAX_MISSING_SEMICOLON
            msg = "Missing semicolon ';' before next statement"
            hint = "Insert ';' at the end of the preceding statement."
        else:
            code = DiagnosticCode.LEX_INVALID_CHAR
            msg = f"Unexpected character {repr(char)}"

        raise ParserError(msg, loc, code=code, hint=hint) from e

    except UnexpectedEOF as e:
        lines = source_code.splitlines()
        line = max(1, len(lines))
        column = len(lines[-1]) + 1 if lines else 1
        loc = SourceLocation(line=line, column=column, file=filename)
        expected = getattr(e, "expected", [])
        code = DiagnosticCode.SYNTAX_UNCLOSED_BLOCK if any("RBRACE" in str(x) or "}" in str(x) for x in expected) else DiagnosticCode.SYNTAX_ERROR
        hint = "Check for matching opening brace '{' or missing semicolon ';'."
        msg = "Unexpected end of input (expected closing brace or statement)"
        raise ParserError(msg, loc, code=code, hint=hint) from e

    except UnexpectedInput as e:
        line = getattr(e, "line", 1)
        column = getattr(e, "column", 1)
        if line is None or line < 1:
            line = 1
        if column is None or column < 1:
            column = 1
        loc = SourceLocation(line=line, column=column, file=filename)
        raise ParserError(f"Syntax error at {loc}", loc, code=DiagnosticCode.SYNTAX_ERROR) from e

    except LarkError as e:
        loc = SourceLocation(line=1, column=1, file=filename)
        raise ParserError(f"Parsing failed: {e}", loc, code=DiagnosticCode.SYNTAX_ERROR) from e
    except RecursionError as e:
        loc = SourceLocation(line=1, column=1, file=filename)
        raise ParserError("Maximum recursion depth exceeded (nesting is too deep)", loc, code=DiagnosticCode.SYNTAX_ERROR, hint="Reduce statement or expression nesting depth.") from e

    try:
        transformer = JockyTransformer(filename=filename)
        return transformer.transform(tree)
    except RecursionError as e:
        loc = SourceLocation(line=1, column=1, file=filename)
        raise ParserError("Maximum recursion depth exceeded (nesting is too deep)", loc, code=DiagnosticCode.SYNTAX_ERROR, hint="Reduce statement or expression nesting depth.") from e
