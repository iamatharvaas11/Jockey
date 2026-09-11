"""
JOCKY Diagnostics Model
Provides structured error, warning, and informational diagnostics with
error codes, source locations, and optional hints.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List


class DiagnosticSeverity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class DiagnosticCode(str, Enum):
    # Lexer & Syntax (E1xxx)
    LEX_INVALID_CHAR = "E1001"
    LEX_UNTERMINATED_STRING = "E1002"
    SYNTAX_ERROR = "E1003"
    SYNTAX_UNEXPECTED_TOKEN = "E1004"
    SYNTAX_MISSING_SEMICOLON = "E1005"
    SYNTAX_UNCLOSED_BLOCK = "E1006"

    # Symbol & Scope (E2xxx)
    SEM_UNDEFINED_VARIABLE = "E2001"
    SEM_DUPLICATE_VARIABLE = "E2002"
    SEM_SCOPE_ERROR = "E2003"
    SEM_UNUSED_VARIABLE = "W2001"

    # Target & Environment (E3xxx)
    SEM_MISSING_TARGET = "E3001"
    SEM_INVALID_TARGET = "E3002"
    SEM_DUPLICATE_TARGET = "W3001"

    # Commands & Collectors (E4xxx)
    SEM_UNSUPPORTED_COLLECTOR = "E4001"
    SEM_UNSUPPORTED_FIND_TARGET = "E4002"
    SEM_UNSUPPORTED_BUILD_TARGET = "E4003"
    SEM_UNSUPPORTED_EXPORT_TARGET = "E4004"
    SEM_UNSUPPORTED_SOURCE = "E4005"
    SEM_INVALID_COMMAND_ARG = "E4006"

    # Type & Property (E5xxx)
    SEM_TYPE_MISMATCH = "E5001"
    SEM_INVALID_OPERATOR = "E5002"
    SEM_INVALID_PROPERTY = "E5003"
    SEM_NOT_AN_OBJECT = "E5004"


@dataclass(frozen=True)
class SourceLocation:
    """Source location in a JOCKY file (1-indexed)."""
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    file: Optional[str] = None

    def __str__(self) -> str:
        loc = f"line {self.line}, col {self.column}"
        if self.file:
            loc = f"{self.file}:{loc}"
        return loc


@dataclass
class Diagnostic:
    """A single diagnostic message (error, warning, or info)."""
    code: DiagnosticCode
    severity: DiagnosticSeverity
    message: str
    location: Optional[SourceLocation] = None
    hint: Optional[str] = None

    @property
    def is_error(self) -> bool:
        return self.severity == DiagnosticSeverity.ERROR

    @property
    def is_warning(self) -> bool:
        return self.severity == DiagnosticSeverity.WARNING

    def format(self, use_color: bool = False) -> str:
        """Format the diagnostic into a human-readable string."""
        loc_str = str(self.location) if self.location else "<unknown>"
        code_str = self.code.value if isinstance(self.code, DiagnosticCode) else str(self.code)
        sev_str = self.severity.value

        if use_color:
            color = "\033[91m" if self.is_error else ("\033[93m" if self.is_warning else "\033[94m")
            reset = "\033[0m"
            header = f"{color}[{sev_str} {code_str}]{reset}"
        else:
            header = f"[{sev_str} {code_str}]"

        result = f"{header} at {loc_str}: {self.message}"
        if self.hint:
            hint_color = "\033[96m" if use_color else ""
            reset = "\033[0m" if use_color else ""
            result += f"\n  {hint_color}Hint: {self.hint}{reset}"
        return result

    def __str__(self) -> str:
        return self.format(use_color=False)


class DiagnosticBag:
    """Collection of diagnostics with filtering and reporting utilities."""

    def __init__(self):
        self._diagnostics: List[Diagnostic] = []

    def add(self, diagnostic: Diagnostic):
        self._diagnostics.append(diagnostic)

    def error(
        self,
        code: DiagnosticCode,
        message: str,
        location: Optional[SourceLocation] = None,
        hint: Optional[str] = None,
    ):
        self.add(Diagnostic(code, DiagnosticSeverity.ERROR, message, location, hint))

    def warning(
        self,
        code: DiagnosticCode,
        message: str,
        location: Optional[SourceLocation] = None,
        hint: Optional[str] = None,
    ):
        self.add(Diagnostic(code, DiagnosticSeverity.WARNING, message, location, hint))

    def info(
        self,
        code: DiagnosticCode,
        message: str,
        location: Optional[SourceLocation] = None,
        hint: Optional[str] = None,
    ):
        self.add(Diagnostic(code, DiagnosticSeverity.INFO, message, location, hint))

    @property
    def has_errors(self) -> bool:
        return any(d.is_error for d in self._diagnostics)

    @property
    def has_warnings(self) -> bool:
        return any(d.is_warning for d in self._diagnostics)

    @property
    def errors(self) -> List[Diagnostic]:
        return [d for d in self._diagnostics if d.is_error]

    @property
    def warnings(self) -> List[Diagnostic]:
        return [d for d in self._diagnostics if d.is_warning]

    @property
    def all(self) -> List[Diagnostic]:
        return list(self._diagnostics)

    def clear(self):
        self._diagnostics.clear()

    def __len__(self) -> int:
        return len(self._diagnostics)

    def __iter__(self):
        return iter(self._diagnostics)

