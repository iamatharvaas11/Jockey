"""
JOCKY Lexer
Tokenizes JOCKY DSL source code into a stream of tokens with exact
source location metadata (line, column) and structured diagnostic error reporting.
"""
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, List, Optional, Tuple

from .diagnostics import DiagnosticBag, DiagnosticCode, SourceLocation


class TokenType(Enum):
    # Keywords
    TARGET = "TARGET"
    SYSTEM = "SYSTEM"
    REMOTE = "REMOTE"
    ALL = "ALL"
    SCAN = "SCAN"
    WHERE = "WHERE"
    FIND = "FIND"
    BUILD = "BUILD"
    EXPORT = "EXPORT"
    TO = "TO"
    SET = "SET"
    LET = "LET"
    FILTER = "FILTER"
    IF = "IF"
    THEN = "THEN"
    ELSE = "ELSE"
    FOREACH = "FOREACH"
    IN = "IN"

    # Targets & Sources
    PROCESSES = "PROCESSES"
    FILES = "FILES"
    NETWORK = "NETWORK"
    EVENTLOGS = "EVENTLOGS"
    REGISTRY = "REGISTRY"
    IOC = "IOC"
    SUSPICIOUS = "SUSPICIOUS"
    MALWARE = "MALWARE"
    PERSISTENCE = "PERSISTENCE"
    TIMELINE = "TIMELINE"
    CORRELATIONS = "CORRELATIONS"
    PROCESSGRAPH = "PROCESSGRAPH"
    REPORT = "REPORT"
    EVIDENCE = "EVIDENCE"

    # Logical & comparison operators
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    CONTAINS = "CONTAINS"
    EQ = "=="
    NE = "!="
    LE = "<="
    GE = ">="
    LT = "<"
    GT = ">"
    ASSIGN = "="

    # Arithmetic operators
    PLUS = "+"
    MINUS = "-"
    STAR = "*"
    SLASH = "/"

    # Punctuation
    SEMICOLON = ";"
    DOT = "."
    COMMA = ","
    LBRACE = "{"
    RBRACE = "}"
    LPAREN = "("
    RPAREN = ")"

    # Literals & Identifiers
    ID = "ID"
    STRING = "STRING"
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"
    BOOL = "BOOL"

    # Trivia & Meta
    COMMENT = "COMMENT"
    EOF = "EOF"


KEYWORDS = {
    "TARGET": TokenType.TARGET,
    "SYSTEM": TokenType.SYSTEM,
    "REMOTE": TokenType.REMOTE,
    "ALL": TokenType.ALL,
    "SCAN": TokenType.SCAN,
    "WHERE": TokenType.WHERE,
    "FIND": TokenType.FIND,
    "BUILD": TokenType.BUILD,
    "EXPORT": TokenType.EXPORT,
    "TO": TokenType.TO,
    "SET": TokenType.SET,
    "LET": TokenType.LET,
    "FILTER": TokenType.FILTER,
    "IF": TokenType.IF,
    "THEN": TokenType.THEN,
    "ELSE": TokenType.ELSE,
    "FOREACH": TokenType.FOREACH,
    "IN": TokenType.IN,
    "PROCESSES": TokenType.PROCESSES,
    "FILES": TokenType.FILES,
    "NETWORK": TokenType.NETWORK,
    "EVENTLOGS": TokenType.EVENTLOGS,
    "REGISTRY": TokenType.REGISTRY,
    "IOC": TokenType.IOC,
    "SUSPICIOUS": TokenType.SUSPICIOUS,
    "MALWARE": TokenType.MALWARE,
    "PERSISTENCE": TokenType.PERSISTENCE,
    "TIMELINE": TokenType.TIMELINE,
    "CORRELATIONS": TokenType.CORRELATIONS,
    "PROCESSGRAPH": TokenType.PROCESSGRAPH,
    "REPORT": TokenType.REPORT,
    "EVIDENCE": TokenType.EVIDENCE,
    "CONTAINS": TokenType.CONTAINS,
    "AND": TokenType.AND,
    "OR": TokenType.OR,
    "NOT": TokenType.NOT,
    "TRUE": TokenType.BOOL,
    "FALSE": TokenType.BOOL,
    "true": TokenType.BOOL,
    "false": TokenType.BOOL,
}


@dataclass
class Token:
    """A lexical token with source location."""
    type: TokenType
    value: Any
    location: SourceLocation

    def __str__(self) -> str:
        return f"Token({self.type.name}, {repr(self.value)}, line={self.location.line}, col={self.location.column})"


class LexerError(Exception):
    """Raised when lexical analysis encounters a fatal error."""
    def __init__(self, message: str, location: SourceLocation, code: DiagnosticCode):
        super().__init__(message)
        self.message = message
        self.location = location
        self.code = code


class JockyLexer:
    """
    Tokenizer for JOCKY DSL source code.
    Generates typed tokens and tracks source locations.
    """

    def __init__(self, source: str, filename: Optional[str] = None):
        self.source = source
        self.filename = filename
        self.diagnostics = DiagnosticBag()
        self._pos = 0
        self._line = 1
        self._column = 1

    def tokenize(self, include_comments: bool = False) -> List[Token]:
        """Tokenize entire source and return a list of tokens ending with EOF."""
        tokens: List[Token] = []

        while not self._is_at_end():
            self._skip_whitespace()
            if self._is_at_end():
                break

            start_line = self._line
            start_col = self._column
            ch = self._peek()

            # Single-line comment: // ...
            if ch == '/' and self._peek_next() == '/':
                comment_token = self._lex_comment(start_line, start_col)
                if include_comments:
                    tokens.append(comment_token)
                continue

            if ch == '/':
                self._advance()
                loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                tokens.append(Token(TokenType.SLASH, "/", loc))
                continue

            # String literal: "..."
            if ch == '"':
                tok = self._lex_string(start_line, start_col)
                if tok:
                    tokens.append(tok)
                continue

            # Numbers: digits
            if ch.isdigit():
                tokens.append(self._lex_number(start_line, start_col))
                continue

            # Identifiers and keywords
            if ch.isalpha() or ch == '_':
                tokens.append(self._lex_identifier_or_keyword(start_line, start_col))
                continue

            # Multi-character operators
            if ch == '=':
                self._advance()
                if self._peek() == '=':
                    self._advance()
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.EQ, "==", loc))
                else:
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.ASSIGN, "=", loc))
                continue

            if ch == '!':
                self._advance()
                if self._peek() == '=':
                    self._advance()
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.NE, "!=", loc))
                else:
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    self.diagnostics.error(
                        DiagnosticCode.LEX_INVALID_CHAR,
                        "Unexpected character '!'. Did you mean '!='?",
                        loc,
                        hint="Use '!=' for inequality comparison."
                    )
                continue

            if ch == '<':
                self._advance()
                if self._peek() == '=':
                    self._advance()
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.LE, "<=", loc))
                else:
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.LT, "<", loc))
                continue

            if ch == '>':
                self._advance()
                if self._peek() == '=':
                    self._advance()
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.GE, ">=", loc))
                else:
                    loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                    tokens.append(Token(TokenType.GT, ">", loc))
                continue

            # Single-character tokens
            simple_tokens = {
                ';': TokenType.SEMICOLON,
                '.': TokenType.DOT,
                ',': TokenType.COMMA,
                '{': TokenType.LBRACE,
                '}': TokenType.RBRACE,
                '(': TokenType.LPAREN,
                ')': TokenType.RPAREN,
                '+': TokenType.PLUS,
                '-': TokenType.MINUS,
                '*': TokenType.STAR,
            }

            if ch in simple_tokens:
                self._advance()
                loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
                tokens.append(Token(simple_tokens[ch], ch, loc))
                continue

            # Unexpected character
            self._advance()
            loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
            self.diagnostics.error(
                DiagnosticCode.LEX_INVALID_CHAR,
                f"Unexpected character {repr(ch)}",
                loc,
                hint="Check for syntax or keyboard typo."
            )

        eof_loc = SourceLocation(self._line, self._column, self._line, self._column, self.filename)
        tokens.append(Token(TokenType.EOF, "", eof_loc))
        return tokens

    def _lex_comment(self, start_line: int, start_col: int) -> Token:
        self._advance()  # '/'
        self._advance()  # '/'
        comment_chars = []
        while not self._is_at_end() and self._peek() != '\n':
            comment_chars.append(self._advance())
        text = "".join(comment_chars).strip()
        loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
        return Token(TokenType.COMMENT, text, loc)

    def _lex_string(self, start_line: int, start_col: int) -> Optional[Token]:
        self._advance()  # opening quote
        chars = []
        terminated = False

        while not self._is_at_end():
            ch = self._peek()
            if ch == '\n':
                break  # Strings cannot span newlines without escape
            if ch == '"':
                self._advance()  # closing quote
                terminated = True
                break
            if ch == '\\':
                self._advance()
                if self._is_at_end():
                    break
                esc = self._advance()
                escape_map = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}
                chars.append(escape_map.get(esc, esc))
            else:
                chars.append(self._advance())

        loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
        if not terminated:
            self.diagnostics.error(
                DiagnosticCode.LEX_UNTERMINATED_STRING,
                "Unterminated string literal",
                loc,
                hint="Ensure closing quote '\"' is present on the same line."
            )
            return None

        return Token(TokenType.STRING, "".join(chars), loc)

    def _lex_number(self, start_line: int, start_col: int) -> Token:
        chars = []
        is_float = False

        while not self._is_at_end() and self._peek().isdigit():
            chars.append(self._advance())

        if self._peek() == '.' and self._peek_next().isdigit():
            is_float = True
            chars.append(self._advance())  # '.'
            while not self._is_at_end() and self._peek().isdigit():
                chars.append(self._advance())

        loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)
        num_str = "".join(chars)
        if is_float:
            return Token(TokenType.FLOAT, float(num_str), loc)
        return Token(TokenType.INTEGER, int(num_str), loc)

    def _lex_identifier_or_keyword(self, start_line: int, start_col: int) -> Token:
        chars = []
        while not self._is_at_end() and (self._peek().isalnum() or self._peek() == '_'):
            chars.append(self._advance())

        word = "".join(chars)
        loc = SourceLocation(start_line, start_col, self._line, self._column, self.filename)

        if word in KEYWORDS:
            tok_type = KEYWORDS[word]
            if tok_type == TokenType.BOOL:
                val = word.lower() == "true"
                return Token(TokenType.BOOL, val, loc)
            return Token(tok_type, word, loc)

        return Token(TokenType.ID, word, loc)

    def _skip_whitespace(self):
        while not self._is_at_end():
            ch = self._peek()
            if ch in (' ', '\t', '\r'):
                self._advance()
            elif ch == '\n':
                self._line += 1
                self._column = 1
                self._pos += 1
            else:
                break

    def _peek(self) -> str:
        if self._is_at_end():
            return '\0'
        return self.source[self._pos]

    def _peek_next(self) -> str:
        if self._pos + 1 >= len(self.source):
            return '\0'
        return self.source[self._pos + 1]

    def _advance(self) -> str:
        ch = self.source[self._pos]
        self._pos += 1
        self._column += 1
        return ch

    def _is_at_end(self) -> bool:
        return self._pos >= len(self.source)

