"""
Tests for JOCKY Lexer.
Verifies tokenization of keywords, identifiers, literals, operators,
comments, whitespace, source locations, and error handling for invalid characters and strings.
"""
import pytest
from compiler.lexer import JockyLexer, TokenType
from compiler.diagnostics import DiagnosticCode


class TestLexerValidTokens:
    """Tests for valid tokenization."""

    def test_keywords(self):
        source = "TARGET SYSTEM SCAN WHERE FIND BUILD EXPORT TO SET LET FILTER IF THEN ELSE FOREACH IN"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        expected_types = [
            TokenType.TARGET, TokenType.SYSTEM, TokenType.SCAN, TokenType.WHERE,
            TokenType.FIND, TokenType.BUILD, TokenType.EXPORT, TokenType.TO,
            TokenType.SET, TokenType.LET, TokenType.FILTER, TokenType.IF,
            TokenType.THEN, TokenType.ELSE, TokenType.FOREACH, TokenType.IN,
            TokenType.EOF
        ]
        actual_types = [t.type for t in tokens]
        assert actual_types == expected_types

    def test_identifiers(self):
        source = "process_name threshold count_123 alert_id"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert [t.type for t in tokens[:-1]] == [TokenType.ID, TokenType.ID, TokenType.ID, TokenType.ID]
        assert [t.value for t in tokens[:-1]] == ["process_name", "threshold", "count_123", "alert_id"]

    def test_integer_and_float_literals(self):
        source = "42 0 1048576 3.14 0.005"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.INTEGER and tokens[0].value == 42
        assert tokens[1].type == TokenType.INTEGER and tokens[1].value == 0
        assert tokens[2].type == TokenType.INTEGER and tokens[2].value == 1048576
        assert tokens[3].type == TokenType.FLOAT and tokens[3].value == 3.14
        assert tokens[4].type == TokenType.FLOAT and tokens[4].value == 0.005

    def test_string_literals_and_escapes(self):
        source = r'"hello world" "path\\to\\file" "line1\nline2" "with \"quotes\""'
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.STRING and tokens[0].value == "hello world"
        assert tokens[1].type == TokenType.STRING and tokens[1].value == "path\\to\\file"
        assert tokens[2].type == TokenType.STRING and tokens[2].value == "line1\nline2"
        assert tokens[3].type == TokenType.STRING and tokens[3].value == 'with "quotes"'

    def test_booleans(self):
        source = "true false TRUE FALSE"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        for i in range(4):
            assert tokens[i].type == TokenType.BOOL
        assert tokens[0].value is True
        assert tokens[1].value is False
        assert tokens[2].value is True
        assert tokens[3].value is False

    def test_operators(self):
        source = "== != <= >= < > = CONTAINS AND OR NOT"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        expected = [
            TokenType.EQ, TokenType.NE, TokenType.LE, TokenType.GE,
            TokenType.LT, TokenType.GT, TokenType.ASSIGN, TokenType.CONTAINS,
            TokenType.AND, TokenType.OR, TokenType.NOT, TokenType.EOF
        ]
        assert [t.type for t in tokens] == expected

    def test_punctuation(self):
        source = "; . , { } ( )"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        expected = [
            TokenType.SEMICOLON, TokenType.DOT, TokenType.COMMA,
            TokenType.LBRACE, TokenType.RBRACE, TokenType.LPAREN, TokenType.RPAREN,
            TokenType.EOF
        ]
        assert [t.type for t in tokens] == expected

    def test_comments(self):
        source = """
        // This is a comment
        TARGET SYSTEM; // Trailing comment
        // Another comment
        """
        lexer = JockyLexer(source)
        tokens = lexer.tokenize(include_comments=False)
        assert [t.type for t in tokens] == [TokenType.TARGET, TokenType.SYSTEM, TokenType.SEMICOLON, TokenType.EOF]

        lexer_with_comments = JockyLexer(source)
        all_tokens = lexer_with_comments.tokenize(include_comments=True)
        comment_tokens = [t for t in all_tokens if t.type == TokenType.COMMENT]
        assert len(comment_tokens) == 3

    def test_source_locations(self):
        source = "TARGET\n  SYSTEM;"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert tokens[0].location.line == 1
        assert tokens[0].location.column == 1
        assert tokens[1].location.line == 2
        assert tokens[1].location.column == 3
        assert tokens[2].location.line == 2
        assert tokens[2].location.column == 9


class TestLexerErrors:
    """Tests for lexer error detection and diagnostics."""

    def test_invalid_character(self):
        source = "TARGET SYSTEM; @ # $ ^"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert lexer.diagnostics.has_errors
        errors = lexer.diagnostics.errors
        assert any(e.code == DiagnosticCode.LEX_INVALID_CHAR for e in errors)
        assert any("@" in e.message for e in errors)

    def test_unterminated_string(self):
        source = 'SET x = "unclosed string without end;'
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert lexer.diagnostics.has_errors
        assert any(e.code == DiagnosticCode.LEX_UNTERMINATED_STRING for e in lexer.diagnostics.errors)
        assert lexer.diagnostics.errors[0].location.line == 1

    def test_lone_exclamation_mark(self):
        source = "SCAN PROCESSES WHERE name ! 'test';"
        lexer = JockyLexer(source)
        tokens = lexer.tokenize()
        assert lexer.diagnostics.has_errors
        assert any(e.code == DiagnosticCode.LEX_INVALID_CHAR and "!=" in (e.hint or "") for e in lexer.diagnostics.errors)

