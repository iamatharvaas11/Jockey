"""
Tests for the JOCKY Compiler.
Tests parsing, AST generation, semantic analysis, and LLVM IR generation.
"""
from compiler.parser import parse
from compiler.semantic_analyzer import SemanticAnalyzer
from compiler.compiler import JockyCompiler


def test_basic_parse():
    """Test basic JOCKY script parsing."""
    source = '''
    TARGET SYSTEM;
    SCAN PROCESSES;
    SCAN NETWORK;
    FIND IOC;
    BUILD TIMELINE;
    EXPORT REPORT;
    '''
    program = parse(source)
    assert program is not None
    assert len(program.statements) == 6
    print("[PASS] test_basic_parse")


def test_scan_with_condition():
    """Test SCAN with WHERE condition."""
    source = '''
    TARGET SYSTEM;
    SCAN PROCESSES WHERE name == "powershell.exe";
    '''
    program = parse(source)
    assert program is not None
    assert len(program.statements) == 2
    print("[PASS] test_scan_with_condition")


def test_set_and_let():
    """Test SET and LET statements."""
    source = '''
    TARGET SYSTEM;
    SET output_format = "JSON";
    LET threshold = 5;
    '''
    program = parse(source)
    assert program is not None
    assert len(program.statements) == 3
    print("[PASS] test_set_and_let")


def test_export_with_path():
    """Test EXPORT with TO path."""
    source = '''
    TARGET SYSTEM;
    SCAN PROCESSES;
    EXPORT REPORT TO "my_report";
    '''
    program = parse(source)
    assert program is not None
    print("[PASS] test_export_with_path")


def test_semantic_no_target():
    """Test semantic analysis catches missing TARGET."""
    source = '''
    SCAN PROCESSES;
    '''
    program = parse(source)
    analyzer = SemanticAnalyzer()
    errors, warnings = analyzer.analyze(program)
    assert len(errors) > 0 or len(warnings) > 0
    print("[PASS] test_semantic_no_target")


def test_full_compilation():
    """Test full compilation pipeline."""
    source = '''
    TARGET SYSTEM;
    SCAN PROCESSES;
    SCAN NETWORK;
    FIND IOC;
    BUILD TIMELINE;
    EXPORT REPORT;
    '''
    compiler = JockyCompiler()
    result = compiler.compile(source)
    assert result.success, f"Compilation failed: {result.errors}"
    assert result.ast is not None
    assert result.ir_code is not None
    assert "jocky_program" in result.ir_code
    print("[PASS] test_full_compilation")
    print(f"  LLVM IR generated: {len(result.ir_code)} chars")


def test_full_investigation_script():
    """Test compiling a full investigation script."""
    source = '''
    TARGET SYSTEM;

    SET output_format = "JSON";

    SCAN PROCESSES;
    SCAN FILES;
    SCAN NETWORK;
    SCAN EVENTLOGS;
    SCAN REGISTRY;

    FIND IOC;
    FIND SUSPICIOUS;
    FIND PERSISTENCE;

    BUILD TIMELINE;
    BUILD CORRELATIONS;

    EXPORT REPORT TO "investigation_report";
    '''
    compiler = JockyCompiler()
    result = compiler.compile(source)
    assert result.success, f"Compilation failed: {result.errors}"
    print("[PASS] test_full_investigation_script")


if __name__ == "__main__":
    print("=" * 50)
    print("  JOCKY Compiler Test Suite")
    print("=" * 50)
    print()

    tests = [
        test_basic_parse,
        test_scan_with_condition,
        test_set_and_let,
        test_export_with_path,
        test_semantic_no_target,
        test_full_compilation,
        test_full_investigation_script,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
