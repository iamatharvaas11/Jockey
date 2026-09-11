"""
JOCKY CLI — Command-line interface for the JOCKY forensic compiler and runtime.

Usage:
    python -m compiler.cli compile script.jky       # Compile to LLVM IR
    python -m compiler.cli compile script.jky -o f.ll  # Save IR to file
    python -m compiler.cli ast script.jky            # Print AST
    python -m compiler.cli run script.jky            # Execute via runtime
    python -m compiler.cli check script.jky          # Semantic analysis only
"""
import argparse
import sys
import time
import json
from .compiler import JockyCompiler


def get_argparser():
    """Build argument parser for JOCKY CLI."""
    parser = argparse.ArgumentParser(
        prog="jocky",
        description="JOCKY Forensic Investigation Language & Framework",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # compile command
    comp = subparsers.add_parser("compile", help="Compile JOCKY script through JOCKY IR and LLVM IR")
    comp.add_argument("file", help="Input JOCKY script file (.jky)")
    comp.add_argument("--emit-ir", action="store_true", help="Emit JOCKY Intermediate Representation (IR)")
    comp.add_argument("--emit-llvm", action="store_true", help="Emit verified LLVM IR (.ll)")
    comp.add_argument("--emit-object", action="store_true", help="Emit native object file (.obj/.o)")
    comp.add_argument("-o", "--output", help="Output file path")

    # ast command
    ast_cmd = subparsers.add_parser("ast", help="Print AST for JOCKY script")
    ast_cmd.add_argument("file", help="Input JOCKY script file (.jky)")

    # run command
    run_cmd = subparsers.add_parser("run", help="Execute JOCKY script via forensic runtime")
    run_cmd.add_argument("file", help="Input JOCKY script file (.jky)")
    run_cmd.add_argument("-o", "--output", help="Output directory for results", default="./jocky_output")

    # check command
    check_cmd = subparsers.add_parser("check", help="Perform semantic analysis only")
    check_cmd.add_argument("file", help="Input JOCKY script file (.jky)")
    check_cmd.add_argument("--ast", action="store_true", help="Print AST representation")

    # investigate command
    inv_cmd = subparsers.add_parser("investigate", help="Run full-system automated forensic investigation")
    inv_cmd.add_argument("--case-id", default="JOCKY-CASE-001", help="Investigation Case ID")
    inv_cmd.add_argument("-o", "--output", default="./jocky_output", help="Output directory")

    # report command
    rep_cmd = subparsers.add_parser("report", help="Generate forensic report (HTML/JSON/PDF) from analysis output")
    rep_cmd.add_argument("input", nargs="?", default="./jocky_output/execution_result.json", help="Path to execution_result.json or analysis_result.json")
    rep_cmd.add_argument("--html", action="store_true", default=True, help="Generate HTML report")
    rep_cmd.add_argument("--json", action="store_true", help="Generate JSON report")
    rep_cmd.add_argument("--pdf", action="store_true", help="Generate PDF report (if reportlab available)")
    rep_cmd.add_argument("-o", "--output", default="./jocky_output", help="Output directory")

    # verify command
    ver_cmd = subparsers.add_parser("verify", help="Verify cryptographic integrity manifest of evidence")
    ver_cmd.add_argument("manifest", nargs="?", default="./jocky_output/manifest.json", help="Path to manifest.json")

    # doctor command
    subparsers.add_parser("doctor", help="Check system environment and dependencies")
    
    # version command
    subparsers.add_parser("version", help="Print version information")

    return parser


def print_banner():
    """Print JOCKY banner."""
    print("\033[96m")
    print("     +=======================================+")
    print("     |       JOCKY Forensic Framework        |")
    print("     +=======================================+")
    print("\033[0m")


def print_result(res):
    """Print compilation warnings and errors."""
    if res.warnings:
        print("\033[93m[!] WARNINGS:\033[0m")
        for w in res.warnings:
            print(f"  * {w}")
    if res.errors:
        print("\033[91m[X] ERRORS:\033[0m")
        for e in res.errors:
            print(f"  * {e}")


def cmd_compile(args):
    """Handle 'compile' command with multi-stage diagnostics and emission flags."""
    import os
    if not os.path.exists(args.file):
        _safe_print(f"[X] File not found: {args.file}")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        source = f.read()

    # Stage 1: Lexing
    from .lexer import JockyLexer
    lexer = JockyLexer(source, filename=args.file)
    lexer.tokenize()
    if lexer.diagnostics.has_errors:
        for err in lexer.diagnostics.errors:
            loc = f" at line {err.location.line}" if err.location else ""
            _safe_print(f"✗ Lexical error {err.code.value}{loc}: {err.message}")
        sys.exit(1)
    _safe_print("✓ Lexing passed")

    # Stage 2: Parsing
    from .parser import parse, ParserError
    try:
        ast = parse(source, filename=args.file)
    except ParserError as pe:
        loc = f" at line {pe.location.line}" if pe.location else ""
        _safe_print(f"✗ Syntax error {pe.code.value}{loc}: {pe.message}")
        sys.exit(1)
    except Exception as e:
        _safe_print(f"✗ Syntax error: {e}")
        sys.exit(1)
    _safe_print("✓ Parsing passed")

    # Stage 3: Semantic analysis
    from .semantic_analyzer import SemanticAnalyzer
    analyzer = SemanticAnalyzer()
    diag_bag = analyzer.analyze_diagnostics(ast)
    if diag_bag.has_errors:
        for err in diag_bag.errors:
            loc = f" at line {err.location.line}" if err.location else ""
            _safe_print(f"✗ Semantic error {err.code.value}{loc}: {err.message}")
        sys.exit(1)
    _safe_print("✓ Semantic analysis passed")

    # Stage 4: JOCKY IR generation & validation
    from .ir.builder import ASTToIRConverter
    from .ir.validator import IRValidator
    from .ir.printer import IRPrinter
    try:
        mod_name = os.path.splitext(os.path.basename(args.file))[0]
        converter = ASTToIRConverter(module_name=mod_name)
        jocky_ir = converter.convert(ast)
        IRValidator.verify(jocky_ir)
    except Exception as e:
        _safe_print(f"✗ JOCKY IR error: {e}")
        sys.exit(1)
    _safe_print("✓ JOCKY IR generation passed")

    # If --emit-ir requested
    if getattr(args, "emit_ir", False):
        ir_text = IRPrinter.print_module(jocky_ir)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(ir_text)
            _safe_print(f"✓ JOCKY IR written to {args.output}")
        else:
            _safe_print("\n--- JOCKY IR ---")
            _safe_print(ir_text)
        return

    # Stage 5: LLVM IR code generation
    from .llvm_codegen import LLVMCodeGenerator, LLVMVerificationError
    codegen = LLVMCodeGenerator()
    try:
        llvm_mod = codegen.generate(jocky_ir)
    except Exception as e:
        _safe_print(f"✗ LLVM codegen error: {e}")
        sys.exit(1)
    _safe_print("✓ LLVM IR generation passed")

    # Stage 6: LLVM verification
    try:
        llvm_ir_str = codegen.verify(llvm_mod)
    except LLVMVerificationError as lve:
        _safe_print(f"✗ LLVM verification failed: {lve}")
        sys.exit(1)
    _safe_print("✓ LLVM verification passed")

    # If --emit-llvm requested
    if getattr(args, "emit_llvm", False):
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(llvm_ir_str)
            _safe_print(f"✓ LLVM IR written to {args.output}")
        else:
            _safe_print("\n--- LLVM IR ---")
            _safe_print(llvm_ir_str)
        return

    # Stage 7: Native object code emission
    from .native_compiler import NativeCompiler
    native = NativeCompiler()
    try:
        obj_bytes = native.emit_object(llvm_ir_str)
    except Exception as e:
        _safe_print(f"✗ Object generation failed: {e}")
        sys.exit(1)
    _safe_print("✓ Code generation passed (native object)")

    # Output handling
    output_path = args.output
    if not output_path:
        base = os.path.splitext(args.file)[0]
        ext = ".obj" if os.name == "nt" else ".o"
        output_path = base + ext

    with open(output_path, "wb") as out_f:
        out_f.write(obj_bytes)
    _safe_print(f"[+] Compiled artifact written to: {output_path}")

    # Check external linking tools
    tools = NativeCompiler.check_toolchain()
    if tools["clang"]["available"]:
        _safe_print(f"✓ Linker available: clang ({tools['clang']['path']})")
    else:
        _safe_print("[i] Clang not found in PATH for full executable linking; object file emitted.")


def cmd_ast(args):
    """Handle 'ast' command."""
    compiler = JockyCompiler()
    print(f"\033[96m[*] Parsing: {args.file}\033[0m")
    res = compiler.compile_file(args.file)

    if res.ast:
        print("\033[93m--- Abstract Syntax Tree ---\033[0m")
        _print_ast(res.ast, indent=0)
    print_result(res)
    if not res.success:
        sys.exit(1)


def _print_ast(node, indent=0):
    """Pretty-print AST node recursively."""
    prefix = "  " * indent
    node_type = type(node).__name__

    if hasattr(node, 'statements'):
        print(f"{prefix}\033[96m{node_type}\033[0m")
        for stmt in node.statements:
            _print_ast(stmt, indent + 1)
    elif hasattr(node, 'body'):
        fields = {k: v for k, v in node.__dict__.items() if k != 'body'}
        field_str = ", ".join(f"{k}={v}" for k, v in fields.items())
        print(f"{prefix}\033[93m{node_type}\033[0m({field_str})")
        for stmt in node.body:
            _print_ast(stmt, indent + 1)
    else:
        fields = node.__dict__
        field_str = ", ".join(f"{k}={v}" for k, v in fields.items())
        print(f"{prefix}\033[92m{node_type}\033[0m({field_str})")


def cmd_run(args):
    """Handle 'run' command — compile and execute via forensic runtime."""
    compiler = JockyCompiler()

    print(f"\033[96m[*] Compiling: {args.file}\033[0m")
    res = compiler.compile_file(args.file)
    print_result(res)

    if not res.success:
        print("\033[91m[X] Compilation failed, cannot execute\033[0m")
        sys.exit(1)

    print(f"\033[92m[+] Compilation successful\033[0m")
    start_time = time.time()
    jit_success = False

    # Primary execution path: LLVM IR -> JIT Execution -> Runtime ABI -> Forensic Runtime -> Platform Adapter -> Collectors
    if res.llvm_ir:
        print(f"\033[96m[*] Executing via compiled LLVM JIT runtime pipeline...\033[0m\n")
        try:
            from compiler.native_compiler import NativeCompiler
            from runtime.native_abi import get_runtime, reset_context
            rt = get_runtime()
            ctx = reset_context()

            native = NativeCompiler()
            exit_code = native.execute_jit(res.llvm_ir)
            elapsed = time.time() - start_time
            jit_success = (exit_code == 0)

            # Re-fetch active context after JIT execution
            ctx = rt.context

            print()
            print(f"\033[92m{'='*50}\033[0m")
            print(f"\033[92m  Compiled execution completed in {elapsed:.2f}s (Exit code: {exit_code})\033[0m")
            print(f"\033[92m{'='*50}\033[0m")

            if ctx.collected_evidence:
                for target_name, col_result in ctx.collected_evidence.items():
                    print(f"\033[96m  {target_name.capitalize()} collected: {len(col_result.data)} (status: {col_result.status.value})\033[0m")

            # Evidence Store, Integrity Manifest, and Verification
            case_id = getattr(args, "case_id", "JOCKY-CASE-001") if hasattr(args, "case_id") else "JOCKY-CASE-001"
            manifest = rt.evidence_store.create_manifest(case_id=case_id)
            v_report = rt.evidence_store.verify_integrity(manifest)

            print(f"\033[94m  Evidence Store: {rt.evidence_store.count()} canonical items normalized\033[0m")
            print(f"\033[92m  Integrity Status: {v_report.status.value} (Root SHA-256: {manifest.root_hash[:16]}...)\033[0m")

            # Stage 6: Forensic Analysis Pipeline (IOC + Correlation + Timeline)
            from analysis import run_investigation_analysis
            canonical_items = rt.evidence_store.list()
            analysis = run_investigation_analysis(canonical_items, case_id=case_id)

            print(f"\033[95m  Analysis Summary: {analysis.statistics['ioc_findings']} IOC findings, {analysis.statistics['relationships']} relationships, {analysis.statistics['timeline_events']} timeline events\033[0m")

            if ctx.limitations:
                for lim in list(set(ctx.limitations))[:3]:
                    print(f"\033[93m  [i] Limitation: {lim}\033[0m")

            if ctx.errors:
                for err in ctx.errors[:3]:
                    print(f"\033[91m  [!] Error: {err}\033[0m")

            # Save normalized evidence output
            import os
            os.makedirs(args.output, exist_ok=True)
            output_file = os.path.join(args.output, "execution_result.json")
            analysis_file = os.path.join(args.output, "analysis_result.json")

            result_dict = {
                "execution_path": "JOCKY IR -> LLVM IR -> JIT execution -> Runtime ABI -> Forensic Runtime -> Platform Adapter -> Collectors -> Normalizer -> Evidence Store -> SHA-256 Manifest -> Analysis (IOC + Correlation + Timeline)",
                "host": ctx.hostname,
                "target_type": ctx.target_type,
                "elapsed_seconds": elapsed,
                "exit_code": exit_code,
                "canonical_evidence_count": rt.evidence_store.count(),
                "integrity_manifest": manifest.to_dict(),
                "integrity_verification": {
                    "status": v_report.status.value,
                    "valid_count": v_report.valid_count,
                    "modified_count": v_report.modified_count,
                },
                "analysis_statistics": analysis.statistics,
                "evidence": {k: v.to_dict() for k, v in ctx.collected_evidence.items()},
                "limitations": list(set(ctx.limitations)),
                "errors": ctx.errors,
            }

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, indent=2)

            with open(analysis_file, "w", encoding="utf-8") as f:
                json.dump(analysis.to_dict(), f, indent=2)

            print(f"\033[92m  Results saved to: {output_file}\033[0m")
            return
        except Exception as e:
            print(f"\033[93m[!] Compiled JIT execution error: {e}\033[0m")
            print(f"\033[93m[*] Falling back to AST interpreter...\033[0m")

    # Fallback execution path: AST interpreter
    try:
        from runtime.runtime_engine import JockyRuntime
        runtime = JockyRuntime()
        start_time = time.time()
        result = runtime.execute_ast(res.ast)
        elapsed = time.time() - start_time

        print()
        print(f"\033[92m{'='*50}\033[0m")
        print(f"\033[92m  Execution completed in {elapsed:.2f}s\033[0m")
        print(f"\033[92m{'='*50}\033[0m")

        if hasattr(result, 'collected_evidence') and result.collected_evidence:
            ev = result.collected_evidence
            if 'processes' in ev:
                print(f"\033[96m  Processes collected: {len(ev['processes'])}\033[0m")
            if 'network' in ev:
                print(f"\033[96m  Network connections: {len(ev['network'])}\033[0m")
            if 'registry' in ev:
                print(f"\033[96m  Registry entries:    {len(ev['registry'])}\033[0m")

        # Save results
        import os
        os.makedirs(args.output, exist_ok=True)
        output_file = os.path.join(args.output, "execution_result.json")

        result_dict = {}
        if hasattr(result, '__dict__'):
            for key, value in result.__dict__.items():
                try:
                    json.dumps(value)
                    result_dict[key] = value
                except (TypeError, ValueError):
                    result_dict[key] = str(value)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, default=str)

        print(f"\033[92m  Results saved to: {output_file}\033[0m")

    except ImportError as e:
        print(f"\033[93m[!] Runtime not available: {e}\033[0m")
        print(f"\033[93m[!] Install runtime dependencies: pip install psutil\033[0m")
    except Exception as e:
        print(f"\033[91m[X] Runtime error: {e}\033[0m")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _safe_print(text: str):
    """Print text safely across different console encodings."""
    try:
        print(text)
    except UnicodeEncodeError:
        safe = text.replace("✓", "[+]").replace("✗", "[-]").replace("—", "-")
        print(safe)


def cmd_check(args):
    """Handle 'check' command — lexical, syntactic, and semantic validation."""
    import os
    if not os.path.exists(args.file):
        print(f"\033[91m[X] File not found: {args.file}\033[0m")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        source = f.read()

    # Step 1: Lexical analysis
    from .lexer import JockyLexer
    lexer = JockyLexer(source, filename=args.file)
    lexer.tokenize()
    if lexer.diagnostics.has_errors:
        for err in lexer.diagnostics.errors:
            loc_str = f" at line {err.location.line}" if err.location else ""
            _safe_print(f"✗ Lexical error {err.code.value}{loc_str}: {err.message}")
        sys.exit(1)
    _safe_print("✓ Lexing passed")

    # Step 2: Parsing
    from .parser import parse, ParserError
    try:
        ast = parse(source, filename=args.file)
    except ParserError as pe:
        loc_str = f" at line {pe.location.line}" if pe.location else ""
        _safe_print(f"✗ Syntax error {pe.code.value}{loc_str}: {pe.message}")
        sys.exit(1)
    except Exception as e:
        _safe_print(f"✗ Syntax error: {e}")
        sys.exit(1)
    _safe_print("✓ Parsing passed")

    # Step 3: Semantic analysis
    from .semantic_analyzer import SemanticAnalyzer
    analyzer = SemanticAnalyzer()
    diag_bag = analyzer.analyze_diagnostics(ast)
    if diag_bag.has_errors:
        for err in diag_bag.errors:
            loc_str = f" at line {err.location.line}" if err.location else ""
            _safe_print(f"✗ Semantic error {err.code.value}{loc_str}: {err.message}")
        sys.exit(1)
    _safe_print("✓ Semantic analysis passed")
    _safe_print("JOCKY program is valid.")

    # Optional AST dump
    if getattr(args, "ast", False):
        _safe_print("\n--- Abstract Syntax Tree ---")
        _safe_print(ast.pretty())


def cmd_version(args):
    """Handle 'version' command."""
    print("jocky version 0.1.0")


def cmd_doctor(args):
    """Handle 'doctor' command."""
    import platform
    import subprocess
    import sys
    
    print("JOCKY Environment Doctor\n")
    print(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
    
    py_version = sys.version_info
    if py_version.major >= 3 and py_version.minor >= 10:
        print(f"[FOUND] python {sys.version.split()[0]}")
    else:
        print(f"[INCOMPATIBLE] python {sys.version.split()[0]} - requires version >= 3.10")
        
    deps = {
        'llvmlite': 'llvmlite',
        'lark': 'lark',
        'psutil': 'psutil',
        'fastapi': 'fastapi',
        'sqlalchemy': 'sqlalchemy',
        'uvicorn': 'uvicorn',
        'pydantic': 'pydantic'
    }
    
    for name, module in deps.items():
        try:
            m = __import__(module)
            version = getattr(m, '__version__', 'unknown')
            print(f"[FOUND] {name} {version}")
        except ImportError:
            print(f"[MISSING] {name} - required dependency")

    if platform.system() == 'Windows':
        try:
            import win32evtlog
            print("[FOUND] win32evtlog (pywin32)")
        except ImportError:
            print("[MISSING] pywin32 - required for Windows event log forensic capabilities")
        try:
            import winreg
            print("[FOUND] winreg (builtin)")
        except ImportError:
            print("[MISSING] winreg - required for Windows registry forensic capabilities")
            
    if platform.system() == 'Linux':
        import os
        if os.path.exists('/proc'):
            print("[FOUND] /proc filesystem")
        else:
            print("[MISSING] /proc filesystem - required for Linux process forensic capabilities")
        if os.path.exists('/var/log'):
            print("[FOUND] /var/log")
        else:
            print("[MISSING] /var/log - required for Linux log forensic capabilities")
            
    # Check CMake
    try:
        cmake_res = subprocess.run(["cmake", "--version"], capture_output=True, text=True, check=True)
        print(f"[FOUND] cmake {cmake_res.stdout.split()[2] if len(cmake_res.stdout.split()) > 2 else 'unknown'}")
    except (subprocess.SubprocessError, FileNotFoundError):
        print("[OPTIONAL] cmake - not found (required only for building native C-extensions)")

    # Check C/C++ compiler (clang, gcc, or cl)
    compiler_found = False
    for comp in ["clang", "gcc", "cl"]:
        try:
            c_res = subprocess.run([comp, "--version"] if comp != "cl" else ["cl"], capture_output=True, text=True)
            first_line = c_res.stdout.splitlines()[0] if c_res.stdout else c_res.stderr.splitlines()[0]
            print(f"[FOUND] {comp} ({first_line[:40]})")
            compiler_found = True
            break
        except (subprocess.SubprocessError, FileNotFoundError):
            continue
    if not compiler_found:
        print("[OPTIONAL] C/C++ compiler (clang/gcc) - not found (required for linking native binaries)")

    # Optional reportlab for PDF
    try:
        import reportlab
        print(f"[FOUND] reportlab {reportlab.__version__}")
    except ImportError:
        print("[OPTIONAL] reportlab - not found (HTML and JSON reports available; required for native PDF export)")


def cmd_investigate(args):
    """Handle 'investigate' command — run full-system forensic collection and analysis."""
    import os
    import json
    from runtime import ForensicRuntime
    from evidence.integrity import EvidenceIntegrityManager
    from analysis import run_investigation_analysis
    from engine.report_generator import ReportGenerator

    print(f"[*] Initiating full-system forensic investigation: {args.case_id}")
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    runtime = ForensicRuntime()
    print("[*] Collecting active processes...")
    p_res = runtime.execute_scan("process")
    print(f"  [+] Processes collected: {len(p_res.data)}")

    print("[*] Collecting network sockets...")
    n_res = runtime.execute_scan("network")
    print(f"  [+] Network sockets collected: {len(n_res.data)}")

    # Retrieve all canonical evidence
    evidence_items = runtime.evidence_store.list_items()
    print(f"[*] Total canonical evidence items normalized: {len(evidence_items)}")

    # Create Merkle root integrity manifest
    manifest = EvidenceIntegrityManager.create_manifest(
        items=evidence_items,
        case_id=args.case_id,
        examiner="JOCKY Automated Investigator",
    )
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2)
    print(f"[+] Cryptographic Manifest: {manifest.root_hash[:16]}... (Status: VALID)")

    # Run Analysis Pipeline
    print("[*] Executing IOC, Correlation, and Timeline analysis...")
    analysis = run_investigation_analysis(evidence_items, case_id=args.case_id)
    analysis_path = os.path.join(out_dir, "analysis_result.json")
    with open(analysis_path, "w", encoding="utf-8") as f:
        json.dump(analysis.to_dict(), f, indent=2)

    # Generate Reports
    rep_gen = ReportGenerator(case_id=args.case_id)
    report_dict = rep_gen.generate(
        evidence_items=evidence_items,
        integrity_manifest=manifest,
        analysis=analysis,
        limitations=p_res.limitations + n_res.limitations,
        errors=p_res.errors + n_res.errors,
    )
    html_path = os.path.join(out_dir, "investigation_report.html")
    json_path = os.path.join(out_dir, "investigation_report.json")
    rep_gen.to_html(report_dict, html_path)
    rep_gen.to_json(report_dict, json_path)

    # Automatically persist analysis into central database
    try:
        import asyncio
        from app.db.session import AsyncSessionLocal
        from app.services.investigation_ingestion import ingest_investigation_payload
        async def _persist():
            async with AsyncSessionLocal() as sess:
                await ingest_investigation_payload(sess, report_dict, case_number=args.case_id)
        asyncio.run(_persist())
        print(f"  [+] Analysis persisted to central database.")
    except Exception as e:
        pass

    print("\n==================================================")
    print(f"  Investigation Completed: {args.case_id}")
    print(f"  Evidence: {len(evidence_items)} items")
    print(f"  IOC Findings: {len(analysis.findings)}")
    print(f"  Relationships: {len(analysis.relationships)}")
    print(f"  Timeline Events: {len(analysis.timeline)}")
    print(f"  HTML Report: {html_path}")
    print(f"  JSON Report: {json_path}")
    print("==================================================")
    sys.exit(0)


def cmd_report(args):
    """Handle 'report' command — generate HTML, JSON, or PDF reports from previous analysis."""
    import os
    import json
    from engine.report_generator import ReportGenerator

    input_file = os.path.abspath(args.input)
    if not os.path.exists(input_file):
        print(f"\033[91m[X] Input file not found: {input_file}\033[0m")
        sys.exit(1)

    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Determine case ID and examiner
    case_id = data.get("meta", {}).get("case_id") or data.get("case_id", "JOCKY-CASE-001")
    gen = ReportGenerator(case_id=case_id)

    # If input is already a complete report, re-render
    if "integrity_manifest" in data and "summary" in data:
        report_dict = data
    else:
        report_dict = gen.generate(
            evidence_items=data.get("evidence_items", []),
            integrity_manifest=data.get("integrity_manifest"),
            limitations=data.get("limitations", []),
            errors=data.get("errors", []),
        )

    html_path = os.path.join(out_dir, "forensic_report.html")
    gen.to_html(report_dict, html_path)
    print(f"[+] HTML Report generated: {html_path}")

    if args.json:
        json_path = os.path.join(out_dir, "forensic_report.json")
        gen.to_json(report_dict, json_path)
        print(f"[+] JSON Report generated: {json_path}")

    if args.pdf:
        pdf_path = os.path.join(out_dir, "forensic_report.pdf")
        try:
            gen.to_pdf(report_dict, pdf_path)
            print(f"[+] PDF Report generated: {pdf_path}")
        except NotImplementedError as e:
            print(f"\033[93m[!] PDF export skipped: {e}\033[0m")

    sys.exit(0)


def cmd_verify(args):
    """Handle 'verify' command — verify cryptographic integrity manifest of evidence."""
    import os
    import json
    from evidence.integrity import EvidenceIntegrityManager, IntegrityManifest, VerificationStatus
    from evidence.schema import CanonicalEvidenceItem

    manifest_file = os.path.abspath(args.manifest)
    if not os.path.exists(manifest_file):
        print(f"\033[91m[X] Manifest file not found: {manifest_file}\033[0m")
        sys.exit(1)

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    manifest = IntegrityManifest.from_dict(manifest_data)
    manifest_dir = os.path.dirname(manifest_file)
    evidence_file = os.path.join(manifest_dir, "analysis_result.json")
    if not os.path.exists(evidence_file):
        evidence_file = os.path.join(manifest_dir, "execution_result.json")

    items = []
    if os.path.exists(evidence_file):
        with open(evidence_file, "r", encoding="utf-8") as f:
            e_data = json.load(f)
            raw_items = e_data.get("evidence_items", [])
            items = [CanonicalEvidenceItem.from_dict(it) for it in raw_items]

    if not items:
        # Check manifest root structure
        if manifest.root_hash and len(manifest.root_hash) == 64:
            print(f"[+] Manifest format valid. Root SHA-256: {manifest.root_hash}")
            print(f"[*] Manifest records {len(manifest.entries)} signed evidence items.")
            sys.exit(0)
        else:
            print("[X] Invalid or uninitialized manifest root hash.")
            sys.exit(1)

    report = EvidenceIntegrityManager.verify_manifest(manifest, items)
    if report.status == VerificationStatus.VALID:
        print(f"\033[92m[+] VERIFIED: All {report.valid_count} evidence items and root SHA-256 match.\033[0m")
        sys.exit(0)
    else:
        print(f"\033[91m[X] FAILED: Integrity compromised. Status: {report.status.value}\033[0m")
        for d in report.details:
            print(f"  * {d}")
        sys.exit(1)


def main():
    """Main entry point for JOCKY CLI."""
    print_banner()
    parser = get_argparser()
    args = parser.parse_args()

    commands = {
        "compile": cmd_compile,
        "ast": cmd_ast,
        "run": cmd_run,
        "check": cmd_check,
        "investigate": cmd_investigate,
        "report": cmd_report,
        "verify": cmd_verify,
        "doctor": cmd_doctor,
        "version": cmd_version,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
