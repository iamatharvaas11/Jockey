"""
JOCKY Compiler Service
Bridges the web API with the JOCKY compiler and forensic runtime engine.
"""
from typing import Dict, Any, List
import dataclasses

from compiler.compiler import JockyCompiler
from runtime.runtime_engine import JockyRuntime

def _format_value(val: Any) -> str:
    if hasattr(val, 'left') and hasattr(val, 'operator') and hasattr(val, 'right'):
        r_val = getattr(val.right, 'value', val.right)
        return f"{val.left} {val.operator} {r_val!r}"
    if hasattr(val, 'value'):
        return repr(val.value)
    if isinstance(val, str):
        return f'"{val}"'
    return str(val)

def format_ast_tree(node: Any, prefix: str = "", is_last: bool = True) -> List[str]:
    """
    Formats AST dataclass nodes into a clean ASCII hierarchy tree.
    """
    lines = []
    node_name = type(node).__name__
    
    attrs = {}
    if dataclasses.is_dataclass(node):
        for f in dataclasses.fields(node):
            if f.name not in ('statements', 'body'):
                val = getattr(node, f.name)
                if val is not None:
                    attrs[f.name] = _format_value(val)
    
    attr_str = ""
    if attrs:
        parts = [f"{k}={v}" for k, v in attrs.items() if v is not None]
        if parts:
            attr_str = " (" + ", ".join(parts) + ")"
            
    connector = "\\-- " if is_last else "+-- "
    curr_line = (prefix + connector if prefix else "") + node_name + attr_str
    lines.append(curr_line)
    
    children = []
    if hasattr(node, 'statements') and node.statements:
        children = node.statements
    elif hasattr(node, 'body') and node.body:
        children = node.body
        
    for i, child in enumerate(children):
        new_prefix = prefix + ("    " if is_last else "|   ") if prefix else "    "
        lines.extend(format_ast_tree(child, new_prefix, i == len(children) - 1))
        
    return lines

def compile_script(source: str) -> Dict[str, Any]:
    """
    Invokes the real JOCKY Compiler (Lark parser + AST + llvmlite LLVM IR generator).
    """
    compiler = JockyCompiler()
    res = compiler.compile(source)
    
    ast_repr = "[X] Parsing Failed"
    if res.ast:
        tree_lines = format_ast_tree(res.ast)
        ast_repr = "\n".join(tree_lines)

    return {
        "success": res.success,
        "ast": ast_repr,
        "llvm_ir": res.ir_code if res.success else "; Compilation errors:\n" + "\n".join(f"; {e}" for e in res.errors),
        "errors": res.errors,
        "warnings": res.warnings
    }

def execute_script(source: str) -> Dict[str, Any]:
    """
    Executes JOCKY DSL script via the real forensic runtime.
    """
    runtime = JockyRuntime()
    exec_res = runtime.execute_script(source)
    
    logs = [
        {"type": "info", "message": f"Target initialized: {runtime.os_type.upper()}"},
        {"type": "info", "message": f"Execution completed in {exec_res.execution_time:.2f}s"}
    ]
    
    total_ev = sum(len(v) for v in exec_res.collected_evidence.items() if isinstance(v, (list, dict)))
    if total_ev > 0:
        logs.append({"type": "success", "message": f"Collected forensic artifacts across {len(exec_res.collected_evidence)} categories."})
        
    for k, v in exec_res.collected_evidence.items():
        if isinstance(v, list):
            logs.append({"type": "info", "message": f"Collected {len(v)} {k} items."})
        
    alert_count = len(exec_res.ioc_matches.get('alerts', [])) if exec_res.ioc_matches else 0
    if alert_count > 0:
        logs.append({"type": "warning", "message": f"Detected {alert_count} suspicious IOC alerts!"})
    else:
        logs.append({"type": "success", "message": "Zero critical blacklisted IOC signatures detected."})

    if exec_res.timeline:
        logs.append({"type": "info", "message": f"Super-timeline constructed with {len(exec_res.timeline)} chronologically ordered events."})

    return {
        "success": exec_res.success,
        "logs": logs,
        "execution_time": exec_res.execution_time,
        "results": {
            "evidence_collected": total_ev,
            "correlations_found": len(exec_res.correlations),
            "timeline_events": len(exec_res.timeline),
            "alerts": alert_count
        }
    }
