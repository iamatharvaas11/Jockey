"""
JOCKY Forensic Runtime Engine
Executes JOCKY AST by dispatching commands to OS-specific forensic collectors.
"""
import platform
import time
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from compiler.ast_nodes import (
    Program, TargetStmt, ScanStmt, FindStmt, BuildStmt, ExportStmt,
    SetStmt, VarAssign, FilterStmt, IfStmt, ForEachStmt,
    Condition, StringLiteral, NumberLiteral, BoolLiteral, Identifier, PropertyAccess
)
from compiler.parser import parse as parse_source


@dataclass
class ExecutionResult:
    """Result of executing a JOCKY script."""
    success: bool = False
    collected_evidence: Dict[str, list] = field(default_factory=dict)
    correlations: Dict[str, Any] = field(default_factory=dict)
    ioc_matches: Dict[str, Any] = field(default_factory=dict)
    timeline: List[dict] = field(default_factory=list)
    report: Optional[dict] = None
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0


class JockyRuntime:
    """
    Core JOCKY forensic runtime engine.
    Walks the AST and executes forensic commands using OS-specific adapters.
    """

    def __init__(self):
        self.os_type = platform.system().lower()
        self.variables: Dict[str, Any] = {}
        self.result = ExecutionResult()
        from runtime.adapters import get_platform_adapter
        self._adapter = get_platform_adapter()

    def _init_adapter(self):
        """Adapter is initialized via get_platform_adapter()."""
        pass

    def execute_script(self, source_code: str) -> ExecutionResult:
        """Parse and execute a JOCKY script from source code."""
        self.result = ExecutionResult()
        start_time = time.time()

        try:
            ast = parse_source(source_code)
            self.execute_ast(ast)
            self.result.success = True
        except Exception as e:
            self.result.errors.append(str(e))
            self.result.success = False

        self.result.execution_time = time.time() - start_time
        return self.result

    def execute_file(self, filepath: str) -> ExecutionResult:
        """Read and execute a JOCKY script file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source_code = f.read()
            return self.execute_script(source_code)
        except FileNotFoundError:
            self.result.errors.append(f"File not found: {filepath}")
            self.result.success = False
            return self.result

    def execute_ast(self, ast_program) -> ExecutionResult:
        """Walk the AST and execute each statement."""
        if isinstance(ast_program, Program):
            for stmt in ast_program.statements:
                self._execute_statement(stmt)
        self.result.success = len(self.result.errors) == 0
        return self.result

    def _execute_statement(self, stmt):
        """Dispatch a statement to the appropriate handler."""
        handlers = {
            TargetStmt: self._handle_target,
            ScanStmt: self._handle_scan,
            FindStmt: self._handle_find,
            BuildStmt: self._handle_build,
            ExportStmt: self._handle_export,
            SetStmt: self._handle_set,
            VarAssign: self._handle_var_assign,
            FilterStmt: self._handle_filter,
            IfStmt: self._handle_if,
            ForEachStmt: self._handle_foreach,
        }

        handler = handlers.get(type(stmt))
        if handler:
            try:
                handler(stmt)
            except Exception as e:
                print(f"\033[91m[-] Error executing {type(stmt).__name__}: {e}\033[0m")
                self.result.errors.append(str(e))
        else:
            print(f"[?] Unknown statement type: {type(stmt).__name__}")

    def _handle_target(self, stmt: TargetStmt):
        """Handle TARGET statement — collect system info."""
        print(f"\033[96m[*] Setting target: {stmt.target_type}\033[0m")

        system_info = {
            'hostname': platform.node(),
            'os': platform.system(),
            'os_version': platform.version(),
            'release': platform.release(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'target_type': stmt.target_type,
        }

        if stmt.hostname:
            system_info['remote_host'] = stmt.hostname
            print(f"\033[96m  Remote target: {stmt.hostname}\033[0m")

        self.result.collected_evidence['system_info'] = [system_info]
        print(f"\033[92m[+] Target set: {system_info['os']} {system_info['release']} on {system_info['hostname']}\033[0m")

    def _handle_scan(self, stmt: ScanStmt):
        """Handle SCAN statement — collect forensic evidence."""
        target = stmt.scan_target
        print(f"\033[96m[*] Scanning {target.lower()}...\033[0m")

        try:
            if target == 'PROCESSES':
                data = self._scan_processes()
            elif target == 'FILES':
                data = self._scan_files()
            elif target == 'NETWORK':
                data = self._scan_network()
            elif target == 'EVENTLOGS':
                data = self._scan_eventlogs()
            elif target == 'REGISTRY':
                data = self._scan_registry()
            elif target == 'ALL':
                self._handle_scan(ScanStmt(scan_target='PROCESSES'))
                self._handle_scan(ScanStmt(scan_target='FILES'))
                self._handle_scan(ScanStmt(scan_target='NETWORK'))
                self._handle_scan(ScanStmt(scan_target='EVENTLOGS'))
                self._handle_scan(ScanStmt(scan_target='REGISTRY'))
                return
            else:
                print(f"\033[93m[!] Unknown scan target: {target}\033[0m")
                return

            self.result.collected_evidence[target.lower()] = data
            print(f"\033[92m[+] Found {len(data)} {target.lower()}\033[0m")

        except Exception as e:
            print(f"\033[91m[-] Error scanning {target}: {e}\033[0m")
            self.result.collected_evidence[target.lower()] = []

    def _scan_processes(self) -> list:
        """Collect running processes via platform adapter."""
        if self._adapter:
            res = self._adapter.scan_processes()
            return res.data if hasattr(res, 'data') else res
        return []

    def _scan_network(self) -> list:
        """Collect network connections via platform adapter."""
        if self._adapter:
            res = self._adapter.scan_network()
            return res.data if hasattr(res, 'data') else res
        return []

    def _scan_files(self) -> list:
        """Scan files via platform adapter."""
        if self._adapter:
            res = self._adapter.scan_files()
            return res.data if hasattr(res, 'data') else res
        return []

    def _scan_eventlogs(self) -> list:
        """Scan event logs via platform adapter."""
        if self._adapter:
            res = self._adapter.scan_eventlogs()
            return res.data if hasattr(res, 'data') else res
        return []

    def _scan_registry(self) -> list:
        """Scan registry via platform adapter."""
        if self._adapter:
            res = self._adapter.scan_registry()
            return res.data if hasattr(res, 'data') else res
    def _handle_find(self, stmt: FindStmt):
        """Handle FIND statement — run IOC/suspicion analysis."""
        target = stmt.find_target
        print(f"\033[96m[*] Finding {target.lower()}...\033[0m")

        try:
            from engine.ioc_matcher import IOCMatcher
            matcher = IOCMatcher()

            processes = self.result.collected_evidence.get('processes', [])
            connections = self.result.collected_evidence.get('network', [])

            if target in ('IOC', 'MALWARE', 'SUSPICIOUS'):
                matches = matcher.scan_all(processes, connections)
                self.result.ioc_matches = matches
                alert_count = len(matches.get('alerts', []))
                print(f"\033[92m[+] IOC scan complete: {alert_count} alerts\033[0m")

                if alert_count > 0:
                    for alert in matches.get('alerts', [])[:3]:
                        severity = alert.get('severity', 'UNKNOWN')
                        color = '\033[91m' if severity == 'CRITICAL' else '\033[93m'
                        print(f"{color}  [!] [{severity}] {alert.get('type', 'ALERT')}: {alert.get('details', '')[:80]}\033[0m")

            elif target == 'PERSISTENCE':
                registry = self.result.collected_evidence.get('registry', [])
                if registry:
                    print(f"\033[92m[+] Found {len(registry)} persistence entries\033[0m")
                else:
                    print(f"\033[93m[!] No registry data available for persistence check\033[0m")

        except ImportError as e:
            print(f"\033[93m[!] IOC engine not available: {e}\033[0m")

    def _handle_build(self, stmt: BuildStmt):
        """Handle BUILD statement — construct analysis artifacts."""
        target = stmt.build_target
        print(f"\033[96m[*] Building {target.lower()}...\033[0m")

        try:
            if target == 'TIMELINE':
                from engine.timeline_builder import TimelineBuilder
                builder = TimelineBuilder()

                processes = self.result.collected_evidence.get('processes', [])
                connections = self.result.collected_evidence.get('network', [])
                events = self.result.collected_evidence.get('eventlogs', [])

                builder.add_process_events(processes)
                builder.add_network_events(connections)
                if events:
                    builder.add_eventlog_events(events)

                # Add IOC alerts to timeline
                if self.result.ioc_matches:
                    for alert in self.result.ioc_matches.get('alerts', []):
                        builder.add_alert(alert)

                self.result.timeline = builder.build()
                print(f"\033[92m[+] Timeline built: {len(self.result.timeline)} events\033[0m")

            elif target == 'CORRELATIONS':
                from engine.correlation_engine import CorrelationEngine
                engine = CorrelationEngine(
                    processes=self.result.collected_evidence.get('processes', []),
                    connections=self.result.collected_evidence.get('network', []),
                    events=self.result.collected_evidence.get('eventlogs', []),
                    files=self.result.collected_evidence.get('files', []),
                    registry=self.result.collected_evidence.get('registry', []),
                )
                self.result.correlations = engine.correlate_all()
                net_proc = len(self.result.correlations.get('network_to_process', []))
                suspicious = len(self.result.correlations.get('suspicious_chains', []))
                print(f"\033[92m[+] Correlations: {net_proc} network-process links, {suspicious} suspicious chains\033[0m")

            elif target == 'PROCESSGRAPH':
                processes = self.result.collected_evidence.get('processes', [])
                from collectors.process_collector import ProcessCollector
                collector = ProcessCollector()
                tree = collector.build_process_tree(processes)
                self.result.collected_evidence['process_tree'] = tree
                print(f"\033[92m[+] Process graph built\033[0m")

        except ImportError as e:
            print(f"\033[93m[!] Engine not available: {e}\033[0m")

    def _handle_export(self, stmt: ExportStmt):
        """Handle EXPORT statement — generate output."""
        target = stmt.export_target
        path = stmt.path or "jocky_report"
        print(f"\033[96m[*] Exporting {target.lower()} to {path}...\033[0m")

        try:
            if target == 'REPORT':
                from engine.report_generator import ReportGenerator
                generator = ReportGenerator()
                report = generator.generate(
                    processes=self.result.collected_evidence.get('processes', []),
                    connections=self.result.collected_evidence.get('network', []),
                    events=self.result.collected_evidence.get('eventlogs', []),
                    correlations=self.result.correlations,
                    ioc_matches=self.result.ioc_matches,
                    timeline=self.result.timeline,
                    integrity_manifest=None,
                )
                self.result.report = report

                # Save JSON report
                json_path = f"{path}.json"
                generator.to_json(report, json_path)
                print(f"\033[92m[+] JSON report saved: {json_path}\033[0m")

                # Save HTML report
                html_path = f"{path}.html"
                generator.to_html(report, html_path)
                print(f"\033[92m[+] HTML report saved: {html_path}\033[0m")

            elif target in ('EVIDENCE', 'ARTIFACTS'):
                os.makedirs(path, exist_ok=True)
                for key, data in self.result.collected_evidence.items():
                    filepath = os.path.join(path, f"{key}.json")
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, default=str)
                print(f"\033[92m[+] Evidence exported to: {path}/\033[0m")

            elif target == 'TIMELINE':
                tl_path = f"{path}_timeline.json"
                with open(tl_path, 'w', encoding='utf-8') as f:
                    json.dump(self.result.timeline, f, indent=2, default=str)
                print(f"\033[92m[+] Timeline exported: {tl_path}\033[0m")

        except Exception as e:
            print(f"\033[91m[-] Export error: {e}\033[0m")

    def _handle_set(self, stmt: SetStmt):
        """Handle SET statement — store configuration variable."""
        value = self._resolve_value(stmt.value)
        self.variables[stmt.name] = value
        print(f"\033[96m[*] SET {stmt.name} = {value}\033[0m")

    def _handle_var_assign(self, stmt: VarAssign):
        """Handle LET statement — store variable."""
        value = self._resolve_value(stmt.value)
        self.variables[stmt.name] = value
        print(f"\033[96m[*] LET {stmt.name} = {value}\033[0m")

    def _handle_filter(self, stmt: FilterStmt):
        """Handle FILTER statement — filter collected evidence."""
        print(f"\033[96m[*] Applying filter...\033[0m")
        # Basic filter implementation
        cond = stmt.condition
        if isinstance(cond, Condition):
            field_name = self._resolve_value(cond.left)
            op = cond.operator
            compare_val = self._resolve_value(cond.right)
            print(f"\033[92m[+] Filter applied: {field_name} {op} {compare_val}\033[0m")

    def _handle_if(self, stmt: IfStmt):
        """Handle IF statement — conditional execution."""
        if self._evaluate_condition(stmt.condition):
            for body_stmt in stmt.body:
                self._execute_statement(body_stmt)

    def _handle_foreach(self, stmt: ForEachStmt):
        """Handle FOREACH statement — iterate over collection."""
        source = stmt.source.lower()
        items = self.result.collected_evidence.get(source, [])
        print(f"\033[96m[*] Iterating over {len(items)} {source}\033[0m")

        for item in items:
            self.variables[stmt.var_name] = item
            for body_stmt in stmt.body:
                self._execute_statement(body_stmt)

    def _evaluate_condition(self, condition: Condition) -> bool:
        """Evaluate a condition expression."""
        try:
            left = self._resolve_value(condition.left)
            right = self._resolve_value(condition.right)
            op = condition.operator

            if op == '==':
                return str(left) == str(right)
            elif op == '!=':
                return str(left) != str(right)
            elif op == '>=':
                return str(left) >= str(right)
            elif op == '<=':
                return str(left) <= str(right)
            elif op == '>':
                return str(left) > str(right)
            elif op == '<':
                return str(left) < str(right)
        except Exception:
            pass
        return True  # Default to true for demo

    def _resolve_value(self, val) -> Any:
        """Resolve an AST value node to a Python value."""
        if isinstance(val, StringLiteral):
            return val.value
        elif isinstance(val, NumberLiteral):
            return val.value
        elif isinstance(val, BoolLiteral):
            return val.value
        elif isinstance(val, PropertyAccess):
            obj = self.variables.get(val.obj, {})
            if isinstance(obj, dict):
                return obj.get(val.prop, '')
            return f"{val.obj}.{val.prop}"
        elif isinstance(val, str):
            return self.variables.get(val, val)
        return val
