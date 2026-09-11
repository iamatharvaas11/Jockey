"""
JOCKY AST to IR Converter
Translates a validated JOCKY AST into JOCKY Intermediate Representation (IR).
Preserves variable values, branches, and genuine loop control flow.
"""
from typing import Any, Dict, List, Optional
from ..ast_nodes import (
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
from .types import (
    IRType,
    TYPE_I1,
    TYPE_I32,
    TYPE_I64,
    TYPE_F64,
    TYPE_PTR,
    TYPE_STR,
    TYPE_VOID,
)
TYPE_BOOL = TYPE_I1
from .instructions import (
    IRInstruction,
    IRValue,
    Register,
    ConstantInt,
    ConstantFloat,
    ConstantBool,
    ConstantString,
    AllocaInstr,
    LoadInstr,
    StoreInstr,
    BinaryInstr,
    CompareInstr,
    BranchInstr,
    CondBranchInstr,
    CallInstr,
    ReturnInstr,
)
from .module import IRModule, IRFunction, BasicBlock


# Entity property ID mappings for runtime ABI
PROPERTY_IDS: Dict[str, int] = {
    # Process properties (1-99)
    "pid": 1,
    "ppid": 2,
    "name": 3,
    "exe_path": 4,
    "cmdline": 5,
    "username": 6,
    "created_time": 7,
    "status": 8,
    "threads": 9,
    "memory_bytes": 10,
    # Network properties (101-199)
    "protocol": 101,
    "local_ip": 102,
    "local_port": 103,
    "remote_ip": 104,
    "remote_port": 105,
    # File properties (201-299)
    "path": 201,
    "size": 202,
    "modified_time": 203,
    "permissions": 204,
    "md5": 205,
    "sha256": 206,
    # EventLog properties (301-399)
    "source": 301,
    "event_id": 302,
    "level": 303,
    "message": 304,
    # Registry properties (401-499)
    "key": 401,
    "value_name": 402,
    "value_data": 403,
}

INT_PROPERTIES = {
    "pid", "ppid", "threads", "memory_bytes",
    "local_port", "remote_port", "size", "event_id",
}

SOURCE_IDS: Dict[str, int] = {
    "PROCESSES": 1,
    "FILES": 2,
    "NETWORK": 3,
    "EVENTLOGS": 4,
    "REGISTRY": 5,
}


class ASTToIRConverter:
    """Translates a JOCKY Program AST into a structured IRModule."""

    def __init__(self, module_name: str = "jocky_program"):
        self.module = IRModule(name=module_name)
        self.current_function: Optional[IRFunction] = None
        self.current_block: Optional[BasicBlock] = None
        self._reg_counter = 0
        self.variables: Dict[str, Register] = {}  # var_name -> alloca Register (ptr)
        self.variable_types: Dict[str, IRType] = {}

        self._setup_runtime_declarations()

    def _setup_runtime_declarations(self):
        """Declare standard C runtime ABI functions in the module."""
        # System & Target
        self.module.declare_runtime_func("jocky_rt_init", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_set_target", TYPE_VOID, [TYPE_I32, TYPE_STR])
        self.module.declare_runtime_func("jocky_set_config", TYPE_VOID, [TYPE_STR, TYPE_STR])

        # Scans
        self.module.declare_runtime_func("jocky_scan_processes", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_scan_files", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_scan_network", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_scan_eventlogs", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_scan_registry", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_scan_all", TYPE_VOID, [])

        # Analysis & Correlation
        self.module.declare_runtime_func("jocky_find_ioc", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_find_suspicious", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_find_malware", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_find_persistence", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_build_timeline", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_build_correlations", TYPE_VOID, [])
        self.module.declare_runtime_func("jocky_build_processgraph", TYPE_VOID, [])

        # Exports
        self.module.declare_runtime_func("jocky_export_report", TYPE_VOID, [TYPE_STR])
        self.module.declare_runtime_func("jocky_export_evidence", TYPE_VOID, [TYPE_STR])
        self.module.declare_runtime_func("jocky_export_timeline", TYPE_VOID, [TYPE_STR])

        # Collection iteration ABI
        self.module.declare_runtime_func("jocky_get_collection", TYPE_PTR, [TYPE_I32])
        self.module.declare_runtime_func("jocky_collection_count", TYPE_I64, [TYPE_PTR])
        self.module.declare_runtime_func("jocky_collection_get_item", TYPE_PTR, [TYPE_PTR, TYPE_I64])

        # Property access ABI
        self.module.declare_runtime_func("jocky_entity_get_int", TYPE_I64, [TYPE_PTR, TYPE_I32])
        self.module.declare_runtime_func("jocky_entity_get_str", TYPE_STR, [TYPE_PTR, TYPE_I32])
        self.module.declare_runtime_func("jocky_str_contains", TYPE_I1, [TYPE_STR, TYPE_STR])

    def new_register(self, ir_type: IRType, prefix: str = "") -> Register:
        self._reg_counter += 1
        name = f"{prefix}_{self._reg_counter}" if prefix else str(self._reg_counter)
        return Register(type=ir_type, name=name)

    def emit(self, instr: IRInstruction):
        if self.current_block:
            self.current_block.add_instruction(instr)

    def convert(self, ast: Program) -> IRModule:
        main_func = self.module.get_or_create_function("main", return_type=TYPE_I32)
        self.current_function = main_func
        entry = main_func.create_block("entry")
        self.current_block = entry

        # Initialize runtime
        self.emit(CallInstr(None, "jocky_rt_init", []))

        # Visit all statements in program
        for stmt in ast.statements:
            self.visit(stmt)

        # Append return 0 if block not terminated
        if self.current_block and not self.current_block.has_terminator:
            self.emit(ReturnInstr(value=ConstantInt(0, TYPE_I32)))

        return self.module

    def visit(self, node: Any) -> Any:
        if node is None:
            return None
        method_name = f"visit_{node.__class__.__name__}"
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node: Any) -> Any:
        return None

    def visit_TargetStmt(self, node: TargetStmt):
        type_code = 0  # SYSTEM
        if node.target_type == "ALL":
            type_code = 1
        elif node.target_type == "REMOTE":
            type_code = 2

        host_str = self.module.add_string(node.hostname or "")
        self.emit(CallInstr(None, "jocky_set_target", [ConstantInt(type_code, TYPE_I32), host_str]))

    def visit_ScanStmt(self, node: ScanStmt):
        func_name = f"jocky_scan_{node.scan_target.lower()}"
        self.emit(CallInstr(None, func_name, []))

    def visit_FindStmt(self, node: FindStmt):
        func_name = f"jocky_find_{node.find_target.lower()}"
        self.emit(CallInstr(None, func_name, []))

    def visit_BuildStmt(self, node: BuildStmt):
        func_name = f"jocky_build_{node.build_target.lower()}"
        self.emit(CallInstr(None, func_name, []))

    def visit_ExportStmt(self, node: ExportStmt):
        func_name = f"jocky_export_{node.export_target.lower()}"
        path_str = self.module.add_string(node.path or "")
        self.emit(CallInstr(None, func_name, [path_str]))

    def visit_VarAssign(self, node: VarAssign):
        """LET statement: allocate stack slot and store initial value."""
        val = self.visit_expr(node.value)
        val_type = val.type

        ptr = self.new_register(TYPE_PTR, f"var_{node.name}")
        self.emit(AllocaInstr(result=ptr, allocated_type=val_type))
        self.emit(StoreInstr(value=val, ptr=ptr))

        self.variables[node.name] = ptr
        self.variable_types[node.name] = val_type

    def visit_SetStmt(self, node: SetStmt):
        """SET statement: update variable or configuration parameter."""
        config_names = {"output_format", "severity_threshold", "timeout", "hash_algorithm", "case_id"}
        if node.name.lower() in config_names:
            key_str = self.module.add_string(node.name)
            val_str = self.module.add_string(str(getattr(node.value, "value", node.value)))
            self.emit(CallInstr(None, "jocky_set_config", [key_str, val_str]))
            return

        if node.name in self.variables:
            ptr = self.variables[node.name]
            val = self.visit_expr(node.value)
            self.emit(StoreInstr(value=val, ptr=ptr))

    def visit_FilterStmt(self, node: FilterStmt):
        # Filtering evaluates the condition
        self.visit_expr(node.condition)

    def visit_IfStmt(self, node: IfStmt):
        """
        IF condition THEN { ... } [ ELSE { ... } ]
        Generates:
        cond_val
        cbr cond_val, %then, %else_or_merge
        %then:
          ...
          br %merge
        %else: (optional)
          ...
          br %merge
        %merge:
        """
        cond_val = self.visit_expr(node.condition)

        then_block = self.current_function.create_block("if_then")
        else_block = self.current_function.create_block("if_else") if node.else_body else None
        merge_block = self.current_function.create_block("if_merge")

        false_target = else_block.name if else_block else merge_block.name
        self.emit(CondBranchInstr(condition=cond_val, true_target=then_block.name, false_target=false_target))

        # Then block
        self.current_block = then_block
        for stmt in node.body:
            self.visit(stmt)
        if not self.current_block.has_terminator:
            self.emit(BranchInstr(target=merge_block.name))

        # Else block (if present)
        if else_block:
            self.current_block = else_block
            for stmt in node.else_body:
                self.visit(stmt)
            if not self.current_block.has_terminator:
                self.emit(BranchInstr(target=merge_block.name))

        # Continue at merge block
        self.current_block = merge_block

    def visit_ForEachStmt(self, node: ForEachStmt):
        """
        FOREACH var IN source { body }
        Generates real loop control flow using runtime ABI:
          %coll = call @jocky_get_collection(source_id)
          %count = call @jocky_collection_count(%coll)
          %idx = alloca i64
          store 0, %idx
          br %loop_cond
        %loop_cond:
          %i = load %idx
          %has_more = cmp < %i, %count
          cbr %has_more, %loop_body, %loop_exit
        %loop_body:
          %item = call @jocky_collection_get_item(%coll, %i)
          store %item, %var
          ...
          br %loop_step
        %loop_step:
          %i_next = %i + 1
          store %i_next, %idx
          br %loop_cond
        %loop_exit:
        """
        source_id = SOURCE_IDS.get(node.source, 0)
        coll_reg = self.new_register(TYPE_PTR, "coll")
        self.emit(CallInstr(result=coll_reg, func_name="jocky_get_collection", args=[ConstantInt(source_id, TYPE_I32)], return_type=TYPE_PTR))

        count_reg = self.new_register(TYPE_I64, "count")
        self.emit(CallInstr(result=count_reg, func_name="jocky_collection_count", args=[coll_reg], return_type=TYPE_I64))

        # Allocate loop index
        idx_ptr = self.new_register(TYPE_PTR, f"idx_{node.var_name}")
        self.emit(AllocaInstr(result=idx_ptr, allocated_type=TYPE_I64))
        self.emit(StoreInstr(value=ConstantInt(0, TYPE_I64), ptr=idx_ptr))

        # Allocate loop item variable
        item_ptr = self.new_register(TYPE_PTR, f"item_{node.var_name}")
        self.emit(AllocaInstr(result=item_ptr, allocated_type=TYPE_PTR))
        self.variables[node.var_name] = item_ptr
        self.variable_types[node.var_name] = TYPE_PTR

        # Blocks
        cond_block = self.current_function.create_block("loop_cond")
        body_block = self.current_function.create_block("loop_body")
        step_block = self.current_function.create_block("loop_step")
        exit_block = self.current_function.create_block("loop_exit")

        self.emit(BranchInstr(target=cond_block.name))

        # Loop condition
        self.current_block = cond_block
        cur_idx = self.new_register(TYPE_I64, "idx_val")
        self.emit(LoadInstr(result=cur_idx, ptr=idx_ptr))
        has_more = self.new_register(TYPE_I1, "has_more")
        self.emit(CompareInstr(result=has_more, op="<", left=cur_idx, right=count_reg))
        self.emit(CondBranchInstr(condition=has_more, true_target=body_block.name, false_target=exit_block.name))

        # Loop body
        self.current_block = body_block
        item_val = self.new_register(TYPE_PTR, "item_val")
        self.emit(CallInstr(result=item_val, func_name="jocky_collection_get_item", args=[coll_reg, cur_idx], return_type=TYPE_PTR))
        self.emit(StoreInstr(value=item_val, ptr=item_ptr))

        for stmt in node.body:
            self.visit(stmt)
        if not self.current_block.has_terminator:
            self.emit(BranchInstr(target=step_block.name))

        # Loop step
        self.current_block = step_block
        step_idx = self.new_register(TYPE_I64, "step_idx")
        self.emit(LoadInstr(result=step_idx, ptr=idx_ptr))
        next_idx = self.new_register(TYPE_I64, "next_idx")
        self.emit(BinaryInstr(result=next_idx, op="+", left=step_idx, right=ConstantInt(1, TYPE_I64)))
        self.emit(StoreInstr(value=next_idx, ptr=idx_ptr))
        self.emit(BranchInstr(target=cond_block.name))

        # Loop exit
        self.current_block = exit_block

    # ========================================================================
    # Expression Evaluation
    # ========================================================================

    def visit_expr(self, node: Any) -> IRValue:
        if isinstance(node, NumberLiteral):
            if isinstance(node.value, int):
                return ConstantInt(value=node.value, type=TYPE_I64)
            return ConstantFloat(value=float(node.value), type=TYPE_F64)

        if isinstance(node, StringLiteral):
            return self.module.add_string(node.value)

        if isinstance(node, BoolLiteral):
            return ConstantBool(value=node.value, type=TYPE_I1)

        if isinstance(node, Identifier):
            if node.name in self.variables:
                ptr = self.variables[node.name]
                val_type = self.variable_types.get(node.name, TYPE_I64)
                res = self.new_register(val_type, f"val_{node.name}")
                self.emit(LoadInstr(result=res, ptr=ptr))
                return res
            return ConstantInt(0, TYPE_I64)

        if isinstance(node, PropertyAccess):
            return self._emit_property_access(node)

        if isinstance(node, BinaryExpr):
            if node.operator in ("+", "-", "*", "/"):
                left_v = self.visit_expr(node.left)
                right_v = self.visit_expr(node.right)
                res_type = TYPE_F64 if left_v.type == TYPE_F64 or right_v.type == TYPE_F64 else TYPE_I64
                res = self.new_register(res_type, "bin")
                self.emit(BinaryInstr(result=res, op=node.operator, left=left_v, right=right_v))
                return res
            elif node.operator in ("AND", "OR"):
                left_v = self.visit_expr(node.left)
                right_v = self.visit_expr(node.right)
                res = self.new_register(TYPE_I1, "log")
                self.emit(BinaryInstr(result=res, op=node.operator, left=left_v, right=right_v))
                return res
            else:
                # Comparison
                return self._emit_comparison(node.left, node.operator, node.right)

        if isinstance(node, Condition):
            return self._emit_comparison(node.left, node.operator, node.right)

        if isinstance(node, UnaryExpr):
            operand_v = self.visit_expr(node.operand)
            res = self.new_register(TYPE_I1, "not")
            self.emit(BinaryInstr(result=res, op="^", left=operand_v, right=ConstantBool(True)))
            return res

        # Fallback for primitive literals
        if isinstance(node, int):
            return ConstantInt(node, TYPE_I64)
        if isinstance(node, float):
            return ConstantFloat(node, TYPE_F64)
        if isinstance(node, str):
            return self.module.add_string(node)
        if isinstance(node, bool):
            return ConstantBool(node, TYPE_I1)

        return ConstantInt(0, TYPE_I64)

    def _emit_property_access(self, node: PropertyAccess) -> IRValue:
        prop_name = node.prop
        prop_id = PROPERTY_IDS.get(prop_name, 0)
        is_int = prop_name in INT_PROPERTIES

        # Load entity pointer
        if node.obj in self.variables:
            entity_ptr_slot = self.variables[node.obj]
            entity_ptr = self.new_register(TYPE_PTR, f"ptr_{node.obj}")
            self.emit(LoadInstr(result=entity_ptr, ptr=entity_ptr_slot))
        else:
            entity_ptr = ConstantInt(0, TYPE_PTR)

        if is_int:
            res = self.new_register(TYPE_I64, f"prop_{prop_name}")
            self.emit(CallInstr(result=res, func_name="jocky_entity_get_int", args=[entity_ptr, ConstantInt(prop_id, TYPE_I32)], return_type=TYPE_I64))
            return res
        else:
            res = self.new_register(TYPE_STR, f"prop_{prop_name}")
            self.emit(CallInstr(result=res, func_name="jocky_entity_get_str", args=[entity_ptr, ConstantInt(prop_id, TYPE_I32)], return_type=TYPE_STR))
            return res

    def _emit_comparison(self, left_node: Any, op: str, right_node: Any) -> IRValue:
        left_v = self.visit_expr(left_node)
        right_v = self.visit_expr(right_node)

        if op == "CONTAINS":
            res = self.new_register(TYPE_I1, "contains")
            self.emit(CallInstr(result=res, func_name="jocky_str_contains", args=[left_v, right_v], return_type=TYPE_I1))
            return res

        res = self.new_register(TYPE_I1, "cmp")
        self.emit(CompareInstr(result=res, op=op, left=left_v, right=right_v))
        return res
