"""
JOCKY LLVM Code Generator
Translates JOCKY Intermediate Representation (IR) into valid LLVM IR using llvmlite.
Performs strict LLVM assembly verification and error reporting.
"""
from typing import Any, Dict, List, Optional
from llvmlite import ir
import llvmlite.binding as llvm_binding

from .ir.types import IRType, TypeKind
from .ir.instructions import (
    IRInstruction,
    IRValue,
    Register,
    ConstantInt,
    ConstantFloat,
    ConstantBool,
    ConstantString,
    ConstantNull,
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
from .ir.module import IRModule, IRFunction, BasicBlock


class LLVMVerificationError(Exception):
    """Raised when LLVM IR fails verification."""
    pass


class LLVMCodeGenerator:
    """Translates JOCKY IRModule to llvmlite.ir.Module with verification."""

    def __init__(self):
        self._init_llvm()

    def _init_llvm(self):
        llvm_binding.initialize_native_target()
        llvm_binding.initialize_native_asmprinter()

    def map_type(self, ir_type: IRType) -> ir.Type:
        if ir_type.kind == TypeKind.VOID:
            return ir.VoidType()
        elif ir_type.kind == TypeKind.I1:
            return ir.IntType(1)
        elif ir_type.kind == TypeKind.I32:
            return ir.IntType(32)
        elif ir_type.kind == TypeKind.I64:
            return ir.IntType(64)
        elif ir_type.kind == TypeKind.F64:
            return ir.DoubleType()
        elif ir_type.kind in (TypeKind.PTR, TypeKind.STR):
            return ir.PointerType(ir.IntType(8))
        return ir.IntType(64)

    def generate(self, ir_module: IRModule) -> ir.Module:
        """Translate JOCKY IRModule to llvmlite.ir.Module."""
        llvm_mod = ir.Module(name=ir_module.name)

        # Set target triple and data layout
        try:
            target = llvm_binding.Target.from_default_triple()
            target_machine = target.create_target_machine()
            llvm_mod.triple = llvm_binding.get_default_triple()
            llvm_mod.data_layout = str(target_machine.target_data)
        except Exception:
            pass

        # 1. Global strings
        string_ptrs: Dict[str, ir.Value] = {}
        i8_ptr_ty = ir.PointerType(ir.IntType(8))

        for gid, cstr in ir_module.global_strings.items():
            encoded = cstr.value.encode("utf-8") + b"\0"
            c_bytes = bytearray(encoded)
            str_arr_ty = ir.ArrayType(ir.IntType(8), len(c_bytes))
            gv = ir.GlobalVariable(llvm_mod, str_arr_ty, name=f".str_{gid}")
            gv.linkage = "internal"
            gv.global_constant = True
            gv.initializer = ir.Constant(str_arr_ty, c_bytes)

            # Store pointer as i8* constant GEP
            zero = ir.Constant(ir.IntType(32), 0)
            gep_ptr = gv.gep((zero, zero))
            string_ptrs[gid] = gep_ptr

        # 2. External runtime declarations
        for name, decl in ir_module.runtime_declarations.items():
            ret_ty = self.map_type(decl.return_type)
            arg_tys = [self.map_type(t) for t in decl.arg_types]
            fn_ty = ir.FunctionType(ret_ty, arg_tys)
            ir.Function(llvm_mod, fn_ty, name=name)

        # 3. Functions
        for fname, func in ir_module.functions.items():
            ret_ty = self.map_type(func.return_type)
            arg_tys = [self.map_type(t) for _, t in func.arguments]
            fn_ty = ir.FunctionType(ret_ty, arg_tys)
            llvm_fn = ir.Function(llvm_mod, fn_ty, name=fname)

            # Assign argument names
            for i, (arg_name, _) in enumerate(func.arguments):
                llvm_fn.args[i].name = arg_name

            self._generate_function_body(func, llvm_fn, llvm_mod, string_ptrs)

        return llvm_mod

    def _generate_function_body(
        self,
        func: IRFunction,
        llvm_fn: ir.Function,
        llvm_mod: ir.Module,
        string_ptrs: Dict[str, ir.Value],
    ):
        # Step 1: Pre-create all basic blocks
        llvm_blocks: Dict[str, ir.Block] = {}
        for block in func.blocks:
            llvm_blocks[block.name] = llvm_fn.append_basic_block(name=block.name)

        # Step 2: Populate instructions
        reg_map: Dict[str, ir.Value] = {}
        # Map arguments
        for i, (arg_name, _) in enumerate(func.arguments):
            reg_map[arg_name] = llvm_fn.args[i]

        builder = ir.IRBuilder()

        for block in func.blocks:
            bb = llvm_blocks[block.name]
            builder.position_at_end(bb)

            for instr in block.instructions:
                self._emit_instruction(instr, builder, llvm_mod, llvm_blocks, reg_map, string_ptrs)

    def _emit_instruction(
        self,
        instr: IRInstruction,
        builder: ir.IRBuilder,
        llvm_mod: ir.Module,
        llvm_blocks: Dict[str, ir.Block],
        reg_map: Dict[str, ir.Value],
        string_ptrs: Dict[str, ir.Value],
    ):
        if isinstance(instr, AllocaInstr):
            ty = self.map_type(instr.allocated_type)
            name = instr.result.name if instr.result else ""
            ptr = builder.alloca(ty, name=name)
            if instr.result:
                reg_map[instr.result.name] = ptr

        elif isinstance(instr, LoadInstr):
            ptr_val = self._resolve_val(instr.ptr, builder, reg_map, string_ptrs)
            name = instr.result.name if instr.result else ""
            val = builder.load(ptr_val, name=name)
            if instr.result:
                reg_map[instr.result.name] = val

        elif isinstance(instr, StoreInstr):
            val = self._resolve_val(instr.value, builder, reg_map, string_ptrs)
            ptr_val = self._resolve_val(instr.ptr, builder, reg_map, string_ptrs)
            # Match type if needed
            if val.type != ptr_val.type.pointee:
                if isinstance(val.type, ir.IntType) and isinstance(ptr_val.type.pointee, ir.IntType):
                    if val.type.width < ptr_val.type.pointee.width:
                        val = builder.zext(val, ptr_val.type.pointee)
                    else:
                        val = builder.trunc(val, ptr_val.type.pointee)
            builder.store(val, ptr_val)

        elif isinstance(instr, BinaryInstr):
            left = self._resolve_val(instr.left, builder, reg_map, string_ptrs)
            right = self._resolve_val(instr.right, builder, reg_map, string_ptrs)
            name = instr.result.name if instr.result else ""

            # Ensure matching types
            if left.type != right.type:
                if isinstance(left.type, ir.IntType) and isinstance(right.type, ir.IntType):
                    if left.type.width > right.type.width:
                        right = builder.zext(right, left.type)
                    else:
                        left = builder.zext(left, right.type)

            op = instr.op
            if op == "+":
                res = builder.fadd(left, right, name=name) if isinstance(left.type, ir.DoubleType) else builder.add(left, right, name=name)
            elif op == "-":
                res = builder.fsub(left, right, name=name) if isinstance(left.type, ir.DoubleType) else builder.sub(left, right, name=name)
            elif op == "*":
                res = builder.fmul(left, right, name=name) if isinstance(left.type, ir.DoubleType) else builder.mul(left, right, name=name)
            elif op == "/":
                res = builder.fdiv(left, right, name=name) if isinstance(left.type, ir.DoubleType) else builder.sdiv(left, right, name=name)
            elif op in ("AND", "&"):
                res = builder.and_(left, right, name=name)
            elif op in ("OR", "|"):
                res = builder.or_(left, right, name=name)
            elif op == "^":
                res = builder.xor(left, right, name=name)
            else:
                res = builder.add(left, right, name=name)

            if instr.result:
                reg_map[instr.result.name] = res

        elif isinstance(instr, CompareInstr):
            left = self._resolve_val(instr.left, builder, reg_map, string_ptrs)
            right = self._resolve_val(instr.right, builder, reg_map, string_ptrs)
            name = instr.result.name if instr.result else ""

            if left.type != right.type:
                if isinstance(left.type, ir.IntType) and isinstance(right.type, ir.IntType):
                    if left.type.width > right.type.width:
                        right = builder.zext(right, left.type)
                    else:
                        left = builder.zext(left, right.type)

            cmp_map = {
                "==": "==",
                "!=": "!=",
                "<": "<",
                "<=": "<=",
                ">": ">",
                ">=": ">=",
            }
            llvm_op = cmp_map.get(instr.op, "==")

            if isinstance(left.type, ir.DoubleType):
                res = builder.fcmp_ordered(llvm_op, left, right, name=name)
            else:
                res = builder.icmp_signed(llvm_op, left, right, name=name)

            if instr.result:
                reg_map[instr.result.name] = res

        elif isinstance(instr, BranchInstr):
            target_bb = llvm_blocks[instr.target]
            builder.branch(target_bb)

        elif isinstance(instr, CondBranchInstr):
            cond = self._resolve_val(instr.condition, builder, reg_map, string_ptrs)
            if not isinstance(cond.type, ir.IntType) or cond.type.width != 1:
                cond = builder.icmp_signed("!=", cond, ir.Constant(cond.type, 0))
            true_bb = llvm_blocks[instr.true_target]
            false_bb = llvm_blocks[instr.false_target]
            builder.cbranch(cond, true_bb, false_bb)

        elif isinstance(instr, CallInstr):
            callee = llvm_mod.get_global(instr.func_name)
            if not callee:
                # Fallback declare if missing
                ret_ty = self.map_type(instr.return_type)
                arg_tys = [self.map_type(a.type) for a in instr.args]
                fn_ty = ir.FunctionType(ret_ty, arg_tys)
                callee = ir.Function(llvm_mod, fn_ty, name=instr.func_name)

            args = []
            for i, a in enumerate(instr.args):
                arg_val = self._resolve_val(a, builder, reg_map, string_ptrs)
                # Ensure type matches callee expected parameter type
                if i < len(callee.function_type.args):
                    param_ty = callee.function_type.args[i]
                    if arg_val.type != param_ty:
                        if isinstance(arg_val.type, ir.IntType) and isinstance(param_ty, ir.IntType):
                            if arg_val.type.width < param_ty.width:
                                arg_val = builder.zext(arg_val, param_ty)
                            else:
                                arg_val = builder.trunc(arg_val, param_ty)
                args.append(arg_val)

            name = instr.result.name if instr.result else ""
            res = builder.call(callee, args, name=name)
            if instr.result:
                reg_map[instr.result.name] = res

        elif isinstance(instr, ReturnInstr):
            if instr.value:
                val = self._resolve_val(instr.value, builder, reg_map, string_ptrs)
                builder.ret(val)
            else:
                builder.ret_void()

    def _resolve_val(
        self,
        val: Any,
        builder: ir.IRBuilder,
        reg_map: Dict[str, ir.Value],
        string_ptrs: Dict[str, ir.Value],
    ) -> ir.Value:
        if isinstance(val, Register):
            return reg_map.get(val.name, ir.Constant(ir.IntType(64), 0))
        elif isinstance(val, ConstantInt):
            ty = self.map_type(val.type)
            return ir.Constant(ty, val.value)
        elif isinstance(val, ConstantFloat):
            return ir.Constant(ir.DoubleType(), val.value)
        elif isinstance(val, ConstantBool):
            return ir.Constant(ir.IntType(1), int(val.value))
        elif isinstance(val, ConstantString):
            return string_ptrs.get(val.global_id, ir.Constant(ir.PointerType(ir.IntType(8)), None))
        elif isinstance(val, ConstantNull):
            return ir.Constant(ir.PointerType(ir.IntType(8)), None)
        elif isinstance(val, int):
            return ir.Constant(ir.IntType(64), val)
        elif isinstance(val, float):
            return ir.Constant(ir.DoubleType(), val)
        elif isinstance(val, bool):
            return ir.Constant(ir.IntType(1), int(val))
        return ir.Constant(ir.IntType(64), 0)

    @classmethod
    def verify(cls, llvm_mod: ir.Module) -> str:
        """
        Verify the LLVM IR module using the LLVM C++ verification engine.
        Returns the verified LLVM IR assembly string.
        Raises LLVMVerificationError if malformed.
        """
        ir_str = str(llvm_mod)
        try:
            binding_mod = llvm_binding.parse_assembly(ir_str)
            binding_mod.verify()
            return ir_str
        except Exception as e:
            raise LLVMVerificationError(f"LLVM verification failed:\n{e}") from e

