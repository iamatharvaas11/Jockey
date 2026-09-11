"""
JOCKY IR Validator
Verifies structural consistency, basic block termination, and branching validity of an IRModule.
"""
from typing import List
from .module import IRModule, IRFunction, BasicBlock
from .instructions import BranchInstr, CondBranchInstr, ReturnInstr


class IRValidationError(Exception):
    """Raised when JOCKY IR verification fails."""
    pass


class IRValidator:
    """Validates basic blocks, control flow graphs, and typing within an IRModule."""

    @classmethod
    def validate(cls, module: IRModule) -> List[str]:
        errors: List[str] = []

        if not module.functions:
            errors.append("Module contains no functions.")

        for fname, func in module.functions.items():
            if not func.blocks:
                errors.append(f"Function @{fname} contains no basic blocks.")
                continue

            block_names = {b.name for b in func.blocks}

            for block in func.blocks:
                if not block.instructions:
                    errors.append(f"Block '{block.name}' in @{fname} is empty (missing terminator).")
                    continue

                # Check terminator
                last_instr = block.instructions[-1]
                if not last_instr.is_terminator:
                    errors.append(f"Block '{block.name}' in @{fname} does not end with a terminator instruction.")

                # Check for dead code after terminator
                for i, instr in enumerate(block.instructions[:-1]):
                    if instr.is_terminator:
                        errors.append(f"Instruction {i} in block '{block.name}' is unreachable after terminator.")

                # Check branch targets
                if isinstance(last_instr, BranchInstr):
                    if last_instr.target not in block_names:
                        errors.append(f"Branch in block '{block.name}' targets non-existent block '{last_instr.target}'.")
                elif isinstance(last_instr, CondBranchInstr):
                    if last_instr.true_target not in block_names:
                        errors.append(f"Conditional branch true-target '{last_instr.true_target}' not found in @{fname}.")
                    if last_instr.false_target not in block_names:
                        errors.append(f"Conditional branch false-target '{last_instr.false_target}' not found in @{fname}.")

        return errors

    @classmethod
    def verify(cls, module: IRModule):
        errors = cls.validate(module)
        if errors:
            raise IRValidationError("\n".join(errors))

