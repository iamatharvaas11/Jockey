# JOCKY Intermediate Representation (IR) Specification

## 1. Overview & Architectural Role

The JOCKY Intermediate Representation (IR) is an explicit, SSA-like intermediate representation designed for authorized forensic programming tasks. It sits cleanly between the high-level JOCKY Abstract Syntax Tree (AST) and the lower-level LLVM IR code generator.

```
JOCKY Source (.jky)
       │
       ▼
     Lexer (JockyLexer)
       │
       ▼
     Parser (Lark Earley + AST Transformer)
       │
       ▼
   JOCKY AST (Program, VarAssign, IfStmt, ForEachStmt, etc.)
       │
       ▼
Semantic Analysis (Scoping, Symbol Resolution, Entity Schemas)
       │
       ▼
   JOCKY IR (ASTToIRConverter, BasicBlocks, Instructions, Validation)
       │
       ▼
    LLVM IR (LLVMCodeGenerator, Types, Allocas, Branches, String Table)
       │
       ▼
  Native / JIT (Object Emission, MCJIT Linkage to C Runtime ABI)
```

By introducing this intermediate layer, the JOCKY compiler eliminates AST-interpretation stubs, decouples forensic semantics from target-specific machine lowering, and enables validation of control-flow graphs prior to LLVM emission.

---

## 2. Type System

JOCKY IR operates on a strictly typed, machine-oriented type system:

| IR Type | Name | Bitwidth / Representation | Description |
|---|---|---|---|
| `i1` | `TYPE_I1` | 1-bit integer | Boolean truth values (`true`, `false`) |
| `i32` | `TYPE_I32` | 32-bit signed integer | Target codes, source IDs, property IDs, exit codes |
| `i64` | `TYPE_I64` | 64-bit signed integer | Standard integer variables, PIDs, byte counts, loop indices |
| `double` | `TYPE_F64` | 64-bit IEEE 754 float | Floating-point thresholds and durations |
| `ptr` | `TYPE_PTR` | Pointer (64-bit / opaque) | Pointers to stack slots, heap entities, collections |
| `ptr` | `TYPE_STR` | `i8*` pointer | Pointers to null-terminated UTF-8 strings |
| `void` | `TYPE_VOID`| 0-bit | Functions returning no value |

---

## 3. Values and Operands

IR instructions operate on the following value categories:

1. **Virtual Registers (`Register`):** Named SSA temporaries or stack slots (`%var_x_1`, `%val_y_5`, `%cmp_6`).
2. **Integer Constants (`ConstantInt`):** Typed integer literals (`i64 10`, `i32 0`).
3. **Float Constants (`ConstantFloat`):** 64-bit floating point literals (`double 3.14`).
4. **Boolean Constants (`ConstantBool`):** Boolean literals (`i1 true`, `i1 false`).
5. **Global String References (`ConstantString`):** References to interned strings in the global constant table (`@str_0`, `@str_1`).
6. **Null Constants (`ConstantNull`):** Null pointers (`ptr null`).

---

## 4. Instruction Set Architecture

Each basic block contains a sequential series of instructions, concluding with a mandatory terminator.

### 4.1 Memory Operations
* `%res = alloca <type>`: Allocates memory on the execution stack frame.
* `%res = load <type>, ptr %slot`: Loads value from memory location into a virtual register.
* `store <type> %val, ptr %slot`: Stores value into memory location.

### 4.2 Arithmetic & Logic Operations
* `%res = + <type> %left, %right`: Addition (or `fadd` for floats).
* `%res = - <type> %left, %right`: Subtraction (or `fsub` for floats).
* `%res = * <type> %left, %right`: Multiplication (or `fmul` for floats).
* `%res = / <type> %left, %right`: Division (`sdiv` for signed ints, `fdiv` for floats).
* `%res = AND i1 %left, %right`: Logical AND.
* `%res = OR i1 %left, %right`: Logical OR.
* `%res = ^ i1 %left, %right`: Logical XOR / NOT negation.

### 4.3 Comparison Operations
* `%res = cmp <op> <type> %left, %right`:
  Signed integer or floating-point comparison yielding `i1`.
  Supported operators: `==`, `!=`, `<`, `<=`, `>`, `>=`.

### 4.4 Control Flow (Terminators)
* `br label %target`: Unconditional branch to target basic block.
* `br i1 %cond, label %true_target, label %false_target`: Conditional branch.
* `ret <type> %val` / `ret void`: Terminates function execution with return value.

### 4.5 External Calls
* `call <ret_type> @func_name(<arg_types>...)`: Calls an external C runtime ABI function.

---

## 5. Control Flow & Loop Constructs

### 5.1 Conditional Branching (`IF / ELSE`)
Unlike prototype stubs that forced branches with constant values, JOCKY IR constructs a complete Control Flow Graph (CFG):

```
       [ Current Block ]
               │
               ▼ (evaluate condition)
         cbr %cond, %then, %else
               ├───┐
               │   │
        ┌──────┘   └──────┐
        ▼                 ▼
   [ if_then ]       [ if_else ]
        │                 │
        └──────┐   ┌──────┘
               ▼   ▼
          [ if_merge ]
```

### 5.2 Forensic Iteration (`FOREACH`)
`FOREACH var IN source` is compiled to an induction-variable loop over runtime collections:

```
[ entry / pre-loop ]
  %coll = call @jocky_get_collection(source_id)
  %count = call @jocky_collection_count(%coll)
  %idx = alloca i64
  store 0, %idx
  br label %loop_cond
         │
         ▼
[ loop_cond ] ◄─────────────────────────┐
  %i = load %idx                        │
  %has_more = cmp < %i, %count          │
  cbr %has_more, %loop_body, %loop_exit │
         │                              │
         ▼                              │
[ loop_body ]                           │
  %item = call @jocky_collection_get_item(%coll, %i)
  store %item, %var                     │
  ... (body statements)                 │
  br label %loop_step                   │
         │                              │
         ▼                              │
[ loop_step ] ──────────────────────────┘
  %next = %i + 1
  store %next, %idx
  br label %loop_cond
         │
         ▼ (when %has_more is false)
[ loop_exit ]
  ... (subsequent statements)
```

---

## 6. Structural Validation (`IRValidator`)

The `IRValidator` enforces compiler invariant rules prior to LLVM code generation:
1. **Terminator Guarantee:** Every basic block must end in an unconditional branch (`br`), conditional branch (`cbr`), or return (`ret`).
2. **Unreachable Code:** No instructions are permitted in a block following a terminator.
3. **CFG Integrity:** All target labels in `br` and `cbr` must resolve to existing blocks within the enclosing function.
4. **Function Completeness:** All functions must have an entry block and return type compatibility.

Violations raise `IRValidationError` with detailed diagnostic messages.

