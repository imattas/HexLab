# RISC-V integer branch predicates

`evaluate_riscv_branch_predicate` evaluates the six RV32/RV64 integer branch
conditions from register bit patterns: `beq`, `bne`, signed `blt`/`bge`, and
unsigned `bltu`/`bgeu`. Inputs are reduced to XLEN before comparison. Signed
ordering uses the XLEN sign bit, without converting out-of-range unsigned
values to host signed integers.

`evaluate_riscv_branch_predicate_instruction` additionally checks that a
decoded instruction has conditional-branch flow, a supported register/register
and relative-target operand shape, read access, and matching GPR read effects.
It supports both 32-bit and 16-bit decoded branch encodings; compressed
zero-comparison aliases are represented by their canonical branch opcode and
an x0 operand, which the adapter supplies as zero regardless of the caller's
value.

The helper returns no result for other opcodes, invalid XLEN values, or
malformed instruction metadata. It does not compute the branch target or
change control-flow state; the caller decides how to apply a taken predicate.
