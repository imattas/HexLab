# RISC-V AMO.W and AMO.D semantics

`evaluate_riscv_amo_instruction` evaluates decoded word and doubleword atomic
memory operations using caller-supplied old memory bits and the `rs2` value.
It returns the old value observed by the instruction, the updated memory value,
the memory width, and whether the decoded `rd` register receives a result.
For RV64 AMO.W, `rd` receives the sign-extended old 32-bit word; AMO.D is
available only with XLEN 64.

The evaluator covers `amoswap`, `amoadd`, `amoxor`, `amoand`, `amoor`,
`amomin`, `amomax`, `amominu`, and `amomaxu`. Additions wrap to the memory
width. Signed min/max compare two's-complement values at that width; unsigned
min/max compare their raw bits. Word operations mask the supplied memory and
source values to 32 bits before computing the replacement.

Decoded `aq` and `rl` flags remain part of the instruction metadata but do not
change this single-operation value calculation. The caller supplies the
observed memory value and is responsible for atomic execution, memory ordering,
address faults, and concurrency. LR/SC reservation state and AMO access
exceptions are not evaluated here.
