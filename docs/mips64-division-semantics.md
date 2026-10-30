# MIPS64 division semantics helper

`evaluate_mips64_division` evaluates classic `DIV`, `DIVU`, `DDIV`, and `DDIVU`
using caller-supplied GPR values. For defined inputs it returns the 64-bit
architectural `HI` remainder and `LO` quotient. Word forms require both input
GPRs to contain sign-extended 32-bit values and sign-extend their 32-bit
quotient and remainder results into the 64-bit HI/LO registers. `DIVU` treats
the low words as unsigned after validating that source constraint. Doubleword
forms operate on full 64-bit values. Signed division truncates toward zero,
and the remainder has the dividend's sign.

The returned outcome is `defined` for ordinary inputs. It reports
`unpredictable_word_operand` when a word-form source violates the MIPS64 word
constraint, `unpredictable_divide_by_zero` for any zero divisor, and
`unpredictable_signed_overflow` for signed minimum divided by minus one. In
these cases `HI` and `LO` are absent; the operation still reports its decoded
HI/LO destination effect through `writes_hilo`, without inventing concrete
values. Division has no arithmetic exception. The selected classic MIPS64
reference explicitly leaves divide-by-zero results unpredictable and discusses
overflow handling as a software convention; it does not specify an exact
signed-overflow HI/LO result, so the helper fails closed there as well.

`evaluate_mips64_division_instruction` maps decoded `DIV`, `DIVU`, `DDIV`, and
`DDIVU` instructions to this evaluator. It requires a MIPS64 decoded instruction
with two typed GPR reads and HI/LO writes, and rejects nonzero caller values
for a source encoded as GPR zero. The adapter does not read registers or commit
HI/LO state; values remain supplied by the caller.

The helper reads no architectural state and commits no register changes. It
does not model multiply/divide latency, interlocks, or scheduling. The
decompiler continues to render these instructions as typed HI/LO intrinsics.
The division rules follow the [MIPS64 Instruction Set Reference, Revision
2.50](https://0x04.net/~mwk/doc/mips/MD00077-2B-MIPS1664-AFP-02.50.pdf),
including the word-input constraints and unpredictable divide-by-zero result.
