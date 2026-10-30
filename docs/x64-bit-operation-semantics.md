# x86 Bit Operation Semantics

HexLab exposes a pure value evaluator for decoded `BT`, `BTS`, `BTR`, `BTC`,
`BSF`, `BSR`, `TZCNT`, and `LZCNT` instructions in
`x64_instruction_semantics.hpp`. Callers supply the value read from the
instruction's source or bit base and, for register-index `BT`-family forms,
the index register value. Immediate bit indices come from the decoded
instruction.

The result carries the value to write, whether the destination is written and
defined, the selected bit, and per-flag definedness. BT-family operations
return the old selected bit in CF. BTS/BTR/BTC additionally set, clear, or
toggle that bit. The other modeled status flags remain undefined for this
family. BSF/BSR set ZF for a zero input and mark their destination undefined;
TZCNT/LZCNT return the operand width for zero input and expose their defined
CF/ZF behavior. Undefined flags are explicitly marked undefined instead of
being assigned invented values.

Memory bit strings return a signed byte adjustment to the original memory
operand and a normalized bit index. Register indices for memory operands are
treated as signed, including negative indices that select preceding elements;
immediate indices are treated as unsigned. Register-destination bit operations
select within the register width. The caller still performs memory access,
applies the result, and preserves undefined flags. This helper is not an
instruction executor and does not model faults, locking, or concurrent atomic
updates.

`evaluate_x86_bswap_instruction` evaluates the register result of a decoded
`BSWAP`. It accepts only the decoder's 32-bit or 64-bit GPR form; the 32-bit
result is returned zero-extended, matching x86-64 register-write behavior.
The helper does not modify flags.

The decompiler currently preserves these decoded operations as named x86
intrinsics with their architectural register outputs and memory read or
read-modify-write effects. It does not yet lower the bit selection/update or
scan result into ordinary expression-tree operations. The headless processor
test `bit_operation_semantic_tests` exercises register and immediate forms,
count/scan zero behavior, flag definedness, and negative memory-index
adjustment; decompiler tests check register BTC and memory BTS effects. Decoder
coverage remains in `tests/x86_32_decoder_tests.cpp`.
