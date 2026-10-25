# Mach-O CFI expression evaluator expansion

## Intent

Expand the existing bounded DWARF expression evaluator used by Mach-O `__eh_frame` unwind rules. Common compiler-emitted stack, arithmetic, comparison, and sized-memory operations should work for CFA and saved-register expressions without broadening the parser into a general DWARF VM.

## Existing behavior

`macho_unwind.cpp` currently evaluates literal, base-register, constant, dereference, plus/minus, and call-frame-CFA expressions. It limits each expression to 64 operations and 16 stack values; memory access is delegated to `MachOUnwindMemoryReader`. Unsupported operations fail explicitly.

## Scope

- Add bounded stack manipulation (`dup`, `drop`, `over`, `pick`, `swap`, `rot`).
- Add common scalar arithmetic, signed division, modulo, bitwise, shifts, unary sign/bitwise operations, and relational/equality comparisons. Arithmetic uses fixed 64-bit target values and wraps modulo 2^64 where DWARF defines addressing arithmetic; unrepresentable `abs`/`neg` and signed division overflow return errors. Division by zero errors; shifts outside 0..63 are malformed.
- Add `DW_OP_deref_size` for 1/2/4/8-byte reads and mask the loaded value to that width. The caller memory reader remains the sole memory access path.
- Keep existing operation/stack limits, reject malformed operands/underflow/overflow, and preserve unsupported results for every unimplemented opcode.
- Document the supported operations and that this remains an unwind-expression subset, not a general DWARF evaluator.

## Approaches

1. Copy a general DWARF expression engine. Rejected: expands dependencies and scope, and would require broad value/location/type semantics absent from this runtime API.
2. Add common scalar operations to the existing bounded evaluator. Chosen: preserves the current callback and error model, is independently reviewable, and advances real CFI expression coverage.
3. Support only `DW_OP_deref_size`. Rejected: too narrow to handle common compiler-generated arithmetic and stack expressions.

## Constraints and non-goals

No new dependencies, no parser changes, no register-location model, no branch/call/piece operations, no implicit memory reads, no tests added or run under the current repository instruction. Root owns compile-only integration. Preserve explicit failures and all current resource bounds.

## Completion evidence

Source review of stack effects, signed arithmetic boundaries, sized-reader calls, and limit enforcement; compile-only loader build by root. Documentation records remaining limits.
