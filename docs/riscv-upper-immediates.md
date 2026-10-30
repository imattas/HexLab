# RISC-V upper-immediate evaluation

`evaluate_riscv_upper_immediate_instruction` evaluates `LUI` and `AUIPC` for
RV32/RV64, plus decoded two-byte `C.LUI`. The decoder-provided immediate is
sign-extended and already shifted by 12. `LUI` returns that XLEN-width value;
`AUIPC` adds it to the current instruction address modulo XLEN. Writes to x0
are reported as suppressed.

The adapter validates opcode, instruction length, immediate encoding width and
alignment, operand access, and destination write effects. It returns the value
only; caller-owned state updates and later address resolution remain outside
this helper.
