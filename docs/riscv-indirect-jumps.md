# RISC-V indirect jump evaluation

`evaluate_riscv_jalr_instruction` evaluates decoded `JALR` and compressed
`C.JR`/`C.JALR` forms from the base GPR value. It adds the decoded signed
displacement modulo XLEN, clears target bit zero, and returns the link value
(`PC + instruction length`) when the destination is not x0. x0 sources are
treated as zero and x0 destinations suppress the link write.

The adapter validates the decoded opcode, flow, operand/access shape, GPR
effects, XLEN, and immediate form. The caller resolves the target and commits
the optional link value. Instruction-address-misalignment traps, target
execution, and control-flow state changes remain outside the helper.
