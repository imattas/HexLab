# A32 status-register transfers

The native A32 decoder recognizes `MRS Rd, CPSR` and `MRS Rd, SPSR`, plus `MSR CPSR_f, Rm/#imm` and `MSR SPSR_f, Rm/#imm`, under all ordinary ARM condition codes. CPSR and SPSR are distinct typed register banks; GPR and status effects are retained in the instruction record. MSR immediate operands use the architectural rotated 8-bit immediate expansion.

The supported MSR subset is deliberately limited to the `f` field (field mask `1000`). CPSR writes report an unknown full-NZCV update; SPSR is represented as a separate status bank without pretending to evaluate exception-return behavior. MSR masks selecting control, extension, or status bytes are unsupported because privilege/mode changes and the rest of CPSR/SPSR are not modeled. MRS to PC and MSR from PC are rejected as unpredictable. These instructions do not change control flow or instruction mode.
