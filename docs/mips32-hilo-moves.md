# MIPS32 HI/LO register transfers

`evaluate_mips32_hilo_move_instruction` evaluates decoded `MFHI`, `MFLO`,
`MTHI`, and `MTLO`. MFHI/MFLO return the selected HI/LO word for the GPR
destination; writes to `$zero` are suppressed. MTHI/MTLO replace only the
selected HI/LO word and preserve the other one.

The adapter validates decoded GPR and HI/LO effects. The caller supplies the
old HI/LO state and the source GPR value for MTHI/MTLO, then commits whichever
register values the result marks as written. Multiply/divide exception and
HI/LO timing behavior are not part of these transfer operations.
