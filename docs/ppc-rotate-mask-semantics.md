# PowerPC rotate-word mask semantics

`evaluate_ppc_rotate_mask_instruction` evaluates decoded `RLWINM`, `RLWIMI`, and `RLWNM`, including their record forms. The source's low 32 bits are rotated left by the immediate shift or by `RB & 31`; the MB..ME mask follows PowerPC's MSB-numbered, wrapping bit convention. `RLWIMI` merges selected rotated bits with prior `RA`; `RLWINM` and `RLWNM` replace the destination with the masked word.

PPC64 word results from `RLWINM`/`RLWNM` are zero-extended. `RLWIMI` preserves the destination's high 32 bits in PPC64 mode while inserting into its low word. Record forms return CR0 as LT/GT/EQ for the resulting mode-width GPR plus caller-supplied XER.SO. The helper validates decoded operands and register effects but does not commit GPR or CR state. Other rotate/mask forms, including `RLD*`, remain outside this helper.
