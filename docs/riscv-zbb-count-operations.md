# RISC-V Zbb count operations

The scalar decoder recognizes the Zbb count-operation encodings `clz`, `ctz`,
and `cpop` for RV32 and RV64, plus `clzw`, `ctzw`, and `cpopw` for RV64. These
are unary OP/OP-32 forms and require the encoded `rs2` field to be zero. The
decoder records the single GPR source and destination, formats the standard
mnemonics, and rejects the reserved/noncanonical nonzero-`rs2` encodings.

`evaluate_riscv_zbb_count_operation` returns the architectural destination
value for a supplied register bit pattern. Counts are bounded to the selected
XLEN; word forms count only the low 32 bits and are unavailable in RV32 mode.
The helper does not validate whether an ELF or raw-image profile advertises
Zbb, and the decompiler does not yet lower these opcodes into dedicated
expressions.
