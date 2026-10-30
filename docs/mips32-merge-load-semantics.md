# MIPS32 LWL/LWR merge-load semantics

`evaluate_mips32_merge_load_instruction` evaluates decoded `LWL` and `LWR` instructions from a caller-supplied aligned memory word, the prior `rt` value, and the effective address's low two bits. The aligned word is an integer decoded using the instruction's MIPS byte order. The returned result indicates whether a GPR write occurs; `rt=$zero` returns zero with the write suppressed.

The helper merges the selected memory bytes into the destination register and preserves all other bytes from the prior `rt` value. In big-endian mode, `LWL` selects address offsets `offset..3` and `LWR` selects `0..offset`. In little-endian mode, `LWL` selects `0..offset` and `LWR` selects `offset..3`. Selected bytes are placed in the register's left/high or right/low side according to the instruction and byte order.

The helper validates the decoded load form and memory operand shape but does not perform the memory access, calculate the effective address, or model exceptions and alignment policy.
