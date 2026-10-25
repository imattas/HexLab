# CIL instruction decoding

`decode_cil_instructions` in `hexlab/loaders/cil.hpp` decodes the IL byte span returned by `parse_cil_method_body`. Instruction offsets and branch targets are relative to the first IL byte (the method header is excluded). It decodes common arithmetic, local/argument, constant, call/token, branch, switch, and prefix instructions, including little-endian integer and floating-point operands.

For PE/CLR inputs, `inspect_managed_methods` rebuilds the `MethodDef` catalog from metadata and resolves each IL RVA to a bounded body read, returning decoded instructions alongside the method token/name and an explicit decoded/no-body/unsupported/malformed status. It is suitable for recomputation after a project is opened; it does not persist duplicate derived IL state.

Each instruction reports its opcode, mnemonic, byte size, exact encoded bytes, typed operand, and status. `decoded` means the opcode and operand encoding are represented; `unsupported` means the opcode is known and its operand is retained, while HexLab does not claim semantic support for it. `unknown` preserves the raw opcode bytes and consumes only that one- or two-byte opcode encoding. Truncated operands, malformed switch tables, branches outside the body, and branches into the middle of another instruction return an error instead of guessing an instruction boundary.

The decoder has explicit limits of 16 MiB of IL, one million instructions, and 65,536 switch cases. It is a bytecode decoder, not a verifier or interpreter: it does not validate stack types, token-table relationships, exception-region semantics, or runtime validity. Reserved or future opcode encodings remain unknown.

Validation: `tests/cil_decoder_tests.cpp` covers signed and unsigned operands, short and long branch forms, switch target bases, metadata tokens, two-byte prefixes, unknown/unsupported distinctions, and truncated, out-of-range, and mid-instruction targets.
