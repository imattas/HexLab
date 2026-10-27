# Processor inventory

Run `hexlab_cli processors` to list the canonical architecture, execution mode,
and byte-order contexts accepted by the processor decoder. Each row reports
the runtime capability label and maximum instruction size from the same
`processor_capabilities` gate used by normal decoding. Add `--json` for the
versioned `hexlab.processor-inventory.v1` machine-readable representation.
The JSON includes a stable variant ID, architecture/mode labels, byte order
(`null` when inapplicable), `can_decode`, nullable instruction-size and subset
fields, and a reason for disabled variants when available.

The list includes x86 16/32/64-bit modes; A32, Thumb/Thumb-2, and A64; RV32,
RV64, and RV64C; little- and big-endian MIPS32/MIPS64 and PowerPC32/64; MOS
6502; WebAssembly 32; DEX; and JVM bytecode. WebAssembly byte order is reported
as not applicable because its operand encodings use LEB128.

The names describe enabled decoder subsets. They do not claim full ISA coverage
or imply that assembly, analysis, decompilation, or debugging supports every
instruction in a row. JSON `scope` is `decoder`; consumers should preserve the
schema version and treat other schema versions as distinct. The inventory's
canonical contexts also do not enumerate raw-image profiles such as segmented
x86 or ARM data declarations.
