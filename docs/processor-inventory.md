# Processor inventory

Run `hexlab_cli processors` to list the canonical architecture, execution mode,
and byte-order contexts accepted by the processor decoder. The text output is
unchanged. Each row reports the runtime capability label and maximum
instruction size from the same `processor_capabilities` gate used by normal
decoding. Add `--json` for the versioned
`hexlab.processor-inventory.v2` machine-readable representation. It retains
the v1 variant and capability fields and adds a `coverage` object containing
`instruction_families`, `analysis`, `decompiler`, and `debugger` arrays.

The list includes x86 16/32/64-bit modes; A32, Thumb/Thumb-2, and A64; RV32,
RV64, and RV64C; little- and big-endian MIPS32/MIPS64 and PowerPC32/64; MOS
6502; WebAssembly 32; DEX; and JVM bytecode. WebAssembly byte order is reported
as not applicable because its operand encodings use LEB128.

The `instruction_families` entries name representative implemented decoder
families; they are non-exhaustive and do not imply full ISA coverage. The other
arrays list bounded downstream features wired for that variant. Analysis
labels name function, reference, or stack-slot recovery. Decompiler labels
describe selected typed lifting and pseudocode, not complete instruction
execution. The `remote-register-context` debugger label means the remote
debugger recognizes the architecture and can expose its register context; it
does not promise mode selection, stepping correctness for every opcode, or a
local debugger backend. Empty arrays mean this inventory does not currently
claim coverage for that layer. `scope` is
`decoder-and-selected-downstream`; consumers should preserve the schema version
and treat other schema versions as distinct. The inventory's canonical
contexts do not enumerate raw-image profiles such as segmented x86 or ARM
data declarations. Metadata is a bounded snapshot and is not a substitute for
instruction-by-instruction validation.
