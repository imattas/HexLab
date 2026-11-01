# Integer compressed RISC-V instructions

The integer portion of C version 2.0 is available through
`decode_riscv32c` and `decode_riscv64c`, and through generic dispatch with
`Architecture::riscv32` / `ExecutionMode::rv32c` or
`Architecture::riscv64` / `ExecutionMode::rv64c`. These modes use IALIGN=16
and accept interleaved 16-bit and 32-bit instructions. The existing `rv32`
and `rv64` modes keep IALIGN=32 and reject compressed instructions.

Little-endian ELF32 and ELF64 RISC-V images select their compressed mode
when `EF_RISCV_RVC` is set. The raw loader API and CLI accept `rv32c` and
`rv64c`; their executable entry must be aligned to two bytes. RV32 base,
entry, and mapped extent retain the 32-bit address-domain checks. The new
execution mode is appended to preserve existing recipe enum values.

| Forms | RV32C | RV64C |
| --- | --- | --- |
| C.ADDI4SPN, C.LW, C.SW | Supported | Supported |
| C.NOP, C.ADDI, C.LI, C.LUI, C.ADDI16SP | Supported | Supported |
| C.SRLI, C.SRAI, C.SLLI, C.ANDI | Supported | Supported |
| C.SUB, C.XOR, C.OR, C.AND, C.MV, C.ADD | Supported | Supported |
| C.J, C.BEQZ, C.BNEZ, C.JR, C.JALR, C.EBREAK | Supported | Supported |
| C.LWSP, C.SWSP | Supported | Supported |
| C.JAL | Supported | Encoding selects C.ADDIW |
| C.ADDIW | Encoding selects C.JAL | Supported |
| C.SUBW, C.ADDW | Reserved | Supported |
| C.LD, C.SD, C.LDSP, C.SDSP | Encoding selects unsupported compressed FP forms | Supported |

Instructions retain their original two bytes and length while exposing
canonical base opcodes and operands for formatting, analysis, and lifting.
For example, C.MV formats as `add rd, x0, rs2`, and C.JAL as `jal x1,
target`. Compact ALU source fields select x8 through x15, independently of
the operation selector bits. Source/destination access, base-register reads,
memory direction and data width, direct targets, and flow class are retained.
Writes to x0 are suppressed in register effects.

RV64 shifts accept the full six-bit amount, including 32 through 63. RV32
shifts with bit 5 set are reported as unsupported custom encodings, rather
than being executed as standard shifts. Reserved zero immediates in
C.ADDI4SPN, C.ADDI16SP and C.LUI, zero load destinations, the zero-source
C.JR encoding, and reserved word-ALU selectors are rejected. C.LUI accepts
all nonzero signed six-bit values, including -32. Standard C HINT code
points are accepted as their computational expansion; no distinct hint
opcode or microarchitectural hint behavior is modeled.

RV32 direct targets and continuation addresses wrap at XLEN. C.JAL writes
x1 and has call flow; C.JR through x1/x5 has return flow. The existing
`evaluate_riscv_jalr_instruction` adapter consumes both RV32C and RV64C
indirect-jump operands: address width follows XLEN, target bit zero is
cleared, and the returned link is PC+2 for compressed instructions.

The recovered-CFG reference propagator accepts both compressed modes and
their six-bit arithmetic/LUI, ten-bit stack arithmetic, and compressed
shift immediates. Known integer constants can therefore feed compressed
memory references and C.JR/C.JALR code references with existing producer
provenance. This includes mixed-width AUIPC/ADDI/JALR chains when their
instructions already belong to recovered blocks. Calls retain the existing
conservative register-state clearing. The separate raw-byte backward
AUIPC/JALR resolver remains restricted to fixed-width contexts because it
cannot establish a preceding instruction boundary in mixed-width code.

Compressed floating-point forms, RV128C, Zc extension instructions,
custom-extension shift behavior, and distinct named hint extensions remain
outside this integer C implementation. An unsupported compressed encoding
is not passed to the permissive Capstone fallback. Desktop raw-mode
selectors and the plugin mode catalog have not been extended with RV32C;
ELF mode selection and engine/CLI entry points provide the integration.

The initial audit found no RV32C decoder entry point, a missing XLEN
parameter in the compressed decoder, rejected RV64 right shifts 32-63,
incorrect compact ALU rs2 fields, and rejected C.LUI -32/x0 HINT forms.
Those decode gaps and compressed reference-propagation gates are addressed
here. Existing scalar floating-point and vector instruction families are
unchanged.

Validation: Windows MSVC Debug processor build passed. The headless CLI
dependency build was started separately; its completion is not part of this
focused compile evidence. No tests were added or run,
as instructed for this repository. Encoding and HINT boundaries were audited
against the [C version 2.0 specification](https://docs.riscv.org/reference/isa/v20240411/unpriv/c-st-ext.html).
