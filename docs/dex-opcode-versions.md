# DEX instruction encoding and version checks

Every DEX code item now receives a complete encoding walk before the bounded
operand decoder and register-category verifier run. This walk rejects reserved
opcode values, unknown payload identifiers, truncated encodings, misaligned
payloads, and encodings whose extent exceeds the method address space.

The version checks follow the Android
[Dalvik bytecode reference](https://source.android.com/docs/core/runtime/dalvik-bytecode):

| Opcodes | Instruction family | Minimum DEX version |
| --- | --- | --- |
| `0xfa`, `0xfb` | `invoke-polymorphic`, `/range` | 038 |
| `0xfc`, `0xfd` | `invoke-custom`, `/range` | 038 |
| `0xfe` | `const-method-handle` | 039 |
| `0xff` | `const-method-type` | 039 |

The walk uses encoded format widths, not the typed operand model. A valid
16-bit register move or a range invoke exceeding the display/operand budget
cannot suppress checks of later instructions. Likewise, packed-switch,
sparse-switch, and fill-array-data payloads are skipped using checked lengths,
including the final fill-array padding byte. Payloads are not constrained by
the decoder's 32,000-byte display budget, and their bytes are never interpreted
as instructions. The scan visits unreachable encoded instructions as well as
reachable instructions.

Malformed reports retain the method identifier index, code-item file offset,
instruction code-unit offset, exact instruction file offset, DEX version, and
opcode byte. Each DEX 041 member is checked using its own header and physical
source offsets. APK entries loaded through the DEX loader receive the same
checks. Container inventory alone does not validate embedded instruction code.

The processor library exposes `inspect_dex_instruction_encoding(bytes, address,
version)`, which returns status, byte size, payload classification, and a reason
on failure. Successful inspection allocates no operand, instruction, or payload
vectors. It proves an encoding extent only: it does not validate branch targets,
switch keys, registers, reference indexes, or register types. These remain the
responsibility of the existing decoder and loader passes.

The new `decode_dex(bytes, address, version)` overload checks the encoding and
version before calling the existing operand decoder. Version zero deliberately
omits version admission checks for raw bytecode; the original two-argument
decoder retains its behavior. Generic architecture dispatch still uses that
raw decoder because its decode context has no containing DEX version.

Legacy optimized opcodes `0xe3` through `0xf9` retain their existing Dalvik
interpretations. A DEX header does not identify an optimized runtime profile,
and this change does not validate their API level, ODEX provenance, signatures,
or quickening semantics. Unknown/reserved opcodes are rejected rather than
assigned a guessed width. Complete ART/Dalvik verification, full external
hierarchies, and complete operand/category verification remain unsupported.

The encoding walk uses constant auxiliary storage, honors cancellation between
encodings, and is bounded by the existing 512 MiB file and aggregate mapped-code
limits. The richer flow pass still stops conservatively when operand decoding
is incomplete; the new encoding/version pass does not stop at that boundary.
