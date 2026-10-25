# ARM64 COFF to static PE32+

`link_coff_executable` accepts homogeneous ordinary little-endian ARM64 COFF
objects (`Machine = 0xaa64`) and emits a fixed-base PE32+ console image.
The existing `link_coff_amd64_executable` wrapper still rejects other machines.
The generic API retains AMD64 BigObj, import and unwind handling on that path;
ARM64 does not reuse those architecture-specific encodings.

The existing archive command selects its machine from the root object:

```text
hexlab_cli archive link-pe helpers.lib --root-object entry.obj --entry entry --output linked.exe
```

Before fixed-point symbol selection, the CLI filters ordinary and anonymous
member prefixes by root machine. The existing bounded COFF symbol reader then
uses ordinary ARM64's 18-byte symbol/auxiliary layout to collect external and
common definitions and unresolved references. Members with another machine,
including ARM64EC/ARM64X, cannot provide a same-named symbol. The final linker
also checks every selected object's machine. Selection can encounter an ARM64
import or BigObj provider, but linking that selected form fails explicitly.
No archive mutation or external library discovery is performed.

## Sections, symbols and image properties

Initialized `.text`, `.rdata`, `.data` and their `$` subsections are accepted,
along with zero-filled `.bss` and its subsections. Code must have code/read/execute
characteristics, read-only data initialized/read characteristics, writable data
initialized/read/write characteristics and BSS uninitialized/read/write
characteristics. Unrepresentable flags such as shared, discardable, nonpaged,
noncached or linker-removal semantics reject instead of being silently dropped.
Code contributions have four-byte extents and are placed at least four-byte
aligned. The external entry must identify a complete aligned instruction inside
a selected input code contribution.

External/common symbols, long names, bounded deterministic subsection merging
and the existing supported COMDAT selection modes are shared with the AMD64
linker. Common allocations coalesce by name into BSS with natural alignment
capped at 32 bytes; selected strong definitions take precedence. Losing COMDAT
payloads and relocations are omitted, named externals redirect to the selected
provider, and references to discarded local definitions reject.

Output uses ARM64 machine identity, PE32+ magic, console subsystem, fixed image
base `0x140000000`, Windows/subsystem major version 10, large-address-aware and
relocations-stripped file flags. Code is RX, constants are R, initialized data
and BSS are RW. File alignment is 512 bytes; section alignment is at least 4096
bytes and increases to preserve greater selected input alignment. BSS has
virtual size and no raw payload. Import, exception and base-relocation
directories remain empty, and dynamic-base is not advertised. The shared header
writer stores `SizeOfImage` at optional-header offset 56 and leaves CheckSum zero.

## Relocation subset

All non-no-op fields must lie wholly within their initialized input
contribution. Overlapping fields reject. Instruction fields must be aligned
within `.text`; supported opcode shapes and access sizes are checked before
patching. Unaffected instruction bits are preserved.

| ARM64 COFF type | Supported behavior |
| --- | --- |
| `ABSOLUTE` (0) | No-op; bounded source offset is checked, and no symbol or field is read. |
| `ADDR32` (1) | Target VA plus signed encoded 32-bit addend, checked to fit unsigned 32 bits. At the default image base, ordinary positive in-image addresses usually do not fit. |
| `ADDR32NB` (2) | Target RVA plus signed encoded 32-bit addend, checked to fit unsigned 32 bits. |
| `ADDR64` (14) | Target VA plus signed encoded 64-bit addend, with checked overflow/underflow. |
| `REL32` (17) | Target plus signed encoded addend minus field VA minus four, checked to fit signed 32 bits. |
| `BRANCH26` (3) | `B`/`BL` with zero encoded immediate, aligned executable target and signed 28-bit byte displacement. |
| `BRANCH19` (15) | `B.cond` with conditions 0–13 or `CBZ`/`CBNZ`, zero encoded immediate, aligned executable target and signed 21-bit byte displacement. Literal loads and other opcode shapes reject. |
| `BRANCH14` (16) | `TBZ`/`TBNZ` with zero encoded immediate, aligned executable target and signed 16-bit byte displacement. |
| `PAGEBASE_REL21` (4) | `ADRP`; the signed encoded 21-bit COFF addend is in bytes and is added to the target before computing the signed page delta. |
| `REL21` (5) | `ADR` with its signed encoded 21-bit byte addend and checked signed 21-bit final byte displacement. |
| `PAGEOFFSET_12A` (6) | Unshifted `ADD`/`ADDS` immediate; applies the encoded byte addend and patches the target's low 12 bits. |
| `PAGEOFFSET_12L` (7) | Valid unsigned-immediate integer or scalar/vector load/store, including Q-sized accesses. The encoded addend is scaled by access size; final page offset must respect that size's alignment. Prefetch and reserved shapes reject. |

ADRP and page-offset relocations use independent COFF implicit addends; no
instruction-pair or register-dataflow proof is claimed. Page-offset patching
keeps the low page offset after addition, as required for the corresponding
ADRP calculation. Branch veneers and encoded nonzero branch addends are not
implemented. Range failures return unsupported instead of truncating.

## Explicit gaps and validation evidence

ARM64 `.pdata`/`.xdata`, packed/full unwind records, short/import objects,
BigObj, ARM64EC/ARM64X, directives, debug sections, weak-external aliases,
TLS, base relocations, section-relative relocation families, token/section
relocations, unsupported opcode forms and branch veneers remain unsupported.
Non-no-op relocations stored in BSS reject. Runtime imports, CRT startup and
automatic dependencies are not synthesized. This is useful for freestanding
objects whose contributions fit the subset, rather than general Windows
application linking; ordinary compiler objects carrying unwind or directive
sections need to be produced without those forms.

`CoffLinkLimits` bounds object, symbol, relocation and output counts; existing
archive metadata/name/selection limits and cancellation remain active. The CLI
does not publish output until selection and linking succeed. Source review
covered machine dispatch, archive filtering, section permissions/alignment,
symbol rebasing, implicit addends, opcode masks, field overlap/range guards,
entry constraints and PE header offsets. No builds, tests or generated fixtures
were run in this increment. Serial `hexlab_loaders` then `hexlab_cli` compilation
and ARM64 output/runtime validation remain follow-up work.

Format evidence: [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and [LLVM COFF relocation implementation](https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp).
