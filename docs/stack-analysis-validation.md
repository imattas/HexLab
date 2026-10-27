# Stack frame analysis validation

The analysis library exposes `analyze_stack_frame` over a recovered function and
its basic blocks. It tracks the function-entry stack pointer through x86
`push`/`pop`, recording each implicit push store and pop load as a slot at the
cell's entry-SP-relative offset, `ENTER` with its allocation and nested-frame slot count,
`mov bp,sp`, `mov sp,bp`, `leave`, constant `add`/`sub sp` operations, and
`LEA` relations between SP and BP/FP. Direct `LEA` addresses of
stack slots are retained as address-taking sites; when a read or write at that
entry-SP-relative location is also present, the address site coalesces with the
typed slot. Address-only locations carry unknown width. x86 `PUSHA/PUSHAD` and
`POPA/POPAD` use their decoded operand width and eight-slot count to expose the
implicit stack cells as local slots. Push-all records all eight stores,
including the saved original-SP cell; pop-all records the seven actual loads
and skips the architecturally skipped SP cell. This recovers memory footprint
and access sites, not saved register values. On AArch64 it tracks
`ADD/SUB SP, SP, #imm`, constant `ADD/SUB`
relations between SP and x29 (including restoring SP from x29), and direct typed
memory operands based on SP or x29. `LDP`/`STP` pair operands based on a tracked
SP or x29 produce two adjacent typed slots, each with the instruction's read or
write provenance. Scalar and pair load/store writeback through SP updates the
entry-relative depth, covering common `STP`/`LDP` prologue and epilogue forms.
Post-indexed accesses use the pre-writeback address; pre-indexed accesses use
the adjusted address. On A32 and Thumb it tracks immediate SP adjustments,
`MOV r7/r11,sp`, and constant `ADD`/`SUB` relations that establish r7/r11
from SP or adjust an already tracked frame register. SP restoration from those
frame registers, immediate SP-based load/store operands, and writeback address
modes are also tracked. A32 `STM/LDM` stack saves and
restores with SP writeback map their listed registers to individual four-byte
slots using the decoded IA/IB/DA/DB mode. Direct memory operands based on SP or BP become slots identified by
their bit width and signed offset from the entry stack pointer. Frame-pointer
and stack-pointer references to the same byte range coalesce. Each slot retains
its unique instruction addresses and aggregate read/write use, plus per-site
flags indicating reads, writes, and address-taking. Different access kinds at
the same instruction remain distinct. Address-only sites with unknown width
coalesce with a unique typed slot at the same entry-SP offset; ambiguous widths
remain unknown-width slots and mark the analysis partial.

Immediate stack-address formation is also retained as an address-taking site:
A32/Thumb `ADD`/`SUB` from SP or the tracked r7/r11 frame base, AArch64
`ADD`/`SUB` from SP or a tracked x29, MIPS `ADDI`/`ADDIU` and MIPS64
`DADDI`/`DADDIU` from `$sp` or tracked `$fp`, RISC-V `ADDI` from `sp` or
tracked `s0/fp`, and PowerPC `ADDI` from `r1` or tracked `r31`. These facts
have unknown width and the address-producing instruction as provenance. If an
explicit stack load/store names the same entry-SP byte offset, the address
fact coalesces into that typed slot. This records pointers handed to opaque
code without claiming to follow later accesses through the derived register.

Project analysis derives and retains one `StackFrameAnalysis` per recovered
function in the source-keyed derived cache. The cache format validates these
records against a fresh rooted function recovery before publication; incremental
analysis reuses a record only when its function and all owned blocks are
unchanged. `ProjectSnapshot` publishes the immutable results for CLI and
desktop consumers, so opening the stack-slot view does not rerun stack analysis.

`StackFrameAnalysis::maximum_stack_allocation_bytes` reports the exact
high-water stack allocation relative to function-entry SP when every owned
block is reachable and all stack-depth states remain known and nonnegative.
It includes tracked pushes and explicit stack-pointer adjustments; a proven
frameless body reports zero. The optional stays empty for incomplete functions,
unreachable or missing owned blocks, unsupported architectures or SP writes,
negative stack depth, and conflicting CFG joins. This extent is independent of
slot completeness: unsupported non-stack memory operands can leave `complete`
false while the stack-allocation extent remains proven. Dynamic allocation,
unmodeled alignment, and ambiguous stack changes never produce an extent.

For MIPS32, the analyzer tracks constant `ADDIU`/`ADDI` adjustments of `$sp`,
constant `$fp`/`$s8` relations to `$sp`, and `$sp` restoration from that frame
register through the `ADDU`/`ADD`/`OR` move idioms. For MIPS64, it also tracks
`DADDI`/`DADDIU` adjustments and `DADD`/`DADDU` frame-pointer move idioms. Direct
`$sp`- and `$fp`-based memory operands then share the same entry-SP-relative slot
model. Other writes to `$sp` or the tracked `$fp` invalidate the affected
relation and keep the result partial rather than guessing.

For RV32/RV64, constant `ADDI sp,sp,imm` adjustments, recognized
`ANDI sp,sp,-A` alignments for A = 2, 4, 8 or 16, `ADDI` relations between
`sp` and `s0/fp` (`x8`), and `ADD`/`ADDW` zero-register move idioms are tracked.
Alignment is measured relative to an ABI-aligned function-entry SP and rounds
the tracked depth up to the next aligned boundary. Other masks and alignments
whose incoming SP depth is unknown leave the result partial.
Direct memory operands based on `sp` (`x2`) or the tracked `s0/fp` register then
produce the same entry-SP-relative slots. Other writes to `sp` or tracked `s0`
invalidate the corresponding relation.

For PowerPC32/64, constant `ADDI r1,r1,imm` adjustments and the stack update
forms (`STWU`/`STDU` and immediate load-update instructions) track the entry-SP
depth. `OR r31,r1,r1` and constant `ADDI` relations establish or restore the
common `r31` frame pointer. Direct initialized stack-relative loads/stores
through `r1` or tracked `r31` become slots with read/write provenance. Indexed
update forms, dynamic adjustments, and other writes to `r1` or the active `r31`
frame relation remain partial rather than receiving guessed offsets.

The flow analysis joins predecessor states conservatively across the recovered
CFG. Calls that return normally preserve the caller's stack depth and tracked
frame relation; explicit stack adjustments before or after a call still apply
to the surrounding blocks. A conflicting stack
depth makes the affected stack relation unknown; accesses depending on that
relation are omitted and the result is marked partial. Indexed or segmented
stack references, unsupported SP writes, incompatible CFG joins, incomplete functions and
unsupported instruction contexts do not produce guessed offsets. Unconditional
x86 returns terminate stack-state transfer without treating their implicit SP
update as an unknown clobber. AArch64 writes to SP are modeled for immediate
ADD/SUB from SP or a tracked x29 and scalar or pair memory writeback through
SP; register-based
adjustments and other SP writes invalidate the SP relation and mark the result
partial. AArch64 writes to x29 outside a modeled SP-relative ADD/SUB invalidate
the frame relation. Incompatible incoming frame-pointer relations are joined as
unknown, so x29-based accesses do not guess slot offsets. Derived-cache version
18 persists per-site read/write/address-taken provenance, bounded to one
million sites per function and four million across a cached proposal, and
rejects older payloads for recomputation. When unknown-width address-taken
slots coalesce with typed slots, duplicate per-site provenance is deduplicated
and removed from the budget count, so the limit applies to unique records.
Dynamic ARM32
offsets, ARM register-derived SP changes, and frame-pointer conventions outside
r7/r11 remain unsupported and mark analysis partial. Slots are persisted in
the source-keyed derived cache; ABI type assignment and propagation into
decompiler variable names remain separate.

`stack_analysis` covers x86-16/32/64 local/argument offsets, LEA-derived frame
relations, address-taken locals and coalesced access sites, AArch64 SP/x29-relative
slots, frame setup, restoration and clobber handling, A32/Thumb local slots and multiple-register save areas, aliasing
between BP- and SP-based operands, MIPS32 `$sp`/`$fp`-relative slots and aliases,
and RV32/RV64 `$sp`/`$s0`-relative slots and aliases,
and PowerPC32/64 `r1`/tracked `r31`-relative slots and aliases,
source-site retention and conflicting CFG joins. The desktop pseudocode workflow
shows the resulting slots and navigates from a slot to its first access site in
the function.
