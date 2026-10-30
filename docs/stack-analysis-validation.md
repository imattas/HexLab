# Stack frame analysis validation

The analysis library exposes `analyze_stack_frame` over a recovered function and
its basic blocks. It tracks the function-entry stack pointer through x86
`push`/`pop`, recording each implicit push store and pop load as a slot at the
cell's entry-SP-relative offset, `ENTER` with its allocation and nested-frame slot count,
and `PUSHF/PUSHFD/PUSHFQ` and `POPF/POPFD/POPFQ` using the decoder's exact
operand width and retaining their implicit flag-cell stores/loads,
`mov bp,sp`, `mov sp,bp`, `leave`, constant `add`/`sub sp` operations, and
`LEA` relations between SP and BP/FP. Direct `LEA` addresses of
stack slots are retained as address-taking sites; when a read or write at that
entry-SP-relative location is also present, the address site coalesces with the
typed slot. Address-only locations carry unknown width. x86 `PUSHA/PUSHAD` and
`POPA/POPAD` use their decoded operand width and eight-slot count to expose the
implicit stack cells as local slots. Push-all records all eight stores,
including the saved original-SP cell; pop-all records the seven actual loads
and skips the architecturally skipped SP cell. This recovers memory footprint
and access sites, not saved register values. x86 `mov bp,sp` and `mov sp,bp`
frame relations are accepted only when both operands have the mode's full
stack-pointer width; partial-register writes such as `mov ebp,esp` in 64-bit
mode invalidate the affected relation instead of treating zero-extension as a
preserved stack address. On AArch64 it tracks
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
slots using the decoded IA/IB/DA/DB mode. Register-list transfers through an
established r7/r11 frame pointer recover each four-byte slot using the
pre-writeback base and decoded IA/IB/DA/DB mode. Frame-base writeback updates
the tracked relation; an LDM that restores the tracked frame register
invalidates that relation.
Direct memory operands based on SP or BP become slots identified by
their bit width and signed offset from the entry stack pointer. Frame-pointer
and stack-pointer references to the same byte range coalesce. Each slot retains
its unique instruction addresses and aggregate read/write use, plus per-site
flags indicating reads, writes, and address-taking. Different access kinds at
the same instruction remain distinct. Address-only sites with unknown width
coalesce with a unique typed slot at the same entry-SP offset; ambiguous widths
remain unknown-width slots and mark the analysis partial.

The x86-32 ABI view marks a slot at entry-SP offsets `+4` and above as an
incoming stack argument; offset `+0`, which contains the near-call return
address, is not an argument. Caller-side x86 outgoing arguments are attributed
only when one or more decoded `PUSH` instructions form a contiguous sequence
immediately before a call and the following instruction adds back exactly the
pushed byte count to the stack register (`SP`, `ESP`, or `RSP` for x86-16/32/64).
x86-64 additionally requires a known image-default ABI. Each resulting slot
retains the push source instruction and call instruction as a pair, so the UI
can show the call boundary and navigate to the source. Other cleanup styles,
callee-cleanup conventions, and non-contiguous argument setup remain
unclassified. x86-16 outgoing pushes do not imply that incoming x86-16 slots
have been classified.

Immediate stack-address formation is also retained as an address-taking site:
A32/Thumb `ADD`/`SUB` from SP or the tracked r7/r11 frame base, AArch64
`ADD`/`SUB` from SP or a tracked x29, MIPS `ADDI`/`ADDIU` and MIPS64
`DADDI`/`DADDIU` from `$sp` or tracked `$fp`, RISC-V `ADDI` from `sp` or
tracked `s0/fp`, plus `ADD`/`SUB` register forms only when `x0` makes the
operation an exact copy, and PowerPC `ADDI` from `r1` or tracked `r31`. These facts
have unknown width and the address-producing instruction as provenance. If an
explicit stack load/store names the same entry-SP byte offset, the address
fact coalesces into that typed slot. This records pointers handed to opaque
code without claiming to follow later accesses through the derived register.

RV32/RV64 also recover full-XLEN `OR`/`XOR` copies with `x0` in either
source position and `ORI`/`XORI` copies with the encoded signed 12-bit immediate
zero. These establish `s0/fp` from `sp`, restore `sp` from the tracked `s0/fp`,
and preserve self-copies of those registers. Copying either known base into
another nonzero GPR records an address-taking site at that instruction; later
loads or stores through that destination are not followed. Recognition requires
matching architecture/mode, exact full-width GPR operands and register effects,
and no memory, CSR, floating-status, or control-flow effects. Unknown bases and
conflicting CFG joins remain unknown, so restoration cannot invent an entry-SP
relation. Nonzero masks, other logical identities, and truncated RV64 word
results remain outside this subset. The
identities follow the [RISC-V RV32I integer computational instructions](https://docs.riscv.org/reference/isa/v20260120/unpriv/rv32.html)
and their XLEN-wide RV64I counterparts. These same validated copy identities
can carry a known stack relation from SP, established `s0`, or a tracked
temporary into another temporary. Repeated copies can be chained; writes using
any other operation still discard the destination relation. This does not
extend tracking to nonzero masks, truncated RV64 word results, arbitrary
`ADD`/`SUB` expressions, or unknown memory-indirect pointers.

RISC-V `ADDI`-derived temporary pointers now retain an exact entry-SP-relative
depth in a bounded 32-register map. This covers ordinary and compressed
`C.ADDI4SPN`/`C.ADDI` forms normalized by the decoder, including chained
constant `ADDI` offsets. Direct loads and stores based on such an alias resolve
to typed slots and keep their instruction-site provenance. Any other decoded
write to the alias register invalidates it; calls clear the temporary aliases,
and CFG joins retain one only when every incoming path has the same known
offset. This does not follow arbitrary `ADD`/`SUB` register expressions or
unknown memory-indirect pointers.

Derived-cache version **81** invalidates previously cached stack frames so the
new temporary-pointer copies and ABI argument classifications are recomputed.

For AArch64, full-width immediate `ADD`/`SUB` from SP, tracked x29, or another
tracked temporary can establish a stack-derived address in x0–x30 (excluding
x29, which remains the frame pointer). Later scalar loads/stores and pair
loads/stores through that temporary resolve entry-SP-relative slots. Chained
immediate additions/subtractions retain the exact offset, including the
decoder's shifted immediate value. Pre/post-indexed scalar and pair writeback
through a tracked temporary adjusts its relation from the pre-writeback base;
load destinations that overlap the writeback base invalidate it. Other writes
and calls discard affected aliases, and joins retain aliases only where all
paths agree on the same offset. Register-offset accesses and arbitrary
arithmetic pointer formation remain unsupported.

For AArch64 AAPCS64 functions, entry-SP offsets `+0` and above are stack
argument locations because the return address is held in x30 rather than pushed
on the stack. The incoming-argument flag is set only when a load reads a slot at
such an offset through tracked SP, x29, or a derived alias. Write-only accesses
at those offsets remain unclassified, since a caller can use its stack area for
outgoing arguments; no outgoing-call attribution is inferred for AArch64 yet.

For AArch32 AAPCS32 functions in A32 or Thumb mode, reads from tracked
entry-SP-relative slots at offset zero or above are tagged as incoming stack
arguments after the r0-r3 argument registers. Write-only slots are not tagged.
The analysis reports individual observed slots and does not infer argument
types, aggregate splitting, or the complete signature.

For MIPS32 O32 functions, reads from tracked entry-SP-relative slots at offset
16 or above are tagged as incoming stack arguments after the four 32-bit
argument home words. Reads in the home area and write-only slots are not
classified as overflow arguments. The analysis reports observed slots and
does not infer argument types, paired 64-bit values, or the complete signature.

For ELF64 MIPS N64 functions, reads from tracked entry-SP-relative slots at
offset zero or above are tagged as incoming overflow arguments after the eight
64-bit argument slots. The profile requires EM_MIPS, ELF64, no EF_MIPS_ABI2
(N32) marker, no explicit conflicting ABI selector, and generic SysV/Linux
OSABI metadata. The observed slots are not mapped back to a particular
parameter; write-only accesses and nonconstant stack locations remain
unclassified.

Derived-cache version **88** and function-engine fingerprint suffixes
`aapcs32-stack-argument-slots-v1/mips-o32-stack-argument-slots-v1/mips-n64-stack-argument-slots-v1` invalidate older derived results so frames
and instruction-site provenance are recomputed. The stack record layout is
unchanged; this invalidation covers newly recovered semantics.

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
The 64-bit pass does not treat 32-bit `ADDI`/`ADDIU` results as pointer-width
stack relations, since those instructions sign-extend a 32-bit result rather
than preserving an arbitrary 64-bit stack address.

For NMOS 6502, `PHA`/`PHP` decrement the page-one stack pointer after writing
one byte; `PLA`/`PLP` increment it before reading. The analyzer records those
implicit accesses as one-byte slots relative to the function-entry S value and
coalesces balanced push/pull pairs. `BRK` records its three known implicit
page-one writes (return-PC high byte, return-PC low byte, and status) as
one-byte stack slots and includes them in the maximum depth; its IRQ-vector
control flow remains outside the function CFG. `JSR` records its two implicit
return-address writes at the current and next lower stack cells relative to
the function-entry S value. The balanced call does not change the caller's
propagated stack depth, while the transient two bytes contribute to maximum
stack allocation. `RTS` records reads of the two bytes above the callee's
entry S; `RTI` records reads of the three bytes above the interrupt handler's
entry S (status, then return PC). These accesses use the decoded control
transfer opcode and known NMOS 6502 frame size; analysis does not follow
callees, infer caller-specific stack depths at an entry, or model interrupt
handler control flow. Derived-cache version 90 invalidates cached stack-slot
results from before these implicit accesses were represented.

`TSX` also snapshots the current S depth into X as a frame base. The byte-wide
snapshot can pass through the explicit `TXA`/`TAX` and `TAY`/`TYA` register
transfers, allowing either X or Y to serve as the tracked index while unrelated
writes to the active alias invalidate the relation. `INX`/`DEX` or `INY`/`DEY`
adjust the corresponding alias by one byte while the accumulated displacement
and sampled depth stay within the bounded signed-page range. An 8-bit indexed
memory operand using exactly `$0100,X` or `$0100,Y` resolves to the
corresponding entry-relative byte slot; recognition also checks decoded
register read/write effects and the index width. `TXS` restores S only from a
live X snapshot, including its adjusted value, when the resulting depth remains
in range. Other indexed page-one bases such as `$0101,X` or `$0101,Y` can cross
into page two for some S values, so they remain unresolved and make stack
analysis partial. The analyzer does not infer arbitrary index values or
indirect stack addresses.

Entry-relative NMOS 6502 stack slots are emitted only while their net byte
offset is in `[-127,127]`. Although the hardware stack wraps within page one,
linear offsets outside this signed window can alias another tracked cell after
8-bit wrap. The analyzer keeps propagating the known stack depth but omits an
ambiguous slot and marks the result incomplete. This check applies to indexed
TSX accesses, explicit pushes/pulls, `JSR`, and `BRK` implicit writes; it does
not reinterpret wraparound as a distinct stack allocation. Maximum tracked
allocation is capped at the 256-byte hardware page and marked incomplete if a
path attempts to exceed that capacity.

For RV32/RV64, constant `ADDI sp,sp,imm` adjustments, recognized
`ANDI sp,sp,-A` alignments for A = 2, 4, 8 or 16, `ADDI` relations between
`sp` and `s0/fp` (`x8`), and `ADD`/`ADDW` zero-register move idioms are tracked.
Alignment is measured relative to an ABI-aligned function-entry SP and rounds
the tracked depth up to the next aligned boundary. Other masks and alignments
whose incoming SP depth is unknown leave the result partial.
Direct memory operands based on `sp` (`x2`) or the tracked `s0/fp` register then
produce the same entry-SP-relative slots. Other writes to `sp` or tracked `s0`
invalidate the corresponding relation.

For x86-64, `AND RSP, -A` recognizes low-bit clearing masks for A = 2, 4, 8,
or 16. It uses the ABI entry invariant `RSP % 16 == 8` to compute exact
entry-relative depth after alignment, so later stack slots remain comparable
with pre-alignment slots. Other masks, 32-bit ESP writes, and alignment when
the incoming depth is unknown retain the conservative partial result. This
assumes a normally called x86-64 function entry; custom entry points with a
different stack alignment are not inferred.

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
unknown, so x29-based accesses do not guess slot offsets. Since derived-cache
version 18, the cache persists per-site read/write/address-taken provenance, bounded to one
million sites per function and four million across a cached proposal, and
rejects payloads with an obsolete cache version for recomputation. When unknown-width address-taken
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

Incoming x86-64 stack arguments are identified only for read accesses with a
known image-default ABI. PE selects Windows x64, where entry-SP offsets below
`+40` are excluded for the return address and 32-byte shadow space; ELF and
Mach-O select SysV AMD64, where offsets below `+8` are excluded for the return
address. Raw and unknown image formats do not classify x86-64 incoming
arguments. This mapping is image-level only: per-function ABI overrides are
not supplied to stack derivation, so mixed-ABI functions do not receive
override-aware classification.

RV32 and RV64 base-integer psABI stack overflow arguments are tagged when a
read accesses a recovered slot at a nonnegative entry-SP offset. The first
stack-passed value begins at entry-SP+0; register-passed a0-a7 values do not
create stack slots. The slot records `riscv32` or `riscv64` ABI provenance in
the analysis model, derived cache, CLI, Python API, and desktop slot list. This
is only a stack-location candidate: without a function signature or call-site
argument count, it does not determine which value ordinal occupies a slot,
its type, or whether a caller initialized it. Negative offsets remain local
storage, and writes alone do not classify incoming arguments.
The stack-offset rule follows the [RISC-V psABI procedure calling convention](https://docs.riscv.org/reference/abi/v1.0/riscv-cc-procedure-calling-convention.html).

For PPC64, incoming overflow arguments are tagged when the image default
calling convention is `ppc64le_elfv2` and the instruction context is PPC64.
The default is selected only for ELF64 `EM_PPC64`, little-endian images whose
`e_flags & 3` ABI-version field is 2; raw PPC64, big-endian ELF, ELFv1, and
other ABI flags remain unclassified. The ELFv2 parameter save area starts at
entry-SP+32 and reserves eight 8-byte argument-register slots, so only exact
recovered slots at entry-SP+96 or above qualify. The analyzer requires a read
access and retains
the `ppc64le-elfv2` provenance in cache, CLI, Python, and desktop output. This
does not identify argument ordinals, types, or caller initialization; other
PowerPC ABIs and per-function ABI overrides remain unclassified. The offset
rule follows the [OpenPOWER ELFv2 ABI specification](https://github.com/OpenPOWERFoundation/ELFv2-ABI).

Caller-side outgoing x86 push provenance is retained only for a same-block,
contiguous decoded push sequence followed by a decoded call and an immediately
following decoded `ADD SP,N`, `ADD ESP,N`, or `ADD RSP,N` in x86-16/32/64 mode,
whose immediate exactly equals the total pushed byte count. x86-64 provenance
additionally requires PE/ELF/Mach-O image metadata that selects the
platform-default ABI.
The stack slots retain push and call addresses; preallocated outgoing areas,
stores instead of pushes, nonmatching cleanup, and cross-block sequences are
left unattributed.

AArch64 outgoing stack-slot provenance records direct, write-only SP-relative
`STR`/`STRB`/`STRH`/`STP` stores followed by a direct same-block `BL`. The
store must use a known SP relation, nonnegative displacement from current SP,
and no index or writeback. Stores are discarded across other memory traffic,
SP changes, or control-flow/call boundaries. Pair stores contribute each
element slot, both linked to the single `STP` source and `BL`. This is bounded
evidence for stack slots prepared for a direct call; it does not infer register
arguments or classify arbitrary frame stores as ABI arguments.

For a PE-selected Windows x64 ABI, direct write-only stores through RSP into
the 32-byte shadow area are linked to a following same-block call when the
stack depth is known, at least 32 bytes, and unchanged between the store and
call. Stores must fit wholly in the shadow area; unrelated memory traffic,
RSP writes, and control-flow boundaries discard pending evidence. The CLI
labels these `win64-shadow@` stores separately. This records caller home-area
use, not a recovered argument value or proof that the store was initialized
for the callee.

RISC-V outgoing stack-store provenance links a same-block, full-XLEN `SW`/`SD`
through `0(sp)` or a positive SP displacement to the next call. The stack
depth must be known and unchanged, and the store must map to a recovered slot;
other memory traffic, writes to `sp`, or control-flow boundaries clear pending
stores. The source is labeled `riscv-store@` in CLI output and
`riscv-store` in Python results. This records a stack value prepared before a
call; it does not infer the argument ordinal, prove initialization, recognize
aggregate/by-reference values, or handle cross-block setup.

For PPC32/PPC64, direct write-only `STW`/`STD` stores through `r1` with a
nonnegative displacement are linked to the next decoded same-block call. The
store width must agree with the opcode (32 bits for `STW`, 64 bits for `STD`);
indexed, update-form, and other stores are not captured. The stack depth must
be known and unchanged, and the store must resolve to a recovered stack slot.
Other memory traffic, writes to `r1`, control-flow boundaries, or a stack-depth
change discard pending evidence. The CLI reports `ppc-store@` and Python reports
`powerpc-store`. This records an observed pre-call stack write; it does not
assign an argument ordinal, prove that the callee reads it, or infer register
arguments.

For MIPS32 and MIPS64, direct write-only `SW` and `SD` stores through `$sp`
are linked to the next same-block decoded call. `SW` is recognized in MIPS32
with a 32-bit stack operand; `SD` is recognized in MIPS64 with a 64-bit stack
operand. The base and address widths must match the active mode, the
displacement must be nonnegative, stack depth must be known and unchanged, and
a recovered slot must match. Indexed or update forms, other store widths,
unrelated memory traffic, writes to `$sp`, and control-flow boundaries clear
pending evidence. CLI displays `mips-store@`; Python reports `mips-store`. This
identifies an observed stack write before a call, not an argument slot ordinal,
callee read, or argument value.

For A32 and Thumb, unconditional `STR`, `STRB`, and `STRH` with an immediate
nonnegative offset from `sp` (r13) are linked to the next unconditional
same-block decoded call. The decoded `ArmMemoryOperand` must be pre-indexed,
non-writeback, and carry a 32-, 8-, or 16-bit width matching the opcode. Stack
depth must be known and unchanged, and a recovered slot must match. Indexed,
subtracting, post-indexed, writeback, and conditionally executed stores/calls
are not recorded. Other memory traffic, writes to `sp`, and control-flow
boundaries discard pending evidence. CLI labels the source `aapcs32-store@`;
Python reports `aapcs32-store`. This is an observed stack write before a call,
not an argument ordinal, value, initialization proof, or callee-read claim.
# x86-32 callee-cleanup argument evidence

Stack analysis labels an accessed x86-32 entry-stack slot as
`x86-32-callee-cleanup` only when the recovered function is complete and every
near return in its recovered blocks has the same explicit `ret imm16` byte
count. The return address occupies entry-SP+0; slots wholly inside the cleanup
range beginning at entry-SP+4 receive the label. Plain `ret`, far returns,
missing instruction facts, mixed cleanup counts, and incomplete functions do
not provide callee-cleanup evidence. Other accessed slots retain the generic
x86-32 near-call label. This records epilogue evidence without naming a source
calling convention such as `stdcall` or inferring unobserved arguments.
