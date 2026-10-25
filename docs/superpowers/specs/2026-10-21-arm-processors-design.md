# ARM processor family design

## Intent and authority

Extend the original C++20/wxWidgets modular HexLab engine toward the full approved IDA-class objective. ARM/Thumb/AArch64 are required processor families, not a replacement objective. Preserve two tools, eight engine DLLs, existing domain/provenance/transaction boundaries and user data. Standing user authorization removes approval pauses. Execute inline; no per-task agents or commits/index mutations. One fresh immutable whole-stage reviewer follows complete acceptance.

## Architecture and sequence

Keep decoding in the shared processors engine, followed by shared analysis integration. The user's 2026-10-21 instruction explicitly permits finding and incorporating existing projects/code. This supersedes the earlier original-engine-only restriction: suitable open-source decoders, lifters and decompiler components may be reused with their licenses, attribution and source provenance retained. Existing original decoder work remains usable; upstream reuse does not require another approval. A GUI-only disassembly implementation would diverge from CLI/SDK and persistence. Start with A64 (fixed four-byte instruction state), then A32/T32 and mixed-state contexts. Unknown extensions and unavailable runtime targets remain explicit, while required unimplemented families stay tracked.

Existing enum ordinals and operand variant indexes remain stable. Append ExecutionMode a32=4, thumb=5, a64=6. Append architecture-specific register banks (A32 registers, A64 general registers, SP, zero register and NZCV) and opcodes without reusing x86 spellings or flag semantics. Register31 is SP or zero according to the instruction form; zero is not writable architectural state. W writes describe32-bit destinations with architectural zero-extension implicit in this bank/width combination. LR is x30 for A64 and r14 for A32/T32. Calls write LR, never claim x86 stack pushes. Conditions use ARM condition numbers and dedicated ARM mnemonics.

First A64 slice: B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/BR/BLR/RET, NOP/BRK, MOVN/Z/K, ADD/SUB immediate with flag variants, ADR/ADRP, unsigned-immediate integer LDR/STR including byte/halfword widths. Preserve all original four bytes, operand widths/access, implicit register effects, flags, data/flow targets. Packed immediates have no invented contiguous byte EncodedField; subsequent relocation handlers verify source words and opcode bit patterns explicitly. No SIMD/SVE/SME/PAC/system instruction is falsely decoded as an implemented scalar form. Instruction address must be four-byte aligned;0..3 bytes are truncated. Context mismatch, segmented memory, x86 stack-size overrides and unsupported instruction byte order are rejected. Address overflow retains a decoded displacement with unavailable target, never wraps into another mapped fact. ADRP aligns the current instruction address to a page before adding its signed page displacement.

A32/T32 require predication, shifts, carry effects, PC biases, literal pools, register lists, writeback and interworking. Add typed ARM-specific operand/control metadata before claiming these forms. T32 prefix classification must distinguish a truncated32-bit instruction from a complete16-bit instruction. IT blocks carry explicit predicate context; decoding an isolated IT-controlled instruction cannot invent its predicate. BX/BLX target state is derived from encoded/state-bit evidence and remains unresolved for unknown register values. No input is executed while loading or decoding.

## Image and analysis integration

A64 raw and compatible PE/ELF/Mach-O mappings select explicit A64 mode. Inconsistent width/order/CPU combinations remain metadata-only. A32/T32 mode intervals come from source declarations (ELF mapping symbols/function-state bits, platform contracts), durable raw profiles or user override; data intervals cannot seed code. Immutable source-bound context ranges participate in mapping identity and cache keys. Entry and target canonicalization preserves physical offsets separately from ARM state bits. Conflicting interpretations at one physical address remain conflicts, not arbitrary traversal order.

Use instruction-specific continuation and flow effects throughout coarse/reachable, function/block recovery, manual listing, references, graph and Follow. A64 calls have ordinary next-PC continuations plus an LR write. Conditional branches read NZCV only where encoded; compare/test branches read their GPRs instead. Mixed-state transitions must agree with authoritative destination context or surface a transition conflict. Per-address context lookup and hard data/encryption windows apply to every automatic/manual/cache path. Decode limits and cancellation remain bounded.

ELF/Mach-O/PE relocation support is implemented per documented architecture type with original record/operand-bit provenance. Unapplied relocation placeholders never fabricate direct callees. Only source-bound proven values become Follow targets. ADRP/page-relative pairs and split immediates require matched namespace/source/instruction evidence, not a nearby-instruction guess. Runtime imports/PAC remain unresolved. Partial states remain inspectable.

## Persistence and compatibility

### Task4 image-context contract

The first Task4 phase adds an optional immutable `ArmImageProfile` to ImageLayout.
Its disjoint ranges distinguish A32, Thumb, data, unknown and conflict. An explicit
profile makes uncovered addresses unknown; it never falls back to a whole-domain
code mode. Code windows stop at each declaration boundary, even between adjacent
ranges of the same mode. Data, unknown and conflicting ranges have no code window;
plaintext reads remain available independently. Context lookup reports a conflict
error for conflicting declarations. Lookup uses sorted ranges and binary search.

Each range and explicit code root retains one or more typed source declarations:
raw declaration, ELF mapping symbol, ELF function symbol, platform entry or user
override, with namespace/record identity and optional file evidence. ELF and
platform records require nonempty in-file evidence. Generic image validation
checks shape and extents; format loaders must separately verify actual record
contents before producing these claims. Raw declarations and overrides are
explicit declarations, not inferred source bytes. Sources are canonicalized by
their full identity; range boundaries are preserved. A mapping symbol alone does
not prove Thumb IT state is clear. A root with a known-clear Thumb IT claim must
also cite a function/platform entry or an explicit raw/user declaration.

Profiles require little-endian ARM32 byte-addressed domains without x86 stack or
segmentation options. Code ranges have aligned starts and lengths (A32 four,
Thumb two bytes), executable initialized backing within one segment. All ranges
must fit initialized mappings; roots must agree with a code range and remain
outside code exclusions. One million ranges/roots/source records and 64 MiB of
aggregate profile records bound validation work. Full range validation precedes
root lookup. Sorting permits input-order-independent identity while retaining
distinct provenance and hard declaration boundaries. Absent profiles retain the
exact historical mapping fingerprint; present profiles add an explicit hash tag,
including every source and root claim. An empty explicit profile differs from an
absent one and supplies no code context.

This phase advances engine25 to26 after the genuine25 capture; it adds no derived
wire fields, so schema11/reference9/database-reference10 remain unchanged.
Automatic A32/Thumb flow stays guarded until the later Task4 source-bound IT,
predicate, transition, computed-PC and relocation-barrier work is implemented.

### Task4 durable raw declarations

Add a bounded `ArmRawProfile` with a single ARM32 flat mapping (base address and
permissions), disjoint absolute ranges, and an optional explicit entry carrying
A32 or Thumb mode and a separate known-clear/unknown Thumb IT claim. Range kinds
are A32, Thumb, data or unknown; contradictory overlapping raw declarations are
rejected, rather than assigned an arbitrary priority. Canonicalize ranges by
address. Use little-endian byte-addressed ARM32 domains; check complete aligned
code units, 32-bit extents, and agreement between entry and range. A profile can
be data-only or have no entry. Its uncovered bytes remain unknown.

Human text uses `hexlab-arm-profile 1`, `base <domain> <offset>`,
`permissions <rwx-mask>`, `entry none` or `entry <offset> a32|thumb-clear|thumb-unknown`,
`ranges <count>` and `range <offset> <size> a32|thumb|data|unknown` lines. Accept
bounded UTF8 comments, whitespace and hexadecimal/decimal unsigned numbers;
canonical output uses sorted ranges and lowercase hexadecimal coordinates.
Limit text to 1 MiB, lines to 4096 bytes and ranges to16384. Parsing, validation,
formatting and file reading honor optional cancellation tokens. File readers
check cancellation before/after bounded I/O. Storage extent is checked at load.

Append an ARM profile to RawOptions and an alternative ARM profile path to the
worker OpenRequest. Fields outside an embedded profile must agree exactly.
Generate Image raw-declaration origins from canonical range ordinal (1-based)
and an explicit entry origin0, namespace0; never invent ELF evidence. The primary
mode remains unknown; every decode uses context_at. Durable recipe version3,
kind6 embeds length-prefixed canonical profile text, never its external path.
Old flat/x86/MachO/ELF recipe encodings retain their exact existing bytes. Reject
truncation, noncanonical text, extra bytes and conflicting opening options.
Expose `--arm-profile` in both CLI opening parsers. Project reopen must retain
the declarations after removal of both external profile and original input;
annotations/history, patches, undo/redo and Save As remain intact.

Preserve actual26 first, then advance engine27. No new derived/reference fields
are introduced here (schema11/ref9/DBref10). Raw ARM projects retain valid mappings
with incomplete automatic analysis until source-bound IT/flow integration; manual
decode uses the authoritative intervals. Durable raw declarations do not replace
transactional mode-override operations, ELF source declarations or native Task6
workflow requirements.

Before changing engine20 semantics, capture actual20 project/cache/reference payloads with copied matching SDK/runtime/source in a NEW immutable prefix. Promote exact bytes for compatibility tests; never rewrite old headers/keys/checksums. Advance analysis engine identity when decoder/root/reference semantics change. Existing instruction wire record can represent the initial A64 scalar forms; later ARM-specific metadata requires an explicit schema advance before serialization. Every new fact must round-trip and be checked against canonical current decoding and source identity. Preserve UUID, names/comments, edits/undo/redo/history and embedded source on readonly old-cache recomputation.

## CLI, wx and SDK

Append raw architecture/mode choices to shared CLI/project/native opening flows. Presentation uses architecture-specific formatting and addresses with explicit contexts. Metadata grids and GUI callbacks do not decode or parse inputs. Actual workflows must prove navigation, references, mode transitions, edits, asynchronous stale-result rejection, Save As/export and source-missing reopen. Installed public consumers link only the eight installed engine import libraries and prove actual DLL paths. wx stays outside engine dependencies.

## Validation and limits

Literal typed tests independently assert bits, widths, flags, register31 behavior, PC biases, negative/max displacements, alignment, truncation and unsupported extensions. Compile self-authored A64/A32/T32 code/assembly with pinned clang; independently compare llvm-objdump/llvm-readobj projections and exact relocation records. Source words and expected targets are validated separately from text aliases. Oracle executable/tool hashes and compiler commands are retained; missing tools fail required tests. Semantic negative mutations must fail. Host execution is not an ARM execution oracle; later emulation/execution-backed semantics must be labeled separately.

Acceptance requires full headless Debug/Release, desktop alone, disconnected and BUILD_TESTING=OFF builds; current/historical cache checks; compiler/object differential corpus; actual CLI/native project workflows; public SDK and new installed prefix with dependency/export/module-path proofs, nonblank readable owned-window captures and full file inventory. One independent immutable review, parent rulings for every finding/declined item, one material RED/GREEN fix pass and full revalidation close only this processor stage. Broader instruction inventory, types, ABI recovery, decompiler, debugger and platforms remain required by the active full objective.

## Primary references

- Arm Instruction Set Reference Guide: https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab
- Arm ELF32 ABI/mapping symbols/interworking: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst
- Arm ELF64 ABI/relocations: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst

Reviewed inline for scope, enum stability, byte-vs-bit provenance, endian/context limitations and acceptance coverage. Fixed-width A64 work does not stand in for unfinished A32/T32 obligations.
## Task3 concrete processor-state contract

Implement Task3 in dependency order: (A) ARM instruction-control metadata and A32
control transfers with the v9 derived wire, (B) typed shifted registers, register
lists, pre/post-index/writeback memory and A32 scalar data forms, (C) T32 decoding
with explicit IT-state inputs and independently checked compiler fixtures. All
three remain required; a control-transfer checkpoint is not full A32/T32 support.

Append optional `ArmInstructionInfo` to Instruction. It carries predicate kind
(always/condition/unknown-IT), interworking (none/address-bit0/forced-A32/forced-
Thumb), flag-write mask and whether known, writes-PC/writeback, multiple-memory
addressing mode, IT input/output known-state bits, target/return execution modes
and an optional typed link Address. Existing Instruction.condition holds the
semantic ARM condition; original instruction bits retain the encoded condition.
Conditional writes/returns remain guarded by this metadata. Link addresses keep
the Address domain and return state separately; no Thumb bit is folded into a
physical address. A32 calls write r14 with the next instruction address, not the
architectural PC+8. Direct targets use PC+8 and checked32-bit coordinates.

The first A32 subset implements B/BL/BX/BLX, architectural NOP, BKPT and SVC under
the Armv7 A-profile contract. BLX immediate is unconditional and changes to Thumb;
register exchange retains unavailable target state. Conditional control is not
silently consumed by existing unconditional analysis: image/analysis integration
and state-aware continuation remain Task4. ARM metadata does not change A64's
existing typed facts.

For phaseB, append ArmShiftedRegisterOperand, ArmRegisterListOperand and
ArmMemoryOperand rather than encoding A32 shifts/writeback as x86 addressing.
Keep immediate versus register shifts, RRX/carry input, add/subtract offsets,
pre/post indexing, base writeback and PC-relative address computations explicit.
Logical flag effects retain a per-flag write mask; unknown/preserved C/V are not
reported as overwritten. Exception-return/SPSR and unimplemented privileged forms
remain explicit unsupported states.

IT state is a decode-state input distinct from the static Image domain context.
The Thumb API must represent unknown versus known-no-IT versus active IT, and
retain state before/after the instruction. It must not invent the predicate or
implicit flag effects of an isolated Thumb word. Task4 establishes source-bound
IT chains at instruction boundaries and validates cached state against the
actual prefix/root flow; accepting self-consistent serialized IT bits alone is
insufficient. Until that integration exists, no automatic Thumb analysis is
advertised. Nested/illegal IT combinations must reject, and a32?Thumb transitions
must agree with authoritative destination context.

Derived schema9 serializes the new control metadata before instruction bytes so
canonical decoding can consume a future explicit Thumb state. A32 metadata is
recomputed from source words; every serialized field is compared to canonical
decoding. Reference wire shape7 is retained during phaseA because its expression
shape has not changed; advance reference payload8/cache9 when phaseB introduces
new reference operand forms. Engine23 distinguishes phaseA semantics. This is a
versioning ruling based on actual changed wire shapes, not a rewrite of old
payloads. Genuine engine22 A64/schema8/ref7 production is already sealed and must
supply the schema transition test.

PhaseB concrete operand/wire contract (implemented engine24): Operand indexes6/7/8 append ArmShiftedRegisterOperand, ArmMemoryOperand and ArmRegisterListOperand. Shifts retain source register, kind LSL/LSR/ASR/ROR/RRX, decoded immediate amount and optional amount register. Immediate LSR/ASR zero fields decode to32, ROR zero to RRX1; a register-controlled amount is distinct from immediate zero. Memory carries base, a uint32 offset or shifted-register offset, add/pre-index/writeback booleans, data width, sign-extension and optional physical literal address. Memory shifts cannot have register-controlled amounts. Register masks and IA/IB/DA/DB remain separate from x86 stack operands. Source words remain authoritative; a low-level encoder re-decodes each record and rejects altered typed operands/metadata. This does not authorize automatic ARM flow adoption.

flags_written contains known-written NZCV bits. For register-controlled logical shifts, NZ writes are known, while C may be preserved for a zero runtime shift: flags_known=false marks that uncertainty and the input flags dependency is retained. V is preserved. Arithmetic S writes all NZCV regardless of shifter carry. RRX and ADC/SBC/RSC read carry. PC data sources remain typed; stores do not fabricate a constant PCStoreValue. Armv7 ALU/loaded PC exchanges retain unavailable destination state until Task4 can establish it.

Version ruling: actual accepted23/schema9 control records are sealed before phaseB, so the new instruction operand variants require derived10 and engine24. Standalone reference writer8 adds ARM memory expression tag6; reference DB cache9 distinguishes adoption policy. Reader7 supports only its original forms and preserves old IDs/source keys, rejecting a checksum-valid7 payload that introduces tag6. Genuine23 A64 schema9/ref7 and prior22 schema8/ref7 are unchanged migration fixtures, never generated by rewriting a current header/key/checksum. Task3C Thumb/IT and Task4 source-bound mixed-state analysis remain required; pure A32 decoder capability must not bypass the automatic-flow guard.
