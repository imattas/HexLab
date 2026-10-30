# ARM processor validation

The ARM processor stage is in progress under the full IDA-class objective.
Design: superpowers/specs/2026-10-21-arm-processors-design.md. Plan:
superpowers/plans/2026-10-21-arm-processors.md. Execution is inline with one
fresh immutable whole-stage review only after all acceptance evidence exists.

The initial original A64 decoder lives in the existing processors DLL and
uses the shared typed instruction/formatter API. It has no foreign decoder
or GUI dependency. A32/T32 modes are reserved by appended enum values but
are not enabled. A64 raw/container analysis/project/native integration is
still Task2 and later; decoder support alone does not prove those workflows.
SIMD/SVE/SME/PAC/system forms remain unsupported. Big instruction byte order,
x86 segmentation/stack overrides and incompatible architecture/mode pairs
are rejected. Four-byte alignment and truncation are explicit. Register31
is distinguished as SP or zero for each form; calls write LR without x86
stack effects. Packed immediate fields do not claim a byte EncodedField.

The scalar integer subset now also decodes A64 logical immediates for AND,
ORR, EOR, and ANDS. It validates `N`/`sf`, rejects reserved empty or all-ones
element encodings, rotates the selected contiguous run within its encoded
element, and replicates that mask to the W/X width before emitting a typed
immediate. The A64 pseudocode lifter consumes these three-operand forms as
width-typed bitwise expressions. NZCV writes are recorded for ANDS, while
complete logical-flag predicate reconstruction remains open. The implementation
follows Arm's A64 logical-immediate bitmask encoding and `DecodeBitMasks`
constraints in the [Arm A-profile A64 ISA reference](https://developer.arm.com/documentation/ddi0602/latest).

Initial real RED (`out/arm-task1-a64-red.log`) has227 checks/219 failures
against the old decoder. The first scalar GREEN has1530 checks/zero failures.
A subsequent explicit AL/NV flow/public-opcode-name RED/GREEN checks that
always-true conditions do not invent an untaken edge. Current focused/full
results will be recorded below after the broader header rebuild finishes.

A self-authored27-instruction assembly corpus is compiled for
`aarch64-none-elf`; the independent comparison runs pinned clang23.1.3 and
llvm-objdump with original source/word/target comparisons. Three exact
observed aliases (NOP/HINT, MOVZ/MOV, MOVN/MOV) are explicitly normalized,
and shifted ADD immediates are compared as their effective scalar value.
A deliberately changed decoded branch target must fail comparison. Typed
register/flag/access effects are checked separately by literal tests;
text comparison is not a CPU execution or full-ISA oracle. Input files are
never executed. Missing/mismatched tools fail; required test-only tools
remain excluded from production builds.

Before semantic advance, actual engine20/schema8 ProjectSession and Store
ran once against copied matching accepted SDK/DLLs in the NEW immutable
`out/arm-cache-v8-v20-capture`.626 sealed records include source, SDK,
runtime, producer executable/source, original project/input and annotations.
Engine SHA9222b688ffd6dba6952b65c732464e7c4ade8a4f448f912de161739a750efc25.
Derived6175 bytes SHAc504408a2e8ec553774644e15644031332b5a821a9d8a8ab72046f3232ab6c04.
References2593 bytes SHA83bd05662fcab1ffe8e8c495585bd07c38550e64ebda27060267a23fefad901d.
Promotion fixtures are byte-identical; no header/key/checksum rewriting or
historical producer run against newer DLLs occurred. Decoder semantics
advance engine21; instruction wire shape/schema8 and reference payload7
remain unchanged at this checkpoint. Future ARM-specific metadata requires
an explicit cache schema change before serialization.

Accepted MachODebug/ElfDebug installations and historical captures remain
immutable. No new installed ARM release, processor-stage final review,
execution oracle or full ARM-family completion is claimed at this point.
Focused current GREEN:1560 typed decoder assertions; seven-generation genuine old-cache compatibility;27 compiler-generated source-word/text comparisons including a changed-target rejection (out/arm-task1-final-focus.log). Oracle normalization RED retained in out/arm-task1-focus.log: a tab before LLVM operands prevented ADD shift folding; whitespace normalization before classification fixes the comparator. ADR representation RED1548checks/4failures is retained. ADR/ADRP now use the existing address-only MemoryOperand with original signed displacement/IP-relative marker and optional resolved address, no memory read and no control-flow target; underflow/overflow retains decoded facts. This preserves the existing instruction wire shape. Full95 headless Debug/Release and109 desktop gates are in progress; no success claim yet.

Task1 current-source gates VERIFIED: headless Debug95/95 (105.20s),
Release95/95 (100.61s), desktop Debug109/109 (135.06s). Desktop ran alone
after both build trees and all headless tests ended. Logs:
`out/arm-task1-full-{debug,release,desktop-idle}.log` and associated build logs.
No timeout or assertion was weakened. Focused decoder1560 checks and genuine
seven-generation cache91 checks pass. All three fresh A64 compiler oracle
reports compare27 projections and verify nine identities each with zero
mismatches (`out/arm-task1-oracle-report-audit.json`). Actual wrong-tool and
missing-tool runs fail with no passing report left behind. No ARM input
execution is claimed. All build/test/app processes were terminal afterward;
idle MSBuild reuse nodes are excluded from the active-work audit.

Preservation: accepted MachODebug1064/ElfDebug698 and engine20capture626
recorded hashes remain unchanged (`out/arm-task1-preservation-audit.json`).
Six earlier Mach-O captures retain3049 hashes with zero mismatches
(`out/arm-task1-historical-preservation-audit.json`). These total5437
preserved records. No accepted installation was overwritten, no commit or
index operation was performed, and no per-task agent was dispatched.

This completes Task1's decoder checkpoint, not the ARM stage. Task2 must
integrate A64 raw/container contexts, continuation/analysis/reference/cache
validation and architecture relocation provenance. A32/T32 decode and mixed
state contexts remain required Tasks3–6, followed by full stage delivery and
one immutable review in Task7. Before any further engine21 semantic advance,
capture a genuine21 baseline with matching current runtime/SDK/source in a
NEW prefix; engine20 and earlier captures stay sealed. The full objective
remains active beyond all of these tasks.

## Task2: A64 loading, analysis and persistent projects

The shared engine now enables A64 for explicit raw mappings and compatible
PE32+/ELF64 little-endian/Mach-O64 little-endian inputs. Class/order mismatches
remain inspectable without enabled decoding. Universal selection retains the
existing x64/x86 preferences and ranks A64 before unsupported slices; durable
selection remains pinned. CLI standalone/project parsers accept `--arch a64`.
The native raw dialog appends AArch64 after the three existing choices and
rejects a misaligned entry through the same raw validation API.

A64 continuation, typed GPR/SP/zero/NZCV validation, packed relative expressions
and source/reference/cache validation use the existing shared pipeline. The
processors API supplies `control_operand_index` to analysis and CLI so CBZ/TBZ
references identify their nonfirst relative operand. Packed immediates do not
invent a contiguous byte EncodedField. Original instruction-word overlap queries
retain source relocation IDs and bounded lookup/match/cancellation behavior.

Actual compiler ELF and Mach-O objects exercise6/4 original relocation rows.
ELF RELA CALL26/JUMP26 use the defined symbol plus explicit addend with no x86
next-PC bias. Unsupported packed REL forms retain unavailable addends and
partial metadata rather than interpreting opcode words as scalar addends.
Mach-O canonical zero-immediate BRANCH26 resolves the declared defined symbol;
nonzero embedded immediates, explicit ADDEND/page groups, imports, ambiguity,
weak/runtime/retained/encrypted forms remain unresolved. The source-word equality,
shape and alignment checks are explicit. In particular, instruction addends
belong to explicit Mach-O companions; the negative regression rejects a fake
embedded addend. Primary reference:
https://raw.githubusercontent.com/llvm/llvm-project/main/lld/MachO/Arch/ARM64Common.cpp
Broader paired equations remain Task5; this checkpoint does not claim them.

New61-check image/analysis/cache coverage proves the four formats, source context
round-trip, a checksum-valid context forgery rejection, section/CPU selection and
instruction windows. Data declarations, encryption, a mapping gap and uninitialized
backing stop decoding/coarse/recovery and prevent old-cache adoption; a complete
word ending at an exclusion boundary remains valid.58 compiler-object checks
cover declared targets, unresolved placeholders, nonfirst control operands,
encrypted source and noncanonical words, plus typed provenance round-trip.

The56-check project workflow covers all four input forms plus real ELF/Mach-O
objects: committed names, source-bound Follow, call-to-NOP invalidation, undo/redo,
exact whole-input export and protected source, independent Save As UUID, embedded
readonly reopen after removing the owned external source, cache-hit adoption,
annotations/revisions/history and mutation refusal. The actual wx raw dialog
was tested RED (missing choice), then GREEN with A64 and unchanged existing
mode indices/alignment validation. Full A64 native editor/mixed-state/stale-worker
workflows remain Task6. Seven CLI commands plus input-hash preservation pass;
intentional indirect control flow reports partial status3 rather than claiming
complete analysis. The obsolete PE-ARM64 test now verifies an unsupported
instruction under a recognized CPU instead of expecting CPU-level rejection.

Before engine22, genuine engine21/schema8 ran once against a freshly installed
matching headless SDK/runtime/source in NEW `out/arm-cache-v8-v21-capture`.
656 sealed records preserve the source/runtime/SDK/producer/project/input and
actual6175-byte derived payload
SHA08e0d6f61b8fcfcc7f29d8e3257112472f28e870f20c0dca6a83367e55dfa007,
2593-byte references
SHAab07b7a3b972bd4c9d6094df32ced2acd6f25d16657758b5eb8132808555bea1,
and engine236b9c95ed2ac6e903e6cd173d11e600c5775f723f0582ee02b203778028fecb.
No cache header/key/checksum was rewritten. Eight genuine prior-engine generations
now supply104 migration checks. Current engine22 retains schema8/reference7;
no new instruction record shape was serialized in this task.

Final current-source gates pass: Debug99/99 (45.29s), Release99/99 (27.73s),
desktop Debug113/113 (130.69s), with the desktop suite alone after all other
builds/tests ended. Logs: `out/arm-task2-accept-{debug,release,desktop-idle}.log`.
Three fresh scalar-oracle reports each pass27 projections/nine identities with
zero mismatches (`out/arm-task2-oracle-report-audit.json`). No ARM input was
executed. All6093 preserved records in eight captures and the two accepted
installations retain their hashes (`out/arm-task2-preservation-audit.json`).
No accepted installation was overwritten, no commits/index edits occurred and
no agent was dispatched. All build/test/app processes were terminal afterward.

This closes Task2's integration checkpoint, not the processor stage or full
objective. A32/T32 decoding, predicate/interworking contexts, remaining relocation
families, native editor workflows and final independent delivery/review remain
Tasks3–7. Before the next semantic or wire advance, capture genuine engine22
A64 typed facts/relocations/project with matching current SDK/runtime/source in a
NEW prefix. Preserve the actual A64 ELF object cache, not only another x86
baseline, so the next schema migration exercises the new context/register/packed
operand forms. Existing captures and accepted bundles stay immutable.

Task3 phaseA adds the original A32 control decoder: B/BL/BX/BLX, architectural
NOP, BKPT and SVC. The public `decode_a32` and context dispatcher preserve the
source word, all fourteen ordinary predicates, NZCV read dependency, PC+8
branch targets, typed PC+4 link addresses, exchange behavior and return mode.
BLX immediate retains its H bit and unconditional semantics. Indirect targets
remain unavailable; unimplemented/PC-register exchange forms stay unsupported.
Literal tests cover alignment, truncation, 32-bit target overflow and context
guards (272 checks). No ARM input is executed.

`ArmInstructionInfo` is appended to the shared instruction model. Derived
schema9 serializes bounded control metadata ahead of instruction bytes and
checks it against canonical decoding; engine23 distinguishes these semantics.
Standalone references remain wire7/cache8 because their expression shape has
not changed. The genuine engine22 A64 capture was produced before this advance
with matching SDK/runtime/source and promoted byte-for-byte. Its compatibility
test proves readonly recomputation from embedded input while preserving UUID,
annotations, revisions and history, without rewriting the old cache row.

Pure decoder capability is distinct from automatic flow support. A new A32
image containing BXNE LR exposed an unsafe boundary: automatic analysis treated
it as an ordinary return. The regression failed before the fix; explicit
reachable/function/incremental guards now reject automatic A32 analysis while
`decode_at` remains available. Loading, mixed-state flow and predicate-aware
continuations remain Task4; A32 data operands and Thumb/IT decoding remain
Task3 phasesB/C.

The test-only compiler oracle compares fifteen A32 control word/text projections
with pinned LLVM23.1.3. It records all commands and nine file identities. ARM
uses its supported disassembler options and strips LLVM's `@` annotations;
A64 keeps its own `no-aliases` option. These are unlinked object comparisons:
R_ARM_CALL relocation placeholders describe raw encoded operands, not resolved
linked call targets. Literal decoder tests independently cover H-bit semantics.
The changed-branch-target negative remains enforced. The A64 oracle still
checks27 projections with its three documented exact aliases.

Architectural references: [Arm's branch and call explanation](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/branch-and-call-sequences-explained)
and the [official A32/T32 instruction reference](https://documentation-service.arm.com/static/61c04ba12183326f217711e0).
These inform the original implementation; production engines do not link LLVM
or execute the input.

PhaseA final revised-source gates pass: Debug102/102 (42.93s), Release102/102
(29.41s), desktop Debug116/116 (111.89s). Desktop tests ran alone after all
build/test/app processes were terminal. Authoritative logs are
`out/arm-task3-phaseA-accept-{debug,release,desktop-idle}.log`; earlier logs
precede the automatic-analysis boundary fix. Six fresh oracle reports each
retain nine matching identities, with27 A64 or15 A32 projections and zero
mismatches (`out/arm-task3-phaseA-oracle-report-audit.json`). The preservation
audit verified6763 records across nine genuine captures and the two accepted
installations with zero mismatches. No accepted installation was replaced.

This closes only phaseA of Task3. Before advancing engine23 semantics or cache
shapes again, produce a new genuine23 capture with matching runtime/SDK/source.
Task3 data operands/Thumb, Tasks4-7 and the full application goal remain open.

Task3 phaseB implements the sixteen basic A32 data-processing operations plus
single load/store and multiple-register transfers. Appended operand variants
retain barrel-shift kind/amount/register, register masks, and ARM memory offset,
add/subtract, pre/post indexing, writeback, width, sign extension and checked
PC+8 literal addresses. Register-controlled logical flag updates retain the
known NZ write mask with an explicit unknown C-update state; arithmetic updates
record all NZCV writes. RRX and carry arithmetic retain their input dependency.
PC writes use the Armv7 exchange contract; loaded or computed values remain
unresolved. Conditional effects retain predicate metadata. Automatic A32 flow
analysis remains guarded until Task4.

Literal tests pass113 ALU checks and55 memory/register-list checks, alongside
the272 existing controls. Disabled exception/status/multiply/movwide/doubleword,
unprivileged, base-overlap and user-bank forms remain explicit unsupported
results. This is scalar-subset support, not complete A32 ISA coverage. Stores
using PC do not claim a concrete PCStoreValue.

The shared bounded ARM operand codec now supports source-canonical instruction
encoding and structural reference expressions. Actual derived schema9 advances
to10, engine23 to24, standalone reference payload7 to8, and database reference
cache8 to9. Standalone7 remains readable with its original key/identities; a
checksum-valid7 payload carrying the new expression tag rejects. Operand tests
reject altered shifts, memory addressing, register masks and flag effects
against the original source word. These are low-level encoding checks, not
automatic A32 analysis or cache-adoption claims.

Before this advance, a fresh engine23/schema9/ref7 A64 capture was produced with
matched installed SDK/runtime/source in `out/arm-cache-v9-v23-capture` (682
sealed records). Its real984-byte compiler object yielded5459 HXDC bytes,
1669 reference bytes, two functions/seven instructions/six owned relocation
references, and actual relocated Follow plus a user annotation. Five promoted
fixtures retain every original byte. The compatibility suite now checks both
genuine22 and23 caches (32 assertions), including readonly embedded-input
recomputation, unchanged old rows, UUID, annotations, revisions and history.

The expanded independent corpus compares43 A32 scalar word/text projections,
in addition to15 controls and27 A64 projections. Nine exact observed A32
spelling differences cover signed MOV immediates, MOV-shift aliases, stack
aliases and omitted IA spelling. They are listed explicitly in the test
normalizer. A register-controlled shift is never normalized into a different
register number; that mutation and changed branch targets must reject. No ARM
input executes, and unlinked relocation operands are not claimed as linked
targets. [Arm's architectural PC-write pseudocode](https://documentation-service.arm.com/static/5f8db1f7f86e16515cdba551)
and [multiple-transfer guide](https://support.arm.com/documentation/den0013/0400/ARM-Thumb-Unified-Assembly-Language-Instructions/Memory-instructions/Multiple-transfers)
provide primary architectural references.

PhaseB final gates pass: Debug106/106 (71.64s), Release106/106 (66.97s), desktop
Debug120/120 (105.91s), with desktop tests alone after all other builds/tests
ended. Logs: `out/arm-task3-phaseB-accept-{debug,release,desktop-idle}.log`.
Nine fresh oracle reports cover255 projections and81 matching file identities,
with zero mismatches (`out/arm-task3-phaseB-oracle-report-audit.json`). All7445
records in ten genuine captures and both accepted installations retain their
hashes (`out/arm-task3-phaseB-preservation-audit.json`). No accepted installation
was overwritten. All build/test/app processes were terminal afterward.

This closes phaseB only. Before the next semantic/wire advance, preserve a
genuine engine24/schema10/ref8 capture with matching SDK/runtime/source in a new
prefix. Thumb/IT decoding, state-aware analysis/loading/commands, remaining ARM
relocations, native ARM workflows, final delivery/review and the full application
objective remain unfinished.

Task3 phaseC adds the original Thumb scalar decoder with explicit dynamic IT state.
Unknown, known outside IT and active IT are distinct inputs. The shared dispatcher
uses unknown state; decode_thumb accepts caller-supplied ThumbITState. Isolated
implicit-S encodings do not invent predicate or flag-write facts. Known IT state
suppresses implicit flag writes, retains then/else predicates and advances exactly
to the block end. Nested/invalid IT and early control transfers reject; BKPT stays
unconditional. The decoder preserves original halfwords, validates two/four-byte
framing and never treats an incomplete wide prefix as a narrow instruction.

The supported initial subset covers narrow ALU/shift/carry/MUL/high-register,
load/store/sign-extension/literal/SP/register-list forms, narrow conditional and
unconditional branches/CBZ/CBNZ/BX/BLX, and wide B/Bcond/BL/BLX branches. Thumb literal
and ADR addresses use aligned PC+4. Link addresses remain physical coordinates
with Thumb return state stored separately. Thumb MOV PC stays Thumb; loaded PC
values can interwork. Remaining wide data/memory, system and other ISA families
are explicitly partial. No automatic A32/Thumb analysis is enabled in this phase.

Canonical low-level instruction encoding now uses the recorded incoming IT state
and compares the full decoded record, including outgoing state and flag effects.
This proves self-consistency, not source provenance. Task4 must establish actual
mode/IT roots and prefix chains before adoption; self-consistent serialized IT
bits are insufficient. The existing automatic-flow guard remains in place.
Literal decoder tests pass1468 assertions, including every legal IT mask sequence,
wide S/J sign limits, truncated boundaries, mode/return state and unknown-state
cases. A new four-failure RED exposed shared-helper immediate widths leaking the
A32 rotate-field width into Thumb: corrected fields retain3/7/8 bits and implicit
NEG zero has no invented encoded field.

ThumbRelativeOperand is distinct from the A32 relative form: equal packed-field
counts can have different scaling/range rules. Instruction variant9/reference
expression7 retains Thumb widths6/8/11/20/23/24 with precise bounds and alignment;
the existing A32 halfword-misalignment negative remains enforced. This actual wire
shape change advances derived10 to11, engine24 to25, reference payload8 to9 and
reference DB cache9 to10. Standalone7/8 remains readable with original identities,
but checksum-valid old payloads introducing the new tag reject.

Before this advance, engine24 was captured once with freshly installed matched
SDK/runtime/source in out/arm-cache-v10-v24-capture (694 sealed files). Its actual
A64 ELF object/project produced5459 HXDC bytes and1669 reference bytes, with source-
bound Follow and annotation; five fixtures were promoted byte-for-byte. The three-
generation22/23/24 migration suite passes48 assertions preserving readonly old
cache rows, UUID, annotation, revisions and history with embedded input. Operand
codec/reference tests pass68 assertions; source-window/automatic-flow barriers
pass65 assertions. These counts describe the checked initial subset.

A separate Thumb compiler probe carries explicit IT state through the original
75-instruction corpus and checks every narrow/wide length. The oracle compares
actual little-endian halfword order and disassembler text, normalizes the .w
encoding-width spelling and projects LLVM ADR offsets to aligned PC+4 targets.
The source uses actual local branch labels; the CBNZ target is far enough forward
to produce CBNZ rather than an assembler-relaxed NOP. Decoder formatting preserves
preferred Thumb shift/two-operand/stack/MUL syntax. Existing27 A64 and15+43 A32
projections remain checked. All comparisons concern unlinked object words; no
linked relocation target, ARM execution or CPU-equivalence claim is made.

PhaseC final gates pass: Debug108/108 (83.72s), Release108/108 (75.03s), desktop
Debug122/122 (121.29s), with desktop tests alone after all other builds/tests
ended. Logs: out/arm-task3-phaseC-accept-{debug,release,desktop-idle}.log. Twelve
fresh oracle reports cover480 projections and108 matching file identities with
zero mismatches (out/arm-task3-phaseC-oracle-report-audit.json). All8139 records
in eleven genuine captures and both accepted installations retain their hashes
(out/arm-task3-phaseC-preservation-audit.json). No accepted installation was
replaced. All build/test/app processes were terminal afterward.

This closes Task3's initial decoding subset. Task4 source-bound modes/IT and
transactional overrides, Task5 remaining ARM relocations, Task6 native workflows
and Task7 delivery/review remain open, along with remaining ISA families and the
full application objective. Preserve a genuine25/schema11/ref9 capture with
matching runtime/SDK/source before the next semantic advance.

## Task4 image-context dependency phase

The genuine engine25 capture now exists under `out/arm-cache-v11-v25-capture`:
707 sealed files, freshly matched SDK/runtime/source, original A64 ELF input,
project, derived schema11 and reference9 payloads. Exact original bytes are
promoted as the `tests/fixtures/*arm_v25*` fixtures. Migration tests now cover
actual22/23/24/25 producers. A prior source key misses; substituting the current
database key still rejects the actual envelope (incompatible old schema, or
corrupt source-key mismatch for unchanged schema11). Readonly recomputation
preserves project/user/history and leaves the old database payload unchanged.

Engine26 adds the image SDK's immutable ARM code-context profile. Sorted disjoint
ranges and roots retain typed source identities and optional original file
evidence. A32/Thumb alignment, executable initialized backing, evidence extents,
domain compatibility and record/memory budgets are checked. Conflict origins
remain inspectable; context lookup reports their conflict. Data, unknown and
uncovered addresses have no code window. Even adjacent same-mode declarations
retain a hard boundary. Existing encryption/exclusion policies still apply, and
ordinary data reads remain available. Mapping fingerprints include all range,
source and root claims; absent profiles retain the exact pre-change identity.

The first focused run of `arm_context` failed because Image could not represent
these ranges. After implementation it passes71 checks, and the four-generation
`arm_cache` test passes64 checks. Logs are under `out/arm-task4-context-*`.
The final preservation audit verifies8846 records across twelve genuine captures
and both accepted installations with zero mismatches. All consumers were rebuilt:
Debug109/109 (117.32s), Release109/109 (89.75s), desktop-alone123/123 (139.94s).
Twelve fresh oracle reports cover480 projections and108 matching file identities,
with zero mismatches. Logs: `out/arm-task4-context-{debug,release,desktop-idle}.log`;
audits: `out/arm-task4-context-{preservation,oracle-report}-audit.json`.

This is the image-context contract only. ELF mapping/symbol meaning, platform/raw
declarations, durable overrides, IT chains, stateful flow, computed-PC targets and
packed ARM relocation barriers still require integration. Generic Image shape
validation does not prove a file record's contents. The automatic ARM guard
remains in place. Derived schema11/reference9/database-reference10 are unchanged.

## Task4 durable raw declarations

Engine26 is preserved in `out/arm-cache-v11-v26-capture`:714 sealed records with
matching freshly installed SDK/runtime/source, actual A64 project/cache/reference
payloads, and all eight loaded runtime module paths checked against the capture's
own bin directory. Five promoted fixtures retain the exact original bytes.

Engine27 adds the bounded public `ArmRawProfile` loader APIs and worker-resolved
ARM profile opening intent. Both CLI opening parsers accept `--arm-profile`.
The canonical declaration format is:

```text
hexlab-arm-profile 1
base 7 0x1000
permissions r-x
entry 0x1008 thumb-clear
ranges 3
range 0x1000 0x8 a32
range 0x1008 0x4 thumb
range 0x100c 0x4 data
```

Coordinates are physical offsets in the declared domain, without an encoded
Thumb bit. Entry may be `none`, or an offset with `a32`, `thumb-clear` or
`thumb-unknown`. Range kinds are `a32`, `thumb`, `data` and `unknown`; gaps remain
unknown. Permissions have read/write/execute positions, each its letter or `-`.
Code ranges need executable permission, aligned complete units and initialized
source backing. Entry state must agree with its range. An empty profile does not
infer an entry from bytes. Overlapping or contradictory raw declarations fail.

Human text accepts UTF8 comments, BOM, whitespace and unsigned hexadecimal/decimal
numbers. Canonical output sorts ranges and uses lowercase hexadecimal coordinates.
Text is limited to1MiB, lines4096 bytes and ranges16384; parser, formatter,
validator and file reader accept cancellation. Durable recipe3/kind6 embeds only
canonical text. Raw declaration origins use namespace0 with canonical1-based
range ordinals; the explicit entry uses record0. No ELF evidence is invented.

The literal recipe RED failed on engine26's unknown format, and a matching26 CLI
RED rejected `--arm-profile`. Focused GREEN passes207 profile/project assertions,
80 actual22/23/24/25/26 migration checks and9 CLI checks. The project tests prove
rename, patch, undo/redo, Save As and readonly reopen after removal of both owned
external input/profile files. The CLI checks cover both parsers, incompatible
options, preserved input bytes and source/profile-missing readonly inspection.
The initial project assertion incorrectly expected `file-only`; existing engine
semantics reserve that status for invalid mappings. The corrected test requires
incomplete analysis, no function/reference/basis facts, a reason and valid mapping.
No production status behavior was changed to satisfy that draft assumption.

All consumers were rebuilt and full gates pass: Debug111/111 (147.48s),
Release111/111 (96.34s), desktop-alone125/125 (125.49s). Logs are
`out/arm-task4-raw-{debug,release,desktop-idle}.log`. The final preservation audit
verifies9560 records across thirteen genuine captures and both accepted installs
with zero mismatches. Twelve fresh compiler reports verify480 projections and
108 file identities. Three fresh CLI reports verify27 commands, the literal raw
input hash and27 runtime file identities. CLI file identities are not a loaded-
module path proof; the actual26 capture separately verifies its loaded paths.
Audit artifacts are `out/arm-task4-raw-{preservation,oracle-report,cli-report}-audit.json`.
Automatic ARM flow remains guarded; source-bound IT/predication, ELF declarations,
transactional mode overrides, computed-PC/relocation barriers and native workflows
remain required Task4/5/6 work. Derived11/reference9/database-reference10 remain.

## ELF32 ARM mapping declarations

The loader now turns executable-section `$a`, `$t` (including dotted suffixes),
and `$d` mapping symbols into bounded source-backed A32, Thumb and data intervals.
Each interval retains the original symbol-table section, record index and exact
record bytes. Odd-valued ARM `STT_FUNC` symbols preserve their tagged raw value
while resolving to an even physical address; the function record supplies a
Thumb root with a known-clear IT state. A function state that contradicts its
mapping interval converts that interval to an explicit conflict with both source
records retained. Same-address mapping symbols with different kinds likewise
produce a conflict interval. Data intervals have no decoder context.

The literal ELF32/ARM relocatable fixture covers `$a` to suffixed `$t` to `$d`,
odd Thumb function canonicalization, root IT provenance and exact source record
identity. `elf_symbols` passes the focused Debug test. At that checkpoint,
automatic analysis remained guarded; mixed-state reachable traversal is now
covered separately below. This loader integration alone does not close Task4.

## Mixed A32/Thumb reachable analysis

Reachable analysis now opts into ARM only when an image contains explicit
source-backed A32/Thumb ranges. Roots take their execution mode from the image
profile; a Thumb root is analyzable only when it carries the profile's
known-clear IT claim. Decoded Thumb instructions propagate ITSTATE along
fallthrough, and a statically resolved branch/call is queued only when its
decoded target mode agrees with `Image::context_at` at the destination. This
covers declared A32-to-Thumb and Thumb-to-A32 direct interworking edges while
keeping addresses physical and untagged.

Traversal stops conservatively on unknown Thumb IT state, data/conflict or
unmapped targets, target-state disagreement, state-changing fallthrough, and
instructions that write PC without a modeled flow edge. If one Thumb address is
reached with incompatible IT states, that path stops as incomplete rather than
decoding the same bytes under two predicates. Indirect BX/BLX remains
unresolved because register values are not evaluated. The focused `analysis`
test covers mixed A32/Thumb call traversal, known-clear roots, unknown IT-state
rejection, and contradictory target metadata.

## Partial APSR writes from data-processing instructions

Data-processing instructions that update only part of NZCV now record the old
flags register as an input dependency. Logical operations can write N/Z and,
depending on the immediate or shifted operand, C while preserving C or V. The
typed `flags_written` mask describes the subset replaced; `register_reads`
retains the old APSR value needed for untouched bits. Thumb narrow operations
share this behavior through the A32 semantic lowering, while instructions in
an IT block continue to suppress implicit flag writes. `arm32_data` and
`thumb_decoder` tests cover unrotated and rotated MOVS plus the narrow Thumb
MOVS case. The decompiler now emits symbolic logical N/Z formulas, shifter
carry output (including the old-C input for variable shifts), and preserved V;
predicated flag formulas select the old flag value when the condition is false.
Its A32 condition renderer expands all fourteen condition codes into N/Z/C/V
boolean expressions. These formulas remain symbolic helpers rather than a
concrete runtime NZCV evaluator or independent flag-bit SSA.

## Immediate A32 ALU writes to PC

The A32 decoder and profile-backed reachable traversal resolve a bounded set of
data-processing writes to PC when every source value is encoded in the instruction:
`MOV pc, #imm`, `MVN pc, #imm`, and `ADD`/`SUB`/`RSB pc, pc, #imm`. The architectural
A32 source PC is instruction address plus eight. `ALUWritePC` canonicalizes bit zero
as Thumb state and clears it from the physical address; with bit zero clear, the
physical target is word-aligned and state is A32. The state is carried in
`ArmInstructionInfo::target_mode`, while `direct_target` remains an untagged physical
`Address`.

Conditionally executed ALU writes to PC use conditional-branch flow so analysis keeps
both the NZCV-guarded target edge and the sequential continuation. A target is withheld
when its arithmetic underflows/overflows the 32-bit address domain. Reachable analysis
and function recovery also resolve A32 `LDR pc, [pc, #±imm]` when its literal slot is
initialized, little-endian, and has no overlapping ELF/Mach-O relocation. The loaded
value's low bit selects Thumb versus A32; A32 destinations are word-aligned and Thumb
destinations are halfword-aligned. The physical target must have a matching
source-backed A32/Thumb profile before analysis follows it, so a literal may bridge
declared data and mixed-state code ranges. Register-derived values, register-offset
loads, other PC loads, and relocated literal slots remain unresolved; this does not add
register-value propagation or interpret relocation-written pointer values. The focused
`arm32_decoder` and `analysis` tests cover literal ALU target/state facts, predication,
unresolved registers, overflow/underflow, and an A32-to-Thumb traversal across a
declared data range.

## Predicate-aware A32 returns and function flow

A32 function recovery follows decoded targets only when their declared target mode matches the image context. Conditional A32 returns retain a return stop and a guarded sequential continuation, so function ownership does not treat a predicated return as unconditional. Reachable analysis likewise explores the return and the condition-false continuation. A32 fallthrough cannot cross a declared mode boundary; mode changes require an explicit transfer whose destination agrees with the source-backed profile.

Conditionally executed A32 traps preserve the same two outcomes. For example,
`svcne #0x123` retains a trap stop for the NZCV-true path and a conditional-false
edge to the next A32 instruction. Reachable analysis explores that continuation,
and function recovery partitions it into the successor block while retaining the
trap stop at the SVC. `tests/fixtures/arm32_control.s` supplies this encoding to
the pinned assembler/decoder oracle; the `analysis` and `functions` tests check
the resulting graph behavior. Unconditional traps and Thumb IT trap legality are
unchanged.

Thumb function recovery now requires a profile-backed root with a source-backed
known-clear ITSTATE. Traversal carries incoming ITSTATE on CFG work edges and
continues the state produced by an instruction along fallthrough and branch
paths. The current function graph still stores one instruction fact per physical
address, so a join reached with different ITSTATE values invalidates that fact,
reports both states in an `unsupported` function stop, and leaves the function
incomplete rather than assigning ownership using either predicate. Direct ARM
targets must agree with the declared destination mode, and sequential A32 or
Thumb flow stops at a declared mode boundary. These constraints keep mixed-mode
ownership conservative; they do not provide a graph with multiple state-qualified
nodes at one physical address or complete ARM predication and ISA coverage.
Focused function tests cover a conflicting Thumb ITSTATE join and an adjacent
A32-to-Thumb region that remains a separate function boundary.

## Thumb-2 variable rotate

The wide `ROR{S}.W Rd, Rn, Rm` form now decodes for general-purpose registers
r0-r12. The normalized instruction retains the rotated source and amount
register separately, plus exact source/destination/optional APSR effects. Its
existing MOV-with-shift formatter prints ROR syntax, and the decompiler's
shared ARM scalar path represents the value as a register-controlled rotate.
SP/PC operands remain outside this profile-free decoder slice. Immediate ROR,
other Thumb-2 register-controlled shifts, and broader scalar coverage remain
separate gaps.

