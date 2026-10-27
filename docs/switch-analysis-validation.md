# Switch table analysis validation

The analysis library exposes `analyze_switch_tables` for recovered functions.
For x86, it identifies indirect `JMP` instructions whose memory operand
contains a statically resolved table base and a scaled index. On x86-64 it
also recognizes the adjacent RIP-relative `LEA base, table` followed by
`JMP [base + selector*8]` pattern used by MSVC, recovering absolute pointer
entries without general register-value propagation. It reads at most
4096 contiguous entries. Entries are either mode-width absolute pointers or,
for the recognized x86-64 `LEA`/`MOVSXD`/`ADD`/indirect-`JMP` sequence, signed
32-bit offsets indexed at four-byte scale from the RIP-resolved table base. It accepts an entry only when its target is
file-backed executable image data that decodes as an instruction in the
dispatch mode.

The x86-64 PIC relative-table recognizer also accepts an earlier same-block
table-base definition:
`LEA Rbase, [RIP+table]; ...; MOVSXD Roff, [Rbase+Rindex*4]; ADD Roff, Rbase; JMP Roff`.
The load/add/indirect-jump tail remains contiguous. To carry the LEA value
forward, the nearest reaching write to `Rbase` must be that resolved
RIP-relative LEA; an unknown instruction fact, call, control-flow change, or
intervening write rejects the pattern. This handles compiler scheduling that
places harmless setup instructions between the table LEA and dispatch without
adding general register propagation. A guard may bound the table only when
its compare/branch falls through directly to the recognized LEA and the
selector remains unchanged between that LEA and the indexed load. The backward
base-definition search is capped at 4096 instruction facts. Otherwise the
existing verified-prefix and 4096-entry limit rules apply.

For x86, a signed nonzero interval can bound a normalized selector only for
this exact local sequence: `CMP selector, low; JL default; CMP selector,
high; JG default; SUB selector, low; ... indexed dispatch`. Both comparisons
must use the same register width and selector, and both branches must name the
same decodable default target. Bounds must be nonnegative signed immediates,
`high` must be at least `low`, and the computed inclusive span
`high - low + 1` must be between 1 and 4096. The table index must be the same
register after the in-place subtraction. On x86-64 only, a 32-bit compared and
subtracted register may feed a 64-bit table index when it is the same physical
GPR, because the 32-bit write zero-extends it. The shared predecessor graph
requires the upper compare to follow the lower in-range edge and proves that
the normalized value reaches dispatch without a bypass, ambiguous entry, or
intervening selector write. Unknown or incomplete graph evidence does not
publish a count or default; normal verified-prefix scanning remains available.
Other conditions, negative bounds, out-of-place subtraction, and general
selector arithmetic do not establish this proof.

For AArch64 it recognizes a contiguous `ADR` / indexed `LDR` / `BR` form for nearby pointer tables, as well as the `ADRP` / `ADD` / indexed `LDR` /
`BR` dispatch where `ADRP` supplies a resolved page address, `ADD` uses the
same register and a low immediate to form the table base, and `LDR` loads an absolute 64-bit pointer from `[base + selector, LSL #3]`. The `ADR` form does not propagate its base across intervening instructions. The base, selector,
and loaded target registers must be distinct, the source sequence must be
adjacent in one recovered block, and the table must be in readable,
file-backed image data. Each candidate pointer is accepted only if it decodes
as an executable AArch64 instruction. Unreadable or invalid entries retain
the verified prefix and mark it partial. This recognizer consumes addresses
already resolved by instruction decoding; unresolved ADRP/ADD pairs are only
accepted through the exact ELF relocatable-object pair described below.

AArch64 signed-offset tables are recognized for either exact contiguous
`ADRP Xbase` / `ADD Xbase, Xbase, #low` / `LDR Woff, [Xbase, Wselector,
UXTW #2]` / `SBFM Xoff, Xoff, #0, #31` / `ADD Xoff, Xbase, Xoff` / `BR Xoff`
form, or `ADRP Xbase` / `ADD Xbase, Xbase, #low` / `LDRSW Xoff, [Xbase,
Wselector, UXTW #2]` / `ADD Xtarget, Xbase, Xoff` / `BR Xtarget`. The explicit
`SBFM` encoding must be the exact sign-extension operation (the `SXTW` alias);
the `LDRSW` form uses the native signed-word load and directly writes the
64-bit offset register. In both forms each 32-bit table displacement is
signed and is added to the resolved table base. The `LDRSW` recognizer requires
the indexed memory operand to have a 64-bit base, 32-bit UXTW selector shifted
by two, zero displacement, and a 32-bit signed load. Both five/six-instruction
sequences must be adjacent in the same recovered block, use one A64 context,
preserve the stated register relationships, and address four-byte entries.
The table must be readable and file-backed, and each table-relative target
must decode in executable AArch64 bytes. Invalid entries preserve the verified
prefix and mark it partial. For ELF relocatable objects,
the form can recover an otherwise unresolved table base from an exact
`R_AARCH64_ADR_PREL_PG_HI21` (or its `_NC` variant) /
`R_AARCH64_ADD_ABS_LO12_NC` pair. Both
explicit-addend records must refer to the same validated symbol-table namespace,
symbol index, and addend; the symbol must be a defined local symbol in a mapped
section. Missing, duplicate, overlapping, mismatched, or non-local relocation
evidence leaves the site unrecognized. Relocated 32-bit entries are resolved
through their exact data-slot relocation and retain relocation provenance. The
address and each destination still pass the same checked image bounds and
executable-instruction checks as byte-resolved tables. The path does not
resolve global/preemptible symbols, instruction relocations outside this exact
pair, or REL implicit addends. A bound is recognized when
`SUBS WZR/XZR, selector, #limit` (the `CMP` alias) and `B.HS default` or
`B.HI default` immediately precede the setup sequence. `B.HS` proves `limit`
cases; `B.HI` proves `limit + 1`. The selector width must match the table
index, the count must be between 1 and 4096, the default must decode in
executable file-backed AArch64 bytes, and the same incoming-edge checks used
by x86 guards must hold. Shifted compare immediates, other conditions,
non-adjacent pairs, or ambiguous guard candidates remain unproven. A proven
bound limits reads; otherwise scanning stops at the first invalid entry or
the 4096-entry limit, and an unbounded table reaching that limit is partial.
As with the absolute form, ADRP/ADD relocation records are not applied when
the decoder could not resolve the page or low immediate.

A second AArch64 signed-offset form uses a distinct code base:
`ADR Xtable, table` (or exact `ADRP`/unshifted `ADD` table setup),
`LDRSW Xoffset, [Xtable, Wselector, UXTW #2]`, `ADR Xcode, code_base`,
`ADD Xtarget, Xcode, Xoffset`, `BR Xtarget`. The five or six instructions
must be contiguous in one recovered block, with one A64 context and the
specified register relationships. The final `ADD` must be an unshifted
64-bit register addition. Each signed 32-bit entry is added to the resolved
`ADR` code base, which is reported separately from the table address as
`target_base`. Table bytes and decoded targets must be file-backed; targets
must decode as executable A64 instructions. Exact data-slot relocations can
provide case targets, while unresolved, authenticated, or runtime-bound
fixups end the verified prefix without using raw bytes. The exact local ELF
`ADRP`/`ADD` relocation pair described above can supply this form's table
base. Unknown setup relocations, other index extensions or shifts, an
independent code base formed by another instruction sequence, and intervening
instructions remain unsupported. A proven unsigned selector guard bounds
the case count; otherwise scanning stops at the first unsupported entry or
at 4096 entries. Partial sites report the scan failure through
`incomplete_reason`.

Thumb-2 `TBB [pc, Rm]` and `TBH [pc, Rm, LSL #1]` are decoded as indirect
control transfers and recovered as byte/halfword tables based immediately
after the 32-bit dispatch instruction. Each unsigned table entry scales by
two from the Thumb PC value at instruction address plus four. The recognizer
requires the explicit PC base, a valid 32-bit index register, a readable
file-backed table, and executable decoded Thumb destinations. A contiguous
`CMP Rm, #limit` followed by `BHS` proves `limit` entries; `BHI` proves
`limit + 1`, subject to the same local-edge validation and 4096-entry cap as
other tables. Otherwise the verified prefix is retained and becomes partial
when an invalid entry or scan cap is reached. `Rn=SP`, `Rm=SP` or `Rm=PC`,
IT-block placement before the last slot, non-PC table bases, and other
compiler-generated sequences are unsupported. Encoding, register constraints,
entry scaling, and PC behavior follow the [Armv8-M Architecture Reference
Manual, TBB/TBH](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf).

Each result preserves the dispatch address, table address, selector register,
scale, entry encoding (`absolute_pointer`, `signed_offset_from_table`,
`signed_offset_from_target_base`, or `thumb_scaled_pc_relative`), and
table-order case index. An unreadable or invalid entry ends the
recovered prefix and marks it partial. Cancellation is checked during block,
instruction, and table traversal. A contiguous `CMP selector, immediate` followed
by `JA default` proves `immediate + 1` cases; `JAE default` proves `immediate`
cases. The branch may fall through directly to the indexed jump or the start
of its recognized setup sequence. It may also reach setup through the bounded
CFG proof described below. The compare register must match the
selector including width, and the immediate must have valid widths, be
nonnegative, and produce between 1 and 4096 cases. The default must decode in
file-backed executable bytes in the dispatch mode. Known alternate incoming
edges, contradictory guards, changed contexts, nonadjacent sequences and
unsupported branch conditions cannot establish a bound. This recognizes
unsigned upper bounds. It also recognizes the exact contiguous x86 signed
nonnegative range shape `CMP selector, 0; JL default; CMP selector, max;
JG default; setup`. Both compares must use the exact selector register and
width, both branches must share the same decoded default target, and `max` must
be nonnegative and small enough that checked `max + 1` is within the 4096-entry
cap. The known CFG must show the lower compare is the lower branch's sole
predecessor and the lower branch's in-range fallthrough is the upper compare's
sole predecessor. The existing acyclic selector-preserving proof must then
show every known path from the upper in-range edge to setup. The default must
decode in executable file-backed bytes. Any missing, ambiguous, or alternate
incoming edge leaves the count unproven and keeps verified-prefix scanning.
Other signed conditions, non-contiguous guard pairs, and non-x86 signed range
forms remain unsupported.

Guard-derived `case_count` and `default_target` evidence is emitted only for a
complete function record and complete function snapshot. When recovery stopped
early or omitted blocks under a budget, an unseen block could enter table setup
without passing the guard; the analyzer therefore leaves the bound unproven,
scans only the bounded table prefix, and reports the site as partial. This
applies uniformly to x86, AArch64, and Thumb guard proofs.

Signed x86 switches over a nonzero interval support one exact normalized form:
`CMP selector, low; JL default; CMP selector, high; JG default; SUB selector,
low; indexed dispatch`. The two branches must share a decoded default, the
compare register and width must agree, `0 <= low <= high`, and the in-place
SUB must subtract exactly `low`. The case count is `high - low + 1` and must be
within the existing 4096-case cap. In x86-64, the comparisons and SUB may use
the 32-bit register while the indexed memory operand uses its paired 64-bit
register; the architectural zero-extension of the 32-bit write is required.
The bounded CFG proof requires unique known predecessors for both guard pairs,
then proves the in-range upper-guard edge reaches the normalization and
dispatch without selector writes, alternate entries, bypasses, or cycles.
Negative bounds, different branch conditions/defaults, non-in-place or
different-constant normalization, alias/cross-width forms other than this
32-to-64 zero-extension, and other non-x86 signed ranges remain unproven.
Failed proofs retain the existing verified-prefix scan.

AArch64 also accepts the exact signed immediate form
`SUBS XZR, Xn, #low; B.LT default; SUBS XZR, Xn, #high; B.GT default; ...`.
Both guards must compare the same 32- or 64-bit register, use the same decoded
default target, and prove `0 <= low <= high` in the signed domain. A zero lower
bound uses the original selector directly. A nonzero lower bound requires an
adjacent in-place `SUB Xn, Xn, #low`, and the indexed dispatch must consume that
same register. Shifted and negative immediates, other branch conditions,
cross-width aliases, and non-adjacent normalization remain unsupported. The
existing complete-CFG predecessor and selector-preservation proof is applied
to the in-range edge through normalization and dispatch; incomplete evidence
continues to produce only the verified table prefix. This follows the same
range-driven approach as Ghidra's native jump-table recovery, which models
bounded value ranges and checks value equivalence while tracing guard inputs,
but HexLab intentionally accepts only these explicit typed instruction forms
([Ghidra `jumptable.cc`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc)).

`case_count` and `default_target` are optional evidence. For AArch64, the same
guard proof applies to both recognized table forms. A proven count limits
table reads even when later words resemble valid code pointers. An invalid
entry inside that count still marks the site partial and preserves only its
verified prefix. A proven single-case table is retained for both AArch64
absolute-pointer and signed-offset forms; unguarded tables need two verified
entries because a one-entry prefix alone is ambiguous. The pass does not infer source-language case labels,
arbitrary register-computed table bases, other signed ranges or selector normalization. During
function discovery, recovered destinations from statically resolved indexed
indirect jumps are traversed as CFG edges; a partial table retains an indirect
stop to avoid claiming that all arms were found. The pass rejects snapshots
above one million blocks or sixteen million decoded instruction facts and
checks cancellation during budget counting and guard-edge validation. The pass recognizes the
contiguous two-instruction `LEA`/indexed-`JMP` and four-instruction
`LEA`/`MOVSXD`/`ADD`/`JMP` sequences within one recovered basic block; it does
not propagate register values across other instructions or
recover other compiler sequences that load offsets and branch through registers.

`switch_analysis` covers an x86-64 absolute-pointer table, the MSVC-style
register-based absolute-pointer table and its recovered CFG targets, the compiler-style
RIP-relative signed-offset sequence, JA/JAE inclusive/exclusive bounds,
verified default arms, one-case tables, a guarded 300-case table, bounds through
4096 cases, invalid entries within
bounds, mismatched selector widths and contexts, negative/malformed immediates,
unsupported conditions, bypass edges, contradictory guards, invalid-table
termination, cancellation,
and traversal of recovered table destinations into function CFG. Existing
fixture coverage for AArch64 remains focused on absolute-pointer tables,
bounded invalid-entry prefixes, and rejection of unsupported entry scaling;
the explicit signed-offset sequence described above has not yet received a
literal fixture. Other register-based relative-table forms, provenance
persistence, and broader 16/32-bit fixtures remain follow-up work. The signed
offset recovery path recognizes the directly decoded register-offset `LDRSW`
form as well as the explicit `LDR`/`SBFM` sequence; other signed-load
addressing modes remain outside this decoder subset.

MIPS64 N64 switch recovery recognizes a same-basic-block register sequence
that constructs an absolute table base with `LUI`/`ORI` (or bounded
`DADDIU` adjustments), scales the selector by eight with `DSLL`, combines the
index and base with `DADDU`, loads an eight-byte target with `LD`, and dispatches
through `JR`. Each table word must resolve to an executable, decodable target;
relocation metadata is preserved where available. The scan is capped at 4096
entries. A same-block `SLTIU guard, selector, bound` followed by
`BEQ guard, $zero, default` proves the strict range `[0, bound)` for either
MIPS32 or MIPS64. This proof requires a decoded, side-effect-free fallthrough
delay-slot instruction and setup to begin immediately after that slot; the
bound must be in `[1, 4096]`. The default target must decode as an executable
instruction. Other MIPS delay-slot guard forms, delay-slot control flow,
unsupported base construction, signed-offset tables, and cross-block register
propagation remain unsupported.

The same constrained register-value analysis now recognizes the corresponding
MIPS32 O32 absolute-pointer form with a four-byte table entry:
`LUI`/`ORI` (and checked `ADDIU` adjustments), `SLL` by two, `ADDU`, `LW`,
and `JR`. It accepts only one straight-line block, exact 32-bit GPR operands,
a distinct nonzero selector/base/target, and file-backed table storage. Each
entry must resolve from its exact four-byte slot and decode as executable
MIPS32 code; ELF/Mach-O relocation rows are retained through the existing
slot resolver. The 4096-entry cap applies. Without the validated guard,
counts and defaults remain unknown and scanning is limited to a verified
prefix. Unsupported base construction, signed-offset tables, cross-block
values, and delay-slot control flow remain outside this recognizer. No test or
build was run for this extension; runtime recognition remains unverified.

PPC32 recognizes a straight-line indexed absolute-pointer form ending in
`LWZX target, tableBase, scaledIndex; MTCTR target; BCTR`. The index must come
from `MULLI scaledIndex, selector, 4` or the exact `RLWINM` `SLWI selector, 2`
mask form; the table base must come from decoded
`ADDIS`/`ADDI`/`ORI` immediate facts in the same block. Table entries are
four-byte pointers and each accepted destination must decode as executable
PPC32 code. Recovery requires an adjacent `CMPLI CRf, selector, bound` and
`BC` proof that branches to the default when CRf.LT is clear (BO=4, BI=4*f),
so fallthrough proves the exact unsigned range `[0,bound)`. A complete
dominance/flow proof must connect that guard's fallthrough to the table setup
and dispatch without alternate entries or selector writes. Bounds must be in
`[1,4096]`; recovery declines the site when the proof is absent. Instruction
immediates covered by relocations are left unresolved, and entry relocations
are resolved through the existing relocation-aware table reader. The scan
reads exactly the proven number of entries and preserves a partial prefix if
an entry is unreadable, unresolved, or invalid. PPC64, HA/LO
relocation-paired bases, other index scaling instructions, and cross-block
register propagation are not recognized by this variant.

For project users, `hexlab_cli project switches <project> --at va:<entry>`
prints deterministic JSON containing the dispatch/table addresses, selector,
scale, entry encoding, case indices and targets, optional `case_count` and `default_target`
(JSON `null` when unproven), and completeness flags. It returns exit code 3
when the function or a recovered table is incomplete.

Validated on Windows/MSVC Debug in a fresh `.codex-switch-guard-proof-build`:

```powershell
cmake -S . -B .codex-switch-guard-proof-build -G "Visual Studio 17 2022" -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=ON -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build .codex-switch-guard-proof-build --config Debug --target hexlab_switch_tests hexlab_function_tests hexlab_cli hexlab_fixture_generator hexlab_project_cli_oracle --parallel 4
ctest --test-dir .codex-switch-guard-proof-build -C Debug -R '^(switch_analysis|functions|project_cli)$' --output-on-failure
```

All three selected CTests passed for the earlier local-guard implementation.
`project_cli` checks both unknown (`null`) metadata and an exact
two-case/default-arm result after project creation and reopening. Indirect
incoming paths, cross-width selector proofs and broader compiler switch
lowering remain unsupported.
The earlier-LEA relative-table variant is source-compiled but currently has no
dedicated literal fixture, so runtime recognition remains unverified.


## Bounds across CFG edges

An unsigned compare/branch pair can now bound a recognized dispatch even when
its in-range fallthrough reaches table setup through several recovered blocks.
A bounded reverse instruction graph proves that every known incoming path to
setup passes the same in-range edge and leaves the exact selector register
unchanged. Straight-line connectors and acyclic diamonds are accepted; calls,
opaque facts, selector writes (including narrower aliases), context changes,
alternate function entries, roots without the guard, and cyclic reverse cones
reject the bound. A default arm that later rejoins setup is a bypass and is
rejected. The conditional branch must have only its adjacent compare as a known
predecessor, so a jump into the branch cannot reuse unrelated flags. Known
transfers into the middle of table setup are rejected as well.

The reverse graph is built at most once per `analyze_switch_tables` invocation
and reused across dispatch sites. It contains at most 100,000 instruction nodes
and 1,000,000 incoming edges. A shared 4,000,000-operation scan budget counts
all visited blocks, facts, function entries and explicit edges, including
snapshot records outside the current function. A separate shared 2,000,000
proof budget also accounts for per-node scratch initialization. Exhausting
either budget leaves the count/default unproven and retains the existing
bounded verified-prefix table scan. These are known-CFG proofs; arbitrary
unknown indirect entries and loop invariants are not inferred.

The Debug analysis target was source-built after this change. No tests were
added or run for the new cross-block proof, and runtime recognition remains
unverified. The function-engine fingerprint changed to invalidate older
derived analyses affected by the broader guard recognition.


## AArch64 ELF relocatable absolute-pointer tables

The contiguous absolute-pointer form now also resolves an unlinked ELF64
little-endian AArch64 table:

```text
ADRP Xbase, table
ADD  Xbase, Xbase, :lo12:table
LDR  Xtarget, [Xbase, Xselector, LSL #3]
BR   Xtarget
```

The setup must carry exactly one `R_AARCH64_ADR_PREL_PG_HI21` (275) or
`R_AARCH64_ADR_PREL_PG_HI21_NC` (276) relocation at `ADRP`, and exactly one
`R_AARCH64_ADD_ABS_LO12_NC` (277) relocation at `ADD`. Both must be explicit
RELA records with the same validated symbol-table namespace, symbol index and
addend. Only a defined local table symbol (NOTYPE, OBJECT or SECTION) with a
mapped section address is accepted. The exact table address is the symbol's
section-relative image address plus the checked signed addend; placeholder
instruction immediates never establish that address. The table can occupy a
separate section/address space from the dispatch, as usual for ET_REL rodata.

The four instructions must be adjacent, have one A64 context, use 64-bit
registers, and preserve distinct table-base, selector and loaded-target
registers. SP/ZR aliases, shifted low-12 ADD, index extensions, nonzero load
displacements and other pointer widths are rejected. Unknown or malformed
setup relocation evidence suppresses the form rather than falling back to
encoded placeholder bytes. The existing signed-offset forms also accept the
275/276 page variants under the same pair checks.

`SwitchSite::table_base_source` reports `elf_relocation_pair` when this pair
establishes the table. `table_base_relocation_rows` retains the two ELF row
indices in ADRP/ADD instruction order. The existing signed-offset recognizers
now retain the same setup provenance. These fields are separate from each
`SwitchCase`'s pointer-slot relocation source and rows: a relocated table base
does not claim that a raw table word was itself relocated. Table words still
use exact data-slot relocation resolution where present, and every resulting
case must decode in executable, file-backed A64 bytes. No guessed target is
emitted for an unresolved slot. Existing proven count/default handling and the
4096-entry scan cap apply unchanged.

This extends source recognition only. No tests were added or run, and no build
was run for this change; runtime recognition remains unverified. The setup
provenance is exposed by the analysis API; CLI serialization and durable
provenance persistence are not extended here. REL implicit addends,
preemptible/global symbols, GOT indirection, arbitrary address propagation and
other instruction relocation families remain unsupported.
