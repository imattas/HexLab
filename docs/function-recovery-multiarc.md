# Multi-architecture function recovery

Function recovery uses shared typed instruction facts for instruction length,
flow kind, direct targets, mode changes, and bounded ownership. Current slices
cover x86-16/32/64, AArch64, RV32, RV64 (including RV64C), NMOS 6502, MIPS32,
ARM A32, and Thumb. Roots come from image entries, source-backed ARM A32/Thumb
profile roots, exports, defined function symbols (including verified PE/PDB procedure
records), Mach-O function starts, explicit user
functions, and code regions. Direct calls can establish callees; branch
targets remain blocks unless independent root evidence establishes a function.
When the configured function budget is reached, explicit user function and
manual code-region roots are admitted before metadata-derived roots. Omitted
automatic roots remain ownership boundaries, so the cap cannot make their
bytes silently merge into another function.

For flat NMOS 6502 images, the NMI, reset, and IRQ/BRK vector words at
`$FFFA`, `$FFFC`, and `$FFFE` can seed function entries. A vector is used only
when its two little-endian bytes are readable in a mapped 6502 context and its
nonzero target has that same architecture/mode; the vector slot is retained as
the seed source. Ordinary executable-byte, root conflict, and budget checks
still apply. This does not model cartridge banking, mirrored vector windows,
or console-specific interrupt remapping.

ARM predicate handling tracks possible NZCV valuations during function
recovery. A32 condition codes and the condition attached to each Thumb IT
slot guard both execution and skip edges. For conditional branches, the taken
and not-taken edges refine those valuations; writes to NZCV widen the executed
path to all valuations while the predicate-false path retains its prior
valuations. Calls conservatively widen the continuing executed path because
the callee may change flags. Terminal returns, traps, unsupported PC writes,
and unresolved transfers retain guarded stops and possible skip edges. The
A32/Thumb model does not evaluate flag-producing instruction semantics, so it prunes
only contradictions implied by known predicate conditions. Unknown Thumb IT
state remains conservative and does not narrow conditions. Shared block CFGs
publish the union of edges reachable by their owners; per-owner edge filtering
is not represented in the public CFG.

AArch64 `B.cond` edges likewise constrain the possible NZCV nibbles, and
decoded NZCV writes invalidate the old flag facts. A bounded scalar refinement
then evaluates `ADDS`, `SUBS`, and `ANDS` (including `CMP`, `CMN`, and `TST`
aliases) when their operands are proven. Arithmetic computes N/Z/C/V at the
actual W/X width, including no-borrow C for subtraction; `ANDS` sets C/V to
zero. `CCMP`/`CCMN` retain the encoded fallback nibble on a false condition and
use the proven arithmetic flags on a true condition. An unknown arithmetic
arm widens only that arm. The resulting flag sets flow through later blocks
and conditional compares, so contradictory branch paths do not acquire
trusted function ownership or establish callees.

The refinement carries full X values from `MOVZ`/`MOVN`/`MOVK`, supported
immediate and shifted-register add/subtract/logic forms, and conditional
selects whose possible values agree. W writes zero-extend. A register value
survives a join only when every discovered predecessor proves the same full
value. Calls, opaque operations, function/chunk entries, differing execution
contexts, and relocated operands discard the relevant proof. Stack pointers
and memory contents are not treated as constants. Proven operands also prune
`CBZ`/`CBNZ` and `TBZ`/`TBNZ` edges; otherwise both edges remain possible.
This follows the scalar flag behavior in the
[Arm A64 reference](https://documentation-service.arm.com/static/68da52dfbd7cab51328c0622).

The pass is capped at 100,000 A64 instructions and 500,000 edges and solves only acyclic
predecessor dependencies. Cyclic or incomplete regions retain local-only
zero-register and identical-register proofs; they do not inherit speculative
constants. Initial discovery still follows conservative paths before this
refinement. Consequently, an overlap encountered during discovery remains a
reported conflict even if a later proof excludes that path. The pass does not
infer runtime memory values, floating-point flags, loop-carried constants, or
general symbolic relationships between different unknown registers.

Validated PE TLS callback entries are also roots because the loader invokes
them independently of the image entry point. Callback RVAs are translated
against the currently mapped PE base, then passed through the normal
initialized executable-code and architecture-context checks. A callback that
does not resolve to permitted code is ignored; TLS callback metadata does not
provide function extents, so these roots have no metadata chunk bound.

Validated PE Guard CF function-table entries are roots as well. These entries
cover address-taken functions that may have no direct call edge or ordinary
symbol. Their RVAs are translated against the mapped image base and checked
through the same executable and initialized-code rules. The table identifies
entry points but does not provide function extents.

Validated Mach-O `__eh_frame` FDEs also establish function roots. Their
address ranges bound recovered ownership, preventing linear fallthrough from
absorbing adjacent code when the FDE provides an exact nonempty range. FDEs
whose range is empty, overflows the address space, or lacks a resolved start
are ignored as roots; the underlying metadata remains available for inspection.

Function ownership is represented per decoded address, not as a single
address-to-function map. Each independently established root is traversed over
its trusted CFG edges; when paths converge on a shared tail or fragment, the
basic block carries every proven owner and each function record includes that
block and the corresponding chunk range. Xrefs at such a source are associated
with each proven owner. Consumers that accept only an address must not choose
an arbitrary owner: exact entry addresses remain selectable, while shared
interior addresses require resolving one of the stable function identity and
entry candidates. Ownership is conservative: conflicting instruction streams
or path-dependent delay-slot semantics stop trusted ownership and mark affected
functions incomplete rather than assigning contested bytes to one function.

Function records preserve shared tails and explicit chunks. An unconditional
jump to a known function entry is recorded as a tail-call candidate; a
conditional branch to that entry remains a control-flow boundary and is not
misreported as a tail call. A function is marked as a thunk only when its sole
owned instruction is an unconditional jump to another established function.
Such a terminal transfer is considered complete, while a multi-instruction
tail-call candidate does not receive the thunk marker. Conflicting decode
streams stop trusted ownership. Indirect transfers, invalid or
unsupported encodings, truncated instructions, unmapped or uninitialized
bytes, permission boundaries, instruction/chunk boundaries, and configured
budgets remain explicit stops. Relocation, manual-data, and image-exclusion
checks apply across the enabled architectures.

A32 recovery includes predicate-aware conditional PC writes and return
fallthrough. Thumb roots require source-backed known-clear IT state, carry
ITSTATE across edges, and stop conservatively when a join receives incompatible
states. Predicated PC-writing jumps retain both the taken transfer and the
possible false-predicate continuation; unresolved taken targets remain explicit
stops. Reanalysis may reuse instruction facts only when the current address
mapping, decode context, instruction bytes, and incoming Thumb IT state agree.
It rebuilds control flow and ownership from the reused and newly decoded facts,
so mode or root changes cannot silently preserve stale blocks. The recovery walk
remains bounded by the configured instruction, membership, function, and block
budgets and checks cancellation during discovery and ownership. MIPS32 records
supported delay slot instructions as part of control-transfer ownership, with unsupported
delay-slot forms stopping explicitly.

MIPS64 uses the same bounded block-ownership rule for classic one-instruction
delay slots. The control-transfer block points to a distinct slot block; the
slot block owns the post-slot taken/jump/call-continuation/return behavior, so
the branch condition and transfer destination remain attached to their actual
execution paths. Branch-likely instructions keep the not-taken continuation on
the transfer block, bypassing the slot, while their taken edge leaves the slot
block. Slot instructions must decode as ordinary fallthrough instructions;
nested transfers, opaque instructions, and unsupported encodings stop there.
Because one cached node represents each address, recovery marks a slot
incomplete if any ordinary CFG edge or independent function root also enters
that address. This avoids assigning the slot's after-transfer edges to an
entry path that did not execute the owning transfer. The model covers direct
conditional/unconditional transfers and direct calls; unresolved indirect
targets remain explicit stops, and this slice does not implement delay-slot
execution in the decompiler IR.

`tests/function_tests.cpp` covers call/return and conditional-branch ownership
for A64, RV32, RV64, and 6502; MIPS32 delay-slot flows; A32 conditional-return
fallthrough; Thumb source-backed IT propagation and unknown-root rejection;
shared tails; and explicit incomplete stops. These fixtures validate
function ownership and call edges, not the full instruction sets or runtime
behavior of target programs.

Matched PE/PDB procedure symbols establish separate function roots. PDB
metadata marked mismatched, and non-procedure public/data symbols, are ignored
for boundary discovery.

Defined ELF `STT_FUNC` and `STT_GNU_IFUNC` symbols establish symbol roots.
For an IFUNC, the symbol value identifies the resolver routine, so recovery
seeds that address as code and does not attempt to execute the resolver or
predict which implementation it returns. The ordinary executable, initialized
byte, context, relocation, and budget checks still apply. This does not
discover implementations selected only at runtime, and undefined IFUNC
symbols do not create roots.

Validated imported ELF DWARF subprogram DIEs also establish function roots,
including functions omitted from the ELF symbol table. Their half-open code
ranges are rebased to the current image and become ownership chunks only when
every range is fully backed by initialized executable bytes and uses the same
decoder context. Conflicting DIE ranges at one entry are kept as root evidence
but do not bound ownership. Explicit user chunks, unwind ranges, POGO extents,
and ELF symbol extents retain precedence. Range-less/unmapped subprograms and
relocatable-object DWARF are not used for function discovery; Thumb roots still
need source-backed IT-state metadata or a validated EHABI entry.

DWARF `DW_TAG_entry_point` records are kept separately from subprograms. A
named entry point with a direct `DW_AT_low_pc` can seed analysis at that exact
PC after the normal mapped-code and execution-context checks. The record does
not claim a function extent, code chunk, or callable prototype; indexed
`DW_FORM_addrx` entry PCs and entry points without a direct name are not used.

For ELF64 PowerPC ELFv1 images, a defined `STT_FUNC` whose section is
`.opd` names a 24-byte function descriptor rather than executable code.
Recovery validates the descriptor's aligned, initialized section extent,
reads its first target-width word using the ELF byte order, and seeds that
code address through the normal executable and mapped-context checks. The
other descriptor words are not interpreted, descriptors without initialized
targets do not create roots, and ELFv2 is not treated as descriptor-based.
This supplies roots only; it does not infer descriptor relocation, TOC
semantics, or function extents.

For static ELF `ET_EXEC` images, allocated `SHT_INIT_ARRAY` and
`SHT_FINI_ARRAY` sections can also provide initializer/finalizer roots when
the corresponding `DT_INIT_ARRAY` or `DT_FINI_ARRAY` tag is absent. Entries
must be aligned, pointer-width slots backed by initialized section bytes and
are decoded using the ELF byte order. Only nonzero targets in initialized
executable bytes are retained. Evidence identifies the section and slot
separately from dynamic-tag evidence. This fallback does not apply to
`ET_DYN` or relocatable objects, does not interpret dynamic tags as section
metadata, and does not resolve relocations in the section entries.

For PE32 images, validated SafeSEH handler RVAs also seed function entries.
The loader checks table bounds, strict ordering, initialized executable
backing, and source spans. Analysis translates each RVA against the mapped
image base and reapplies its normal executable-code/root checks. SafeSEH
entries establish handler roots only; they do not imply a function extent or
claim that every handler is reached in ordinary control flow. The
function-engine fingerprint includes this root source so persisted recovery
is recomputed when upgrading.
