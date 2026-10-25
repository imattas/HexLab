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
