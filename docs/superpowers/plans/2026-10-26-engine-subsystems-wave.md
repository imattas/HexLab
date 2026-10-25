# Engine Subsystems Wave — 2026-10-26

## Objective

Implement three large independent capability advances for the HexLab IDA-class C++ workbench: robust bounded switch analysis, semantics-preserving decompiler structuring, and complete durable C-header declaration import.

## Workstreams

1. **Switch analysis:** extend `libs/analysis` control-flow reasoning so selector bounds can be proven across CFG edges and recognized tables remain bounded, cancellable, and conservative. Owner: switch-analysis agent. Avoid decompiler and desktop files.
2. **Decompiler structuring:** extend `libs/decompiler` structured C-like output for nested loops and multiway control flow without duplicating side effects or losing CFG behavior. Owner: decompiler agent. Avoid analysis switch-recovery implementation and desktop editor files.
3. **Declaration persistence:** extend the C-header workflow to persist object declarations, function prototypes, and enum values through project commands, queries, undo/redo, and portable exchange. Owner: type-import agent. Avoid analysis/decompiler files.

## Review and integration

- Root reviews each change for ownership conflicts, conservative behavior, and API/schema compatibility.
- Affected Debug targets may be compiled; no tests are added or run.
- Update capability ledger rows for `analysis.switches`, `decompiler.structure`, and the native type workflow.
- Keep the desktop closed and `out/` untouched.

## Progress

- Initial inspection found switch-table recovery is limited to recognized x86/AArch64 instruction sequences and same-block guard pairs; bounded multi-edge guard proof is still missing.
- Structured output already supports selected conditionals and loop forms, with CFG fallback for unsupported regions; nested/multiway combinations remain a source of incomplete output.
- The C parser already recognizes object/function declarations and enum values, but ABI 1.13 plugin import currently persists only typedefs and tags. This wave carries those parsed declarations into durable project workflows.

## Completed work

- **Switch guard proofs:** added one per-analysis cached reverse CFG with 100,000-node / 1,000,000-edge caps, 4,000,000 total scan records, and 2,000,000 proof operations. Bounds now span acyclic selector-preserving connector paths and diamonds; bypasses, alternate entries, selector clobbers, calls, opaque facts, cycles, compare bypasses, and mid-setup entry reject the bound. Updated function fingerprint and switch docs. hexlab_analysis Debug target linked successfully; no tests run.
- **AArch64 ADR switch tables:** added bounded `ADR Xbase; LDR Xtarget, [Xbase, Xindex, LSL #3]; BR Xtarget` recovery for nearby absolute-pointer tables. It preserves relocation-row and dyld provenance through the existing table reader, accepts only distinct valid registers and contiguous same-context instructions, and uses the existing guard proof and executable-target validation. Updated switch API/docs. No tests run.
- **Decompiler multiway structuring:** added complete switch metadata/CFG/phi validation, nested switch/conditional DAG emission with shared joins, and switch transitions in bounded state-machine output for cyclic/nested-loop graphs. Complex entry switches defer to general formatters. Fixed duplicated switch-prefix effects and made loop-edge phi copies simultaneous. Updated docs/decompiler-structuring.md; Debug ClCompile succeeded with existing warnings; no tests run.
- **Durable C declaration import:** ABI 1.14 now exposes declaration roles and paged exact enum values; schema v8, codec v7, and exchange v5 persist object/function declarations and enum values. ABI 1.13 summary semantics remain typedef-plus-tag counts. Snapshot replacement plans compare exact before rows, Python import planning is revision-bound, and enum alias resolution uses a memoized 64-step resolver with indexed lookup. Updated SDK, header import, project format/exchange docs and C example. Database, workspace, plugins, optional Python, and sample Debug builds passed; no tests run.

Integration review found and fixed a possible stale replacement overwrite, an ABI summary counter semantic change, and a page-wide enum alias lookup cost issue. out/ and GUI remained untouched.

- **Legacy SDK row-set compatibility:** kept ABI 1.13 	ypes() paging limited to named type rows while ABI 1.14 declarations() returns type/object/function roles. The final hexlab_plugins Debug target and sample provider both rebuilt successfully after this fix; no tests run.
