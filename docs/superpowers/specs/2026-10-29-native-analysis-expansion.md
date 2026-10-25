# Native Analysis Expansion Wave

## Objective

Advance three independent capabilities that materially affect IDA-class workflows: static Mach-O executable linking, managed CIL control-flow lifting, and cross-architecture reference recovery.

## Approaches

1. Continue small isolated parser or UI fixes. This is low integration risk but leaves major workflows incomplete.
2. Add one end-to-end capability in each subsystem, preserving the current library and desktop boundaries. This produces broader user value while keeping ownership and review tractable. **Selected.**
3. Replace the existing subsystem APIs before adding features. This would create unnecessary migration risk because the current APIs already preserve bounded metadata and conservative fallbacks.

The chosen approach adds three self-contained feature slices in the existing C++ monorepo: support ARM64 static Mach-O archive links across the existing section model; make CIL evaluation-stack dataflow converge across supported loop backedges; and resolve PPC32/PPC64/MIPS64 address construction and memory references through the existing bounded CFG register analysis.

## Constraints

- Preserve bounded parsing, checked arithmetic, cancellation behavior, and explicit rejection of malformed or ambiguous input.
- Keep the existing shared engine and wxWidgets desktop architecture.
- Do not alter project persistence formats unless an existing compatible representation cannot express the feature.
- Do not add or run tests in this wave. Compile affected Debug targets and inspect source paths.
- Leave `out/` untouched. Use the desktop only if visual inspection materially helps.
- Keep workstream source ownership separate; root integrates documentation and the capability ledger.

## Completion Evidence

- ARM64 Mach-O link path emits a valid static executable using existing archive member selection, checked symbol resolution, section permissions, and entry state.
- CIL loop stack joins use a bounded fixed-point algorithm and preserve SSA edge values; incompatible joins or budget exhaustion fail conservatively.
- PPC32/PPC64/MIPS64 register propagation uses typed operands, exact architecture widths, and the existing CFG worklist; unknown writes, ambiguous control flow, overflow, and budget exhaustion remain conservative.
- A serial integrated Debug build succeeds; no tests are added or run; `out/` remains untouched.
