# Native Engine Expansion

## Intent

Continue the C++/wxWidgets reverse-engineering workbench across three separate engine gaps: x87 stack state, ELF32 runtime relocation application, and PDB IPI references in type-server sets.

## Approaches

1. Add unrelated small UI changes. This would not materially advance instruction semantics, runtime image modeling, or debug type recovery.
2. Implement one bounded vertical slice in each existing subsystem while preserving its current API and conservative fallbacks. **Selected** because the current architecture already provides the required register effects, relocated image overlays, and namespace-aware PDB type graphs.
3. Replace the processor, loader, and type-import models before extending them. This would add migration risk without being required by the selected capabilities.

## Workstreams

1. **x87 stack state:** represent and propagate the architectural TOP rotation and tag state for supported push, pop, `FINCSTP`, and `FDECSTP` instructions. Preserve logical `ST(i)` identity across proven transitions; unknown environment restores or conflicting joins must remain explicit/opaque.
2. **ELF32 runtime relocations:** add bounded little-endian i386 `ET_DYN` application for `R_386_RELATIVE`, `R_386_GLOB_DAT`, and `R_386_JMP_SLOT`, including implicit `REL` addends, exact caller-supplied symbol bindings, checked 32-bit arithmetic, and provenance. Unsupported relocation types remain skipped with diagnostics.
3. **PDB IPI type-server references:** resolve supported `LF_FUNC_ID`/`LF_MFUNC_ID` IPI records against the matching PDB's TPI and IPI namespaces across an exact-identity type-server set. Preserve parent/class identity and signature provenance; missing, cyclic, duplicate, or ambiguous identities remain unresolved.

## Constraints

- Keep resource, record, and traversal bounds; honor cancellation where supported.
- Keep the current C++20 libraries and wxWidgets desktop architecture.
- Do not change project persistence unless an existing format cannot express the result.
- Do not add or run tests in this wave; compile affected Debug targets and inspect code paths.
- Leave `out/` untouched and do not launch or focus any GUI.
- Keep source ownership separate; root integrates the capability ledger.
