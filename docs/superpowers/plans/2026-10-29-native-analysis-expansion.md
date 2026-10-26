# Native Analysis Expansion Wave Plan

## Global Constraints

- Preserve bounded parsing, checked arithmetic, cancellation behavior, and explicit rejection of malformed or ambiguous input.
- Keep the existing shared engine and wxWidgets desktop architecture.
- Do not alter project persistence formats unless an existing compatible representation cannot express the feature.
- Do not add or run tests in this wave. Compile affected Debug targets and inspect source paths.
- Leave `out/` untouched. Use the desktop only if visual inspection materially helps.
- Keep workstream source ownership separate; root integrates documentation and the capability ledger.

## Tasks

1. **Mach-O linking:** add bounded ARM64 `MH_OBJECT` archive linking into static `MH_EXECUTE`, with supported text/constant/data/BSS contributions, the necessary ARM64 relocation forms, and ARM64 entry state. Keep x86-64 behavior unchanged. Own `libs/loaders/src/macho_link.cpp` and Mach-O link documentation only.
2. **Managed decompilation:** replace the CIL lifter's unsupported non-empty backedge stack case with bounded fixed-point stack dataflow and edge-defined SSA values for loops. Preserve exact stack type/depth agreement and conservative rejection for irreducible/ambiguous or over-budget graphs. Own CIL lifter implementation and managed decompilation documentation only.
3. **Cross-architecture references:** add bounded PPC32/PPC64/MIPS64 register-value propagation for address construction, memory references, and proven static pointer loads, using exact typed operands and the existing CFG worklist. Preserve unknown writes and unsupported instructions conservatively. Own `libs/analysis/src/references.cpp` and architecture-reference documentation only.

## Integration

- Root reviews subsystem boundaries and verifies no overlap.
- Compile the integrated `hexlab_desktop_components` Debug target serially.
- Update only evidence-backed capability ledger fields and record the build result.
- Confirm `out/` is untouched.

## Progress

- Resolved indirect-call prototype propagation now requires exact caller/target ABI identity after a bounded unique in-set address proof. Windows Debug `hexlab_decompiler` build passed; no tests run.

- [x] Task 1: ARM64 static Mach-O linking, including a generic API entry point and retained compatibility wrapper.
- [x] Task 2: fixed-point CIL stack flow with exact stack-shape validation and loop/join phis.
- [x] Task 3: PPC32/PPC64/MIPS64 cross-architecture reference propagation through the bounded CFG analysis.
- [x] Integrated build and capability ledger update.

**Integration evidence:** `cmake --build switch-desktop-build --target hexlab_desktop_components --config Debug --parallel 1` completed with exit code 0 after fixing one helper declaration-order compile error. No tests were added or run; the desktop was not launched; `out/` was left untouched.

- **Mach-O Objective-C metadata:** extended runtime records with direct metaclass/class-method decoding and `__objc_protolist` definitions for adopted protocols, required/optional method lists, and instance properties. Exact address matches link class superclass, category target, and protocol references to scanned records; existing bounded relative method-list decoding and relocation/dyld provenance remain in use. Updated `docs/macho-objc-runtime.md`; `hexlab_analysis` Debug target linked. No tests run.

- **Initializer seed provenance:** ELF dynamic initializer values and preinit/init/fini array seeds, plus Mach-O `__mod_init_func` and routines roots, now retain file, table/section, index, tag, relocation and dyld-origin evidence in `FunctionSeed` and the derived cache. Updated the function fingerprint/cache version and initializer docs. The focused `hexlab_analysis` and `hexlab_cli` Debug targets linked successfully; no tests run.
