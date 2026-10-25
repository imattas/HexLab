# Native Workbench Expansion Wave Plan

**Spec:** `docs/superpowers/specs/2026-10-25-native-workbench-wave.md`

## Ownership map

| Task | Owner | Primary files | Deliverable |
|---|---|---|---|
| Objective-C desktop inspection | desktop UI agent | `apps/desktop/macho_objc_view.*`, `apps/desktop/main_frame.cpp`, desktop docs | Binary Metadata page for classes, categories, protocols, method/property details, and explicit address navigation |
| MSVC ABI special names | symbol agent | `libs/symbols/src/demangle.cpp`, `docs/symbol-demangling.md` | Additional bounded special-name productions, including virtual tables/RTTI and safe thunk forms where grammar permits |
| Linux AArch64 thread scheduling | debugger agent | `libs/debugger/src/native_backend_linux_aarch64.cpp`, AArch64 debugger docs | Per-thread continue schedules with rollback, pending-signal preservation, and explicit preflight rejection for unsupported combinations |

## Tasks

1. Inspect the Objective-C scan result and existing Binary Metadata notebook. Build the view from the immutable analysis snapshot; provide bounded rows, status/provenance details, and navigation actions. Compile `hexlab_desktop_components` and `hexlab` serially.
2. Extend the bounded MSVC decorated-name parser with real ABI special-name forms that can be rendered without guessing. Preserve unchanged-input fallback and enforce existing parser limits. Compile `hexlab_symbols` and its CLI/desktop consumers serially.
3. Extend Linux AArch64 ptrace thread scheduling in `native_backend_linux_aarch64.cpp`; CMake does not select the x86-only `native_backend_linux.cpp` for AArch64. Use the Linux x86 schedule contract as a behavioral reference, and validate ownership, uniqueness, stopped state, event-owner inclusion, pending-signal preservation, peer stop/rollback, deferred races, and unsupported step/breakpoint cases. Source-review on this Windows host; no Linux runtime claim.

## Integration

- Reconcile exact changed-file lists; resolve ownership conflicts before building.
- Review source and docs for malformed-input bounds, event safety, and fallback behavior.
- Compile supported Windows Debug targets serially; no tests and no GUI launch.
- Root updates only capability rows supported by source review/build evidence, then commits and pushes to `feat/foundation`.
- Confirm the GUI stayed closed and `out/` stayed untouched.

## Progress

- Objective-C metadata view integrated with lazy page-selection scanning, per-snapshot cached rows, status/provenance, and navigation. A review found the cached snapshot was held as a raw pointer; it now retains a `shared_ptr` owner to prevent stale cache reuse. Windows Debug builds of `hexlab_desktop_components` and `hexlab` passed; no GUI or tests run.
- MSVC special-name rendering covers `??_7`, `??_8`, and selected `??_R0/R2/R3/R4` forms. Independent review caught and corrected the vbtable `7B@` suffix. Windows Debug builds of `hexlab_symbols` and `hexlab_cli` passed; broader productions remain unsupported.
- Linux AArch64 scheduling now handles partial-resume rollback and deferred stops; source review and x86-host Clang syntax-only compilation passed. Native Linux/AArch64 ptrace runtime validation remains outstanding.
- Capability inventory and install documentation list were updated. The GUI stayed closed, `out/` was untouched, and no tests were run.
