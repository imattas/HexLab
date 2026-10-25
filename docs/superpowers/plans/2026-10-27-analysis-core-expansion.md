# Analysis Core Expansion Plan

1. Inspect each existing implementation and its explicit documented gaps.
2. Implement the three disjoint subsystem improvements in SIMD, PE/PDB types, and decompiler aggregate typing.
3. Review bounds, semantic preservation, and public data compatibility across workstreams.
4. Compile affected Debug targets; add or run no tests.
5. Update capability ledger rows using implemented source and build evidence.
6. Confirm no GUI was opened and `out/` remains untouched.

## Progress

- **x86 SIMD:** added strict VEX.128/.256 AVX2 `vpsubb/w/d/q` decode, formatting, operand and memory effects, VEX.128 upper-YMM clearing, and typed lane-shape decompiler intrinsics. Lane execution and EVEX remain unsupported. `hexlab_processors` and `hexlab_decompiler` Debug targets compiled.
- **PE/PDB types:** parse CodeView unique names for aggregates/enums, canonicalize forward declarations by kind plus exact unique name, and import distinct ODR aggregates that share a displayed name under bounded deterministic SHA-256 storage keys. Type payloads preserve source display names and recursive named references use the storage key. Missing/ambiguous identities remain skipped. `hexlab_types`, `hexlab_loaders`, and `hexlab_workspace` Debug targets compiled.
- **Decompiler aggregate types:** recover nested pointer layouts through four levels under a shared per-function one-million-item budget. Conflicts, cycles, missing evidence, and budget exhaustion stay ambiguous. Typed pseudocode emits member or exact-width array access only when offsets and widths match recovered structures; unions and dynamic/partial cases keep prior fallback formatting. `hexlab_decompiler` Debug target compiled.
- **Integrated verification:** `cmake --build switch-desktop-build --target hexlab_desktop_components --config Debug --parallel 3` completed with exit code 0 after all three workstreams. Existing MSVC warnings remain. No tests were added or run; no GUI was opened; `out/` remains untouched.
