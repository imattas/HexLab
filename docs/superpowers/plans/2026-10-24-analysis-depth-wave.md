# Analysis depth wave plan

## Tasks

- [x] Extend native decompiler structuring for nested regions with edge-safe SSA lowering.
- [x] Extend DWARF expression decode/evaluation through live debugger locals.
- [x] Add bounded PE AMD64 `__CxxFrameHandler4` metadata decoding.
- [x] Reconcile documentation, package install lists, and capability evidence.
- [x] Run one serial integrated Debug build; scan touched files and confirm `out/` is untouched.

## Validation limits

Do not add or run tests. PE/DWARF format claims must cite primary references or
clearly marked implementation research; unimplemented runtime semantics must
remain explicit.

## Integration evidence

- `cmake --build switch-desktop-build --target hexlab_desktop_components --config Debug --parallel 1` completed successfully. Existing MSVC STL DLL-interface and wxWidgets deprecation warnings remain.
- Documentation install entries for `docs/decompiler-structuring.md`, `docs/debugger-dwarf-locals.md`, and `docs/pe-exception-directory.md` are present in the root `CMakeLists.txt`.
- `docs/capabilities.csv` retains 80 records; the ELF/DWARF, PE, and decompiler rows now describe the implemented behavior and remaining unsupported cases.
- No tests were added or run. The integrated build wrote only under `switch-desktop-build`; `out/` was not read, written, cleaned, or built.
