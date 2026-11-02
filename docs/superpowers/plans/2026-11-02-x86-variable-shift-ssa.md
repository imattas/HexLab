# Plan: x86 variable-count shift SSA results

1. Inspect current scalar x86 shift lowering and expression/SSA conventions.
2. Materialize masked register-count `SHL`/`SHR`/`SAR` data results, including zero-count preservation, the defined exact-width result, and an opaque above-width result.
3. Preserve incoming status flags for zero count and keep nonzero variable-count flag values opaque.
4. Document the supported forms and explicit limits.
5. Build the affected Windows and WSL processor/decompiler/CLI targets with tests disabled; review the diff and commit locally.

## Verification

Both platform builds passed with `BUILD_TESTING=OFF`; no tests were run.

Windows MSVC Debug:

```powershell
$env:_CL_='/bigobj'
cmake --preset windows-headless -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build --preset windows-headless --target hexlab_processors hexlab_decompiler hexlab_cli --parallel 4
```

WSL Ubuntu 24.04, Clang 18.1.3, Unix Makefiles, source snapshot at commit `a36833c0`:

```sh
cmake -S /tmp/hexlab-x86-variable-shift-a36833c0 -B /tmp/hexlab-x86-variable-shift-a36833c0-build -G 'Unix Makefiles' -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build /tmp/hexlab-x86-variable-shift-a36833c0-build --target hexlab_processors hexlab_decompiler hexlab_cli --parallel 4
```
