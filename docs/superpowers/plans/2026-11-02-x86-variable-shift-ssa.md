# Plan: x86 variable-count shift SSA results

1. Inspect current scalar x86 shift lowering and expression/SSA conventions.
2. Materialize masked register-count `SHL`/`SHR`/`SAR` data results, including zero-count preservation, the defined exact-width result, and an opaque above-width result.
3. Preserve incoming status flags for zero count and keep nonzero variable-count flag values opaque.
4. Document the supported forms and explicit limits.
5. Build the affected Windows and WSL processor/decompiler/CLI targets with tests disabled; review the diff and commit locally.
