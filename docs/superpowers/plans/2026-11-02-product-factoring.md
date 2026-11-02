# Plan: bounded fixed-width product factoring

1. Inspect current identity simplification, effect/partial-operation whitelists, IR integer semantics, and capability evidence.
2. Implement factoring for `add`/`sub` of same-width `mul` nodes with exact common SSA factors; require purity, total operations, and expression-size bounds.
3. Document fixed-width modular overflow behavior and excluded poison/effect/memory cases; append evidence while preserving `partial`.
4. Build affected Windows and WSL targets with `BUILD_TESTING=OFF`; run no tests or CI.
5. Commit locally and report build limits and unsupported forms.

## Progress

- Implemented the bounded fixed-width product factoring rule and documentation; the capability remains `partial`.
- Windows Debug `hexlab_decompiler` built successfully (`hexlab_decompiler.dll` produced) with tests disabled. The combined command then entered CLI dependencies; that work was stopped before CLI completion.
- WSL Ubuntu 24.04 / GNU 13.3 configure was stopped before compilation at the request to avoid another broad cold dependency build. No tests or CI were run.
