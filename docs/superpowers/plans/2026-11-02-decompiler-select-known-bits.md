# Plan: select simplification and known bits

1. Inspect typed select representation and known-bit proof use.
2. Fold constant one-bit selectors and identical-arm selectors only when dropping the condition is safe.
3. Propagate known bits through exact-type select arms, selecting proven conditions and intersecting unresolved alternatives.
4. Document lazy-arm, unsupported-operation, width, and budget behavior; update the partial capability evidence.
5. Review and build the affected Windows and WSL targets with tests disabled; commit locally.

## Progress

- Implemented steps 1–4. Windows Debug `hexlab_decompiler` and `hexlab_cli` build passed with `BUILD_TESTING=OFF`; no tests were run.
- WSL Ubuntu 24.04 / GNU 13.3 configure passed with `BUILD_TESTING=OFF`. `hexlab_processors` and `hexlab_decompiler` libraries built; the CLI dependency build remained in `hexlab_automation` compilation after approximately 32 minutes and was stopped. No tests were run.
