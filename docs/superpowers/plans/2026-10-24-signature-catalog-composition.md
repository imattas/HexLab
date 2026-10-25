# Signature Catalog Composition Plan

## Files

- `libs/analysis/include/hexlab/analysis/signatures.hpp`
- `libs/analysis/src/signatures.cpp`
- `docs/signatures.md`
- Scoped spec/plan/report under `docs/superpowers` and `.superpowers/sdd`

## Steps

- [x] Append catalog source index to match metadata and expose bounded multi-catalog scan/recognition overloads.
- [x] Validate set size, catalog versions, architecture/mode targets, and total definition count before scanning.
- [x] Reuse one existing scanner invocation so all work limits remain aggregate; map matches back to catalog and global definition indices.
- [x] Document ordering, ambiguity, legacy-catalog policy, API use, and limits.
- [ ] Review error paths and ABI/source compatibility; root compiles `hexlab_analysis` Debug. Do not add/run tests.
