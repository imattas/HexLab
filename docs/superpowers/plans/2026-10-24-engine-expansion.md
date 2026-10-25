# Engine Expansion Implementation Plan

## Goal

Make concrete progress toward the approved full HexLab/IDA-equivalent destination by advancing three independent engine areas: ELF split-debug package consumption, PowerPC/POWER instruction support, and reusable library signature recognition.

## Constraints

- Keep the approved C++20 shared-library monorepo and wxWidgets application architecture.
- Preserve the in-progress decompiler worktree; no agent may edit `libs/decompiler/src/decompiler.cpp` or its active tests/docs.
- Keep desktop/UI closed while the user is gaming.
- Do not add or run tests in this batch. Agents may inspect existing tests as documentation only.
- Integrate with one serialized Windows Debug `hexlab` build after review.
- Agents must not edit `docs/capabilities.csv`; primary agent owns ledger updates.

## Independent workstreams

1. **ELF split-debug packages** — extend bounded DWP contribution support into consumers for debug line/range data and supplementary references where safe; preserve exact unit identity and fail-closed behavior.
2. **PowerPC/POWER** — expand original decoder coverage across 32/64-bit modes and common control-flow, integer, load/store, and special-register instructions; preserve typed operands/effects and explicit unsupported instructions.
3. **Signature recognition** — deepen reusable function/library identification beyond byte-mask matching, with reproducible provenance and explicit ambiguity; integrate at a coherent library/API boundary.

## Integration

- Review each independent change and support boundary; resolve API or build-list overlap in the primary worktree.
- Update docs and capability ledger without converting unverified coverage into verified claims.
- Run `cmake --build out/build/windows-desktop --target hexlab --config Debug -- /m:1 /v:minimal` once; no tests or GUI launch.

## Integration record

- DWP split-CU LINE/RNGLISTS consumers, PowerPC/POWER integer decoder expansion, and normalized function fingerprints are integrated in their existing library/API boundaries.
- Review corrections include DWP line-table endianness, PowerPC `rA=0` indexed addressing and `subfic` carry effects, SC reserved bits, valid-but-unsupported PPC64 LWA, and fingerprint digest parsing.
- The 2026-10-24 Windows Debug `hexlab` build passed after adding default equality to `DwarfLineUnit` for incremental metadata comparisons. The first build exposed that integration error; the corrected build completed. No tests are added or run, and no UI is opened.
