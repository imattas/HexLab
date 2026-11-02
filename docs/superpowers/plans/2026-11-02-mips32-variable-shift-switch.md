# MIPS32 variable-shift switch plan

## Files

- `libs/analysis/src/switches.cpp`: add exact constant-count `SLLV` evaluation to MIPS32 constant propagation, same-block switch setup, and bounded cross-block word-scale proof.
- `docs/switch-analysis-validation.md`: document the accepted O32 sequences, proof conditions, build evidence, and remaining unsupported cases.
- `libs/analysis/src/functions.cpp`: append a function-engine fingerprint token so stale switch-derived function results are recomputed.
- This plan and the design spec: retain the intended proof boundary and verification record.

## Steps

1. Extend same-block and predecessor constant propagation for relocation-free `SLLV` using proven low-five-bit shift counts.
2. Extend O32 selector scaling to derive its factor from a proven count; preserve the original selector, factor, and scale instruction for existing guard proofs.
3. Update the engine fingerprint and architecture documentation.
4. Run `git diff --check`, build `hexlab_analysis` on Windows and WSL with `BUILD_TESTING=OFF` where toolchains are available, then commit locally.

## Review focus

- Unknown or path-disagreeing count register: reject the SLLV-derived fact.
- Count values above 31: mask only their architectural low five bits.
- Relocated instruction or shift-count constant: reject the affected setup fact.
- Shifted selector used for a mismatched table width: final decoded entry-width/scale check must reject it.
- SLLV applied to an already symbolic base: do not combine symbolic values.

## Verification results

Windows/MSVC 19.44 Debug `hexlab_analysis` build passed with `BUILD_TESTING=OFF`.
WSL Ubuntu 24.04 Clang 18 Debug `hexlab_analysis` build passed with `BUILD_TESTING=OFF`. `git diff --check` passed. Tests were not run as requested.
