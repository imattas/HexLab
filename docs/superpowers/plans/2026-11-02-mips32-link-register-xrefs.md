# MIPS32 delayed link-register xrefs plan

## Files

- `libs/analysis/src/mips64_reference_helpers.hpp`: add a strict MIPS32 PC+8 link-value helper beside the existing MIPS64 implementation.
- `libs/analysis/src/references.cpp`: install the link after each delayed link instruction, including relocation-covered instructions, so the following delay-slot operation sees it.
- `libs/analysis/src/functions.cpp`: add a fingerprint token to invalidate cached function/reference facts.
- `docs/architecture-xrefs.md`: record supported forms and conservative limits.
- This plan and its design spec: preserve the change boundary and verification result.

## Steps

1. Implement the helper for the four REGIMM link forms and `JAL`/`JALR`, validating decoded writes, proven-taken REGIMM conditions, and executable initialized `PC+8`.
2. Invoke it after normal transfer processing and on the relocation-opaque early path; retain existing post-call continuation invalidation.
3. Update the engine fingerprint and architecture notes.
4. Run `git diff --check`, build `hexlab_analysis` on Windows and WSL with `BUILD_TESTING=OFF`, then commit locally.

## Review focus

- Address-space overflow at `PC+8`: reject before arithmetic wraps.
- Out-of-range or uninitialized return sites: require four file-backed executable bytes.
- Malformed multiple/incorrect link destinations: reject the fact.
- Conditional REGIMM link branches with unknown or false conditions: emit no link fact.
- Relocation-covered call: keep only the independently known link value; do not infer a call target.
- Continuation after the callee: existing call-continuation transfer must clear the link fact.

## Verification results

- `git diff --check`: passed.
- Windows MSVC 2022 Debug, `BUILD_TESTING=OFF`: `cmake --preset windows-headless -DBUILD_TESTING=OFF`, then `cmake --build --preset windows-headless --target hexlab_analysis --parallel 3`; exit 0. An incremental rerun after tightening the REGIMM condition guard also exited 0.
- WSL Ubuntu 24.04, Clang 18.1.3 Debug, `BUILD_TESTING=OFF`: copied the final `mips64_reference_helpers.hpp`, `references.cpp`, and `functions.cpp` into `/tmp/hexlab-root-wave-2026-11-02`, then ran `cmake --build /tmp/hexlab-root-wave-2026-11-02-build --target hexlab_analysis --parallel 3`; exit 0.
- Tests, CI, and runtime execution were not run.
