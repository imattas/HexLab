# Mach-O read-only section contribution plan

> **For agentic workers:** Implementation is bounded to the existing Mach-O linker and docs. Tests are prohibited by the parent task constraint; root performs compile-only integration.

**Goal:** Merge common Mach-O string and scalar literal sections into the existing read-only output section with correct relocation and symbol mapping.

**Architecture:** Replace the single optional const-section fields on each object with a list of read-only contributions keyed by source section ordinal. Align and append each contribution to the global const image, then route symbol and relocation address resolution through that mapping. Keep the emitted executable's one read-only `__const` section and reject unsupported source sections.

**Tech Stack:** C++20, existing Mach-O metadata reader, `link_macho64_executable`.

**Spec:** `docs/superpowers/specs/2026-10-24-macho-readonly-contributions.md`

## Global constraints

- Do not add or run tests.
- Do not build or access `out/`; root owns compile-only verification.
- Preserve output bounds and cancellation checkpoints.
- Do not modify the root capability ledger or broader plan.

## Review focus

- `__cstring` must be recognized by exact segment/name/type and end with NUL.
- Literal sections must have correct S_4BYTE/S_8BYTE/S_16BYTE_LITERALS type and whole elements.
- Contributions must not overlap; output offsets must honor each alignment and combined resource limits.
- Symbol values and relocation places/targets must resolve through source section ordinals.
- Unsupported/unmapped source sections remain explicit failures.

### Task 1: Generalize read-only section contributions

**Files:** `libs/loaders/src/macho_link.cpp`, `libs/loaders/include/hexlab/loaders/macho_link.hpp`, `docs/macho-static-linking.md`

- [x] Add a read-only contribution record retaining source ordinal, output offset, size, alignment and copied bytes.
- [x] Select exact `__TEXT,__const`, `__cstring`, `__literal4`, `__literal8`, and `__literal16` contributions and validate section kinds, payload extent, literal element size, and cstring termination.
- [x] Merge contribution bytes with checked alignment and total size limits.
- [x] Route defined symbols, relocation source places, and relocation targets through section ordinal contribution lookup.
- [x] Update public linker documentation with merged output behavior and explicit unsupported section classes.
- [ ] Perform source review and whitespace checks; root compiles `hexlab_loaders` Debug. No tests added or run.

