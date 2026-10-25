# x64 Shift and Rotate Evaluation Plan

## Ownership

Files: `libs/processors/include/hexlab/processors/x64_semantics.hpp`, `libs/processors/include/hexlab/processors/x64_instruction_semantics.hpp`, `docs/x64-condition-semantics.md`, and this task's SDD artifacts only.

## Tasks

- [x] Define append-only public result types with explicit flag-definedness and unchanged-state reporting.
- [x] Implement operation evaluation for seven scalar shift/rotate operations, including count masks, rotation/carry rings, zero-count preservation, arithmetic sign fill, and undefined cases.
- [x] Add a decoder adapter validating architecture, operand shape/width, and immediate/runtime count source.
- [x] Document supported semantics and explicit limits.
- [x] Review arithmetic boundaries and API use; root compile-only verification succeeded with `hexlab_processors` Debug (MSBuild exit 0). Do not add or run tests.

