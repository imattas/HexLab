# ARM64 PE Exception Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse ARM64 PE `.pdata` packed, unpacked, and linked records and use validated function starts as provenance-bearing analysis roots.

**Architecture:** Add ARM64-specific public metadata alongside the AMD64 runtime-function structure. Extend the PE exception-directory parser with an ARM64 branch that validates the complete table before publishing it, then feed ARM64 rows into the existing unwind-seed provenance contract. Keep malformed directory handling in the existing PE loader boundary.

**Tech Stack:** C++20, existing PE `ImageReader` and `Result` helpers, current loader and analysis tests, CMake/CTest.

**Spec:** `docs/superpowers/specs/2026-10-22-arm64-pe-unwind-design.md`

## Global Constraints

- Support only PE32+ machine `0xaa64` for this ARM64 format.
- A `.pdata` row is exactly 8 bytes and tags are the low two bits of its second word.
- Reject malformed table metadata atomically without rejecting otherwise usable image bytes.
- Require every accepted function range to be in initialized executable bytes.
- Preserve source byte spans and use the image's loaded base for function roots.
- Keep AMD64 parsing behavior and public metadata compatible.
- Do not modify processor headers/dispatch/format, decompiler files, shared CMake, capability matrices, or reference matrices.

## Review Focus

- Large but bounded counts or xdata extents: test record-budget and image-bound checks.
- Xdata scopes with no code array, or extension headers whose extended counts are empty: test they are rejected as malformed.
- Epilog scopes with invalid ordering, reserved bits, or code indexes: test each invalid class.
- Unwind byte stream with a truncated multi-byte opcode or reserved opcode: test rejection.
- Pdata links that point into the middle of a row or form cycles: test exact row alignment and cycle checks.

---

### Task 1: ARM64 PE metadata and table fixtures

**Files:**
- Modify: `libs/image/include/hexlab/image/pe_metadata.hpp`
- Test: `tests/pe_exception_tests.cpp`
- Modify: `tests/support/pe_fixture.hpp` only if the existing fixture cannot express ARM64 machine/sections cleanly.

**Interfaces:**
- Produce architecture-specific `PeArm64RuntimeFunction`, packed-unwind fields, xdata header/scope/code metadata, optional handler metadata, and pdata-link metadata, each with default structural equality and `PeRecordSource` provenance.
- Add `PeMetadata::arm64_exception_functions` without changing `exception_functions`.

- [x] Add fixture helpers and tests for packed tag 1/tag 2 records, xdata tag 0 with inline and extended header, and link tag 3; assert initial parse is incomplete until loader support exists.
- [x] Run `hexlab_pe_exception_tests` to confirm the new fixture cases expose missing metadata.
- [x] Add the metadata structures with fields pinned by those assertions.
- [x] Rebuild and confirm existing AMD64 metadata equality tests remain green.

### Task 2: Bounded ARM64 `.pdata` and `.xdata` parsing

**Files:**
- Modify: `libs/loaders/src/pe_exceptions.cpp`
- Test: `tests/pe_exception_tests.cpp`

**Interfaces:**
- Consume `ImageReader`, directory metadata, and the Task 1 structures.
- Add `read_arm64_exception_directory` internal implementation, dispatched from `read_exception_directory` for machine `0xaa64`.

- [x] Add tests for packed field extraction, xdata lengths/scopes/code boundaries/handler RVA, link resolution, source spans, and rebased executable function extents.
- [x] Run the focused test and confirm these cases fail before implementation.
- [x] Implement checked 8-byte row parsing, table sorting, code-range mapping, packed fields, bounded version-zero xdata, opcode length decoding, and parent-row link resolution; keep all results local until the full directory validates.
- [x] Add malformed and atomicity cases for the Review Focus inputs, unsupported versions/opcodes, handler failures, and invalid mapped ranges.
- [x] Run the focused test and verify all valid and malformed cases pass.

### Task 3: Provenance-bearing function roots

**Files:**
- Modify: `libs/analysis/src/functions.cpp`
- Test: `tests/pe_exception_tests.cpp`

**Interfaces:**
- Consume `PeMetadata::arm64_exception_functions` and existing `FunctionSeedKind::unwind` / `FunctionSeedUnwindEvidence`.
- Store the pdata ordinal, first backing file offset, and eight-byte row extent in the existing unwind evidence fields.

- [x] Assert ARM64 `.pdata` roots carry `FunctionSeedKind::unwind`, exact row evidence, and loaded-base-adjusted virtual addresses.
- [x] Verify malformed metadata contributes no partial roots and existing roots remain present.
- [x] Run focused PE exception and analysis tests; no derived-cache schema update is expected because the existing unwind evidence format is reused.

### Task 4: User-facing coverage documentation and isolated verification

**Files:**
- Create: `docs/arm64-pe-unwind.md`
- Modify: `docs/pe-exception-directory.md`
- No CMake edits; root owns shared target registration.

- [x] Document supported tags, normalized metadata, source provenance, bounds, root behavior, and runtime-unwinding limits.
- [x] Configure a fresh isolated tree at `agent-arm64-pe-unwind-build` with repository defaults needed for `hexlab_pe_exception_tests`.
- [x] Build `hexlab_pe_exception_tests` and run `ctest -R "^pe_exception_analysis$"`; report the exact command and result to the parent.
