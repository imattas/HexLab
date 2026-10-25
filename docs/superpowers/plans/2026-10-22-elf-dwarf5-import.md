# ELF DWARF v5 Type and Prototype Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import a bounded, practical DWARF v5 subset from ELF into the existing symbol/type/prototype model while preserving v4 behavior.

**Architecture:** Add a version-aware DWARF section bundle and decode v5 CU headers/forms in `hexlab::symbols`; have the ELF loader provide the additional indexed-string/address sections. Keep unit/form parsing bounded and use existing type resolution and result records. The independent v2–v5 line importer remains the source-line path.

**Tech Stack:** C++20, existing `hexlab::symbols`, `hexlab::loaders`, `hexlab::types`, and CTest.

**Spec:** `docs/superpowers/specs/2026-10-22-elf-dwarf5-import-design.md`

## Global Constraints

- Preserve v4 behavior and the `import_dwarf_v4` entry point.
- Keep ELF DIE import little-endian and report unsupported data explicitly.
- Validate all section/contribution bounds and honor cancellation.
- Publish no partial `ImportResult` after malformed input.
- Do not edit shared CMake files, README, `docs/capabilities.csv`, or `docs/reference-matrix.csv`.

## Review Focus

- v5 header unit type and optional fields: test ordinary compile units and reject unsupported kinds without reading beyond the unit.
- Indexed strings: test contribution header/version/width, out-of-range index, and unterminated target string.
- Indexed addresses: test base arithmetic and out-of-range index without inventing an address.
- v4 regression: run current type/prototype and malformed-reference cases unchanged.
- ELF integration: verify malformed v5 metadata leaves the ELF image loadable with no published partial DWARF result.

---

### Task 1: Version-aware v5 section API and unit decoding

**Files:**
- Modify: `libs/symbols/include/hexlab/symbols/dwarf.hpp`
- Modify: `libs/symbols/src/dwarf.cpp`
- Test: `tests/symbols/dwarf_extended_tests.cpp`

**Interfaces:**
- Produces `DwarfSections` with borrowed spans for info, abbrev, strings, string offsets, addresses, and optional line strings; `import_dwarf` accepts it.
- `import_dwarf_v4(const DwarfV4Sections&)` remains source-compatible and delegates to the shared v4 path.

- [x] Add a generated v5 compile-unit fixture using `DW_FORM_implicit_const` and inline/data forms; assert base-type and function prototype imports.
- [x] Run the focused test and confirm the v5 call fails before implementation.
- [x] Decode the v5 header fields inside the existing unit extent and retain version/form context for abbreviation and DIE decoding.
- [x] Add truncated-header and unsupported-unit-type tests; verify malformed/unsupported classifications.
- [x] Run `hexlab_dwarf_extended_tests` and existing symbols tests.

### Task 2: Indexed string and address forms

**Files:**
- Modify: `libs/symbols/src/dwarf.cpp`
- Test: `tests/symbols/dwarf_extended_tests.cpp`

**Interfaces:**
- `DwarfSections` section spans from Task 1 are consumed by bounded indexed-form resolution.
- Abbreviation decoding retains `DW_FORM_implicit_const` values; DIE attributes use an internal unresolved indexed-value representation until CU root bases are known.

- [x] Add a v5 fixture using `DW_FORM_strx1` for a CU name/type name and `DW_FORM_addrx1` for a subprogram low PC; assert exact imported names/address.
- [x] Add negative tests for truncated headers, unsupported unit type, and out-of-range index.
- [x] Decode string-offset and address contribution headers and resolve only entries wholly contained by the declared contribution/section.
- [x] Resolve indexed attributes after reading the CU root base attributes; reject unresolved indices rather than guessing.
- [x] Run `hexlab_dwarf_extended_tests` and `git diff --check`.

### Task 3: ELF section wiring and end-to-end regression

**Files:**
- Modify: `libs/loaders/src/elf_dwarf.cpp`
- Modify: `libs/image/include/hexlab/image/elf_metadata.hpp`
- Modify: `tests/support/elf_dwarf_fixture.hpp`
- Modify: `tests/elf_image_tests.cpp`
- Modify: `docs/dwarf-v4-import.md`
- Create: `docs/dwarf-v5-import.md`

**Interfaces:**
- ELF loader supplies optional `.debug_str_offsets`, `.debug_addr`, and `.debug_line_str` spans to `symbols::import_dwarf`.
- Existing `ElfMetadata::dwarf_info` storage and project command interfaces remain unchanged.

- [x] Extend the generated ELF fixture for a v5 CU and assert the loader exposes its type, prototype, and mapped function symbol.
- [x] Add a malformed v5 ELF case asserting normal ELF load success, incomplete metadata diagnostic, and absent `dwarf_info`.
- [x] Preserve existing tests for the standalone v5 line-table parser and its header/opcode path.
- [x] Wire optional sections with duplicate/compressed/NOBITS behavior consistent with current debug sections.
- [x] Document supported v5 forms and remaining unsupported cases.
- [x] Build and run focused symbol/ELF/project-command tests in a fresh isolated build directory; capture exact CMake commands/results for root integration.

### Follow-up: standalone DWARF v5 type units

- [x] Add a generated type-unit fixture with its signature and unit-relative type offset; assert imported type identity and size.
- [x] Reject truncated type-unit headers and type offsets that do not identify a type DIE.
- [x] Permit a type DIE as the type-unit root while preserving the compile-unit root invariant for ordinary units.
- [x] Document that signature-based cross-unit lookup and skeleton/split units remain unsupported.

## CMake integration report

No CMake edits are part of this patch. Existing registration already builds `hexlab_dwarf_extended_tests` from `libs/symbols/CMakeLists.txt` and `hexlab_elf_image_tests` from `tests/CMakeLists.txt`; report those exact target/test registrations to root for integrated build selection.
