# Mach-O `__eh_frame` Encoding Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Decode common absolute and PC-relative DWARF EH pointer encodings in linked 64-bit Mach-O `__eh_frame` and preserve the selected encoding with each recovered FDE.

**Architecture:** Keep section discovery and record bounds in `macho_commands.cpp`. Add a single bounded scalar decoder for the supported DW_EH_PE formats and absolute/PC-relative applications; parse FDE address ranges with only the encoding format bits. Continue rejecting indirect, aligned, text-relative, and unsupported encodings explicitly. Expose the CIE pointer encoding on `MachOEhFrameFunction` so callers can inspect the recipe provenance.

**Tech Stack:** C++20, existing Mach-O loader, image metadata, fixture-driven CTests.

**Spec:** `docs/macho-eh-frame.md`; `docs/capabilities.csv` row `loader.macho`.

## Global Constraints

- Continue to validate every record and encoded field against the selected section.
- Keep `__eh_frame` parsing bounded by the existing 64 MiB metadata budget.
- Do not open the desktop app.
- Do not compile until the parent assigns the shared MSVC build slot.

## Review Focus

- Truncated or overlong ULEB/SLEB values must fail without reading past the FDE.
- PC-relative signed additions must reject underflow/overflow.
- FDE range encodings use the format nibble but not the initial-location application bits.
- Indirect and aligned pointer encodings remain explicit unsupported cases.

### Task 1: Encoding fixtures

**Files:** `tests/macho_command_tests.cpp`

- [ ] Add a `pcrel|sdata8` fixture with an 8-byte signed initial-location delta and 8-byte range.
- [ ] Add an absolute `absptr` fixture with an 8-byte absolute start and range.
- [ ] Assert recovered range, root, and preserved pointer encoding.
- [ ] Add malformed width/overflow or unsupported-application coverage.

### Task 2: Bounded parser support

**Files:** `libs/loaders/src/macho_commands.cpp`, `libs/image/include/hexlab/image/macho_metadata.hpp`

- [ ] Decode the supported fixed-width and ULEB/SLEB DW_EH_PE scalar formats.
- [ ] Apply absolute or PC-relative base semantics only to initial locations.
- [ ] Decode range values with format bits only and preserve the CIE encoding.
- [ ] Keep existing CIE/FDE extent and executable-mapping validation.

### Task 3: Verify and document

**Files:** `docs/macho-eh-frame.md`

- [ ] Document supported and explicitly rejected encodings.
- [ ] Build `hexlab_macho_command_tests` serially after the parent grants the build slot.
- [ ] Run the focused Mach-O command and unwind CTests.
- [ ] Check the scoped diff and report exact commands and limits.
