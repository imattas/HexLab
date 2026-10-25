# Mach-O Initialized Data Linking Plan

> **For agentic workers:** Implement the scoped tasks in order. Preserve the active project constraints: do not add or run tests, open/focus the desktop UI, link into the running application, edit shared build lists, or touch `out/`.

**Goal:** Extend the bounded x86-64 static Mach-O archive linker from text-only objects to include initialized `__DATA,__data` contributions and relocation targets, while preserving executable/read-write segment permissions and rejecting unsupported section families.

**Architecture:** Keep object section ownership and per-object merged offsets in `libs/loaders/src/macho_link.cpp`; emit `__text`, `__data`, and zero-fill `__bss` sections in the existing `LC_SEGMENT_64` commands. Keep one RX `__TEXT` mapping and one RW `__DATA` mapping. Resolve external definitions and local section relocations using the owning output section's base and offset. Preserve entry points as `__text` symbols.

**Files:** `libs/loaders/src/macho_link.cpp` owns layout, symbols, and relocation application. `docs/macho-static-linking.md` documents supported input sections and rejections. `docs/capabilities.csv` is root-owned integration metadata.

## Tasks

1. Track each object's bounded initialized text/data sections, align and merge each section family, and collect definitions/relocations from either source. Keep unsupported nonempty input sections rejected.
2. Resolve defined symbols and local/external relocations to merged text or data; emit the matching `n_sect`, segment protections, section addresses/file offsets, and stack state. Check arithmetic and output limits before allocation/writes.
3. Update the focused linker documentation and capability ledger. Compile the changed loader translation unit only; do not run tests.

## Review Focus

- Text PC-relative relocations use RX virtual addresses; data PC-relative and absolute relocations use the correct RW data address.
- Symbols in either merged section retain the correct output section ordinal; entry symbols remain in text.
- Alignment, file/VM extents, relocation fields, and output-size arithmetic remain bounded; unsupported sections still fail closed.

## Progress

- `__DATA,__data` is now an optional initialized contribution. Per-object data offsets honor each input alignment; section and external relocations resolve into either merged text or data; output symbols use the matching section ordinal. `MH_EXECUTE` now emits an RW `__DATA` segment with `__data` and zero-fill stack sections. Other nonempty input sections remain rejected.
- `libs/loaders/src/macho_link.cpp` passed Debug source-only MSVC `ClCompile` with existing C4251 warnings. No tests, links, GUI launches, or `out/` changes.
