# Mach-O compact unwind function roots

**Goal:** Read bounded `__TEXT,__unwind_info` compact-unwind indexes for supported 64-bit Mach-O images and feed their linker-declared function starts into the existing Mach-O root model.

**Architecture:** Keep the current `MachOMetadata::function_starts` consumer contract so analysis and reachability get roots without new persistence formats. Add typed compact-unwind index/page metadata only within Mach-O metadata; derive roots from validated second-level entries. Treat encoding words as opaque. Parse only little-endian x86_64 and arm64/arm64e linked images, and mark unsupported architectures incomplete while rejecting malformed declared sections.

**Files:** `libs/image/include/hexlab/image/macho_metadata.hpp`, `libs/loaders/src/macho_commands.cpp`, `tests/macho_command_tests.cpp` plus fixture helper if needed, `docs/macho-analysis-validation.md` or focused `docs/macho-compact-unwind.md`.

## Test-first tasks

- [x] Add synthetic x86_64 and arm64 Mach-O images with `__unwind_info` headers, one-level index, regular and compressed second-level pages, sentinel row, and known function offsets. Assert each executable entry becomes a function start and records preserve page/index source offsets and opaque encoding.
- [x] Add rejection tests for unsupported versions and page kinds, out-of-range function entries, and page records crossing the declared section extent.
- [x] Run the test target first to observe missing compact-unwind metadata/roots, then implement bounded parser with cancellation, reader checks, resource budgets, and checked relative-address mapping.
- [x] Verify x86_64 compressed and arm64 regular-page roots are consumed by function recovery; isolated Debug CTest passed `macho_commands`, `macho_headers`, `macho_images`, `macho_symbols`, `macho_relocations`, `macho_dyld`, and `functions` (7/7).
- [x] Document support and limits: linked 64-bit little-endian x86_64/arm64 section-based compact unwind v1; opaque encodings only; no DWARF FDE parsing from LSDA, no runtime stack unwinding, no 32-bit, big-endian, or object-file contribution merging.





