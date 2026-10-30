# ar archive validation

## AIX big archive listing

The loader also recognizes the AIX `<bigaf>\n` format. It validates the
128-byte fixed header, walks the live member chain using the declared next and
previous offsets, checks even-byte alignment, bounded names and payload
extents, and retains the member table and 32-/64-bit symbol-table members as
special entries. `archive list` labels the format as `AIX big ar`; ordinary
members can be opened or extracted through the normal bounded archive APIs.
The 32-bit and 64-bit global symbol tables are decoded using their 8-byte
big-endian symbol counts, member-header offsets, and sequential NUL-terminated
symbol names. Both tables share the archive's 256 MiB symbol-index budget and
the configured symbol/name limits. Entries are resolved through the validated
member-header chain; unknown offsets and special-table references leave the
index incomplete while valid rows remain available. `lookup_ar_member_by_symbol`
and the desktop/CLI symbol inventory can use these rows. A bounded XCOFF64
relocatable-object summarizer validates big-endian file, section, symbol, and
string-table extents and extracts external definitions and strong undefined
symbols. `archive link-select <archive> --root-object <XCOFF64>` uses those
summaries for fixed-point member selection from AIX big and other ar archives,
reporting trigger and unresolved symbols. This is selection evidence only: XCOFF
linking, relocation application, optional-header objects, and XCOFF32 remain
unsupported.

`archive link-audit <archive> --root-object <XCOFF64>` adds a bounded structural
relocation and selected-object symbol-provider report. Recognized type names
remain unapplied; unknown relocation types and loader-section encoding remain
explicitly unsupported. See the [XCOFF64 audit subset](xcoff64-object-inventory.md)
for limits, deferred cases and the `link-readiness=not-established` contract.

The fixed-header offsets, linked member layout, name padding, and payload
alignment follow the [IBM AIX big ar format](https://www.ibm.com/docs/en/aix/7.1.0?topic=formats-ar-file-format-big).

HexLab detects standard, GNU thin, and AIX big ar signatures automatically. `Format::ar` has a canonical durable load recipe, and `load_archive` returns a `LoadedArchive` that retains the source storage and bounded member index. It indexes standard `!<arch>\n` archives and GNU thin `!<thin>\n` archives with bounded 60-byte member-header parsing, decimal member sizes, even-byte padding, GNU `//` long-name tables and `/offset` references, BSD `#1/length` inline names for regular archives, and GNU 32-bit `/` symbol indexes. Thin archive member rows retain their stored path, declared external size, and header metadata; embedded symbol-index and long-name records are parsed normally. GNU thin member paths are not opened or resolved against the archive directory automatically. Listing works directly; caller-supplied resolvers support member reads and extraction, and resolved object summaries support fixed-point member selection as described below. BSD inline-name records in GNU thin archives are rejected explicitly. Header timestamp, uid, gid, and octal mode are parsed with checked numeric conversion and retained on every `ArMember`; `archive list` prints these fields, including mode in octal. GNU long-name offsets must point at the beginning of a table entry, preventing malformed offsets from exposing arbitrary suffixes of another filename as member names. The returned member list retains special records and records payload offsets separately from header offsets. GNU symbol rows resolve to the corresponding regular or external thin member by header offset.

`open_ar_member` exposes a regular member as zero-copy, bounds-checked `ByteStorage`, which existing PE/ELF loaders can consume directly. `summarize_elf_ar_member` reads ELF `ET_REL` section and symbol tables and produces the `ArMemberSymbols` input for the fixed-point selector. It supports ELF32/ELF64 in either byte order, includes global/weak/GNU-unique definitions, includes strong undefined globals, and omits weak undefineds because they do not cause conventional archive extraction. It applies section, symbol, name, and cumulative metadata limits and checks cancellation while scanning. `select_ar_members` maps an unresolved symbol set to deterministic regular-member indices using first-indexed-definition order, removes duplicate requests/member selections, and returns unresolved names and index completeness to the caller. `select_ar_members_fixed_point` repeatedly chooses the earliest eligible summarized member, feeds its undefined references back into the pending set, and rescans until no more members match. It reports unresolved symbols and per-member trigger symbols, and accepts cancellation plus member/work limits. Copying extraction validates the extent, enforces a configurable output limit, rejects members exceeding host vector capacity before allocation, converts allocation failures to resource-limit errors, reads in bounded chunks, and honors cancellation between chunks. Parsing bounds member count, name lengths, symbol count, index allocation, and GNU long-name table allocation. Malformed archive headers, name references, extents, and missing padding are rejected. Malformed or over-budget GNU and BSD symbol-index payloads instead mark the index incomplete and add a diagnostic; regular-member listing/extraction remains available. Rows that reference unknown or special members are skipped and also mark the index incomplete.

GNU 32-/64-bit and BSD ranlib index payloads share a 256 MiB cumulative read
budget per archive, and decoded symbol rows share `ArLimits::max_symbols`.
If an index exceeds either remaining budget or has a malformed layout, the
loader marks index completeness false, reports a diagnostic, and keeps valid
member listing/open/extraction available. Index rows that exceed the remaining
symbol count are skipped as a whole; they do not partially contribute lookup
results. This prevents multiple individually bounded index records from
exceeding the archive-wide metadata limits.

`lookup_ar_member_by_symbol` provides a single-symbol query over the same parsed
index. It chooses the earliest provider by archive member order, independently
of symbol-index row order, and returns the unique ordered
`candidate_member_indices` to retain duplicate-provider provenance. The
corresponding `ArMember` retains its decoded name and raw header/data file
offsets. The result separately reports whether the archive had a symbol index
and whether parsing deemed that index complete, so callers can distinguish a
complete miss from an absent or partially malformed BSD ranlib index. The
multi-symbol selector applies the same earliest-member rule for duplicate
provider rows. Empty requests and malformed in-memory symbol rows are rejected.

The desktop **Browse ar Archive** dialog lists archive members and a second indexed-symbol table. Each symbol row shows the member name and stable archive member index; selecting a symbol also selects its member, which can then be opened. The status line distinguishes archives without a supported index from incomplete indexes, so an empty symbol table does not imply the archive has no object members.

GNU 32-/64-bit indexes and BSD 32-/64-bit `__.SYMDEF` ranlib tables are decoded with bounded metadata reads. BSD word order is selected by validating the table shape (little-endian first, then big-endian), and all symbol rows resolve through archive member header offsets. Unsupported or malformed BSD index layouts leave member browsing available and produce a diagnostic. `hexlab_cli archive list` prints indexed symbols with their member index and member name, and `archive open` imports a selected regular member into a project. `hexlab_cli archive link-select <archive> --root-object <ET_REL>` summarizes the root object and ELF archive members, selects members to a fixed point, and prints trigger symbols and unresolved names. `archive link-audit` reports each selected relocation's type, symbol, and provider without producing output. `archive link <archive> --root-object <ET_REL> --output <ET_REL>` applies a bounded linker subset and writes a combined ELF64 little-endian x86-64 relocatable object. The linker concatenates executable `.text`, optional read-only `.rodata`, optional writable initialized `.data`, and optional writable zero-filled SHT_NOBITS `.bss` sections per object with section alignment, preserves each output section's maximum input alignment in the section and file layout, resolves strong/weak global symbols, rejects unresolved strong references, and applies supported `.text`, `.rodata`, and `.data` RELA types R_X86_64_NONE, 64, PC32, PLT32, 32, 32S, PC64, 16, PC16, 8, and PC8 with checked overflow and narrow-field range checks. Relocation places and local/global definitions are rebased within their merged output section, so a `.data` relocation can reach a symbol in another object's `.data` as well as `.text`. Local and global symbols from all merged output sections receive rebased values and section indices. It rejects other architectures, allocated sections outside `.text`/`.rodata`/`.data`/`.bss`, non-RELA records, unsupported relocation kinds, duplicate strong definitions, and out-of-range relocation fields. TLS, COMDAT, and non-alloc debug sections remain unsupported. ELF `SHN_COMMON` definitions are coalesced into merged `.bss` using maximum size and alignment; strong definitions take precedence over common and weak definitions, while common definitions take precedence over weak definitions. Archive member summaries treat common symbols as definitions for fixed-point selection. Allocated SHT_NOBITS `.bss` sections are merged into a zero-filled output section; symbols and relocations from `.text`/`.rodata`/`.data` may target `.bss`, while relocations stored inside `.bss` remain unsupported. `hexlab_cli archive link-pe <archive> --root-object <COFF .obj> --entry <symbol> --output <PE .exe>` selects COFF archive members to a fixed point and links ordinary AMD64 objects into a static PE32+ console image. Initialized `.text`/`.rdata`/`.data` and zero-filled `.bss` are merged; references to BSS symbols are relocated, but relocations stored inside BSS remain unsupported. COFF common symbols coalesce by name into zero-filled `.bss`, using natural alignment capped at 32 bytes; selected strong section definitions take precedence. The archive summary treats common symbols as definitions so a needed member can be selected. COFF linking still omits imports, TLS, unwind metadata, base relocations, weak external aliases and CRT support. Mach-O link output is unsupported. ELF archive selection skips non-ELF members. Archive mutation and symbol-index rebuilding are not supported.

Validation: `tests/ar_loader_tests.cpp` covers format detection, durable recipe round-tripping, retained archive storage/member listing, bounded member `ByteStorage` views consumable by the existing raw image loader, GNU and BSD name forms, GNU and BSD 32-/64-bit symbol-to-member resolution, requested-symbol selection, fixed-point transitive dependency selection with provenance, ELF32 and ELF64 `ET_REL` summaries in both byte orders (including weak-undefined filtering and symbol limits), extraction, truncated extents, invalid trailers, configured limits, and pre-requested cancellation. `tests/archive_cli_tests.cmake` and its ELF fixture/verifier scripts confirm fixed-point extraction, audit output, successful transitive x86-64 archive links with merged writable data and rebased symbols, PC32 relocations into both merged `.text` and `.data` (including a data-to-data reference resolved from a later archive member), valid emitted ET_REL sections, and rejection of strong unresolved symbols, unsupported relocation types, and out-of-bounds relocation fields.

Ordinary COFF archive objects can also be summarized with `summarize_coff_ar_member` and passed to the existing fixed-point selector. The reader checks 20-byte headers, 40-byte section records, 18-byte symbol/auxiliary rows, string-table size and names, cancellation, and configured metadata/section/symbol/name limits. It classifies section/absolute external definitions, COFF common symbols, and zero-valued unresolved references, filters references resolved by same-object definitions, and skips each symbol's declared auxiliary rows. Common symbols in the linked PE are coalesced by name using the maximum declared size; their BSS allocation uses MSVC-compatible natural alignment, rounded up to a power of two and capped at 32 bytes, while any selected strong definition supersedes the common allocation. This alignment rule matches the LLD COFF implementation ([`CommonChunk`](https://chromium.googlesource.com/external/llvm.org/lld/%2B/refs/heads/master/COFF/Chunks.cpp#588)). Bigobj and import-object/short-import records remain unsupported. COFF archive member selection and PE32+ link output are available through the bounded CLI path described above. The COFF summary fixture checks symbol classification, aux-row skipping, symbol limits, malformed aux counts, and cancellation. The archive CLI fixture exercises COFF member selection, initialized data, zero-filled BSS, relocations to BSS, emitted PE section metadata, and rejection of a symbol value beyond its section extent. COFF section-definition auxiliary lengths are checked against section-header lengths; a symbol at the exact section end is allowed for one-past-end references.

## ELF32 i386 static archive linking

`hexlab_cli archive link <archive> --root-object <ET_REL> --output <ET_REL>` also accepts homogeneous ELF32 little-endian i386 relocatable objects. The fixed-point archive selector feeds the selected root and members to `link_elf32_i386_text`, which merges allocated `.text`, `.rodata`, `.data`, and zero-filled `.bss` sections with checked power-of-two alignment, including multiple same-category sections and compiler section-suffix forms such as `.text.*`, `.rodata.*`, `.data.*`, and `.bss.*`. Per-object source offsets are tracked separately from final merged offsets so local relocations and section copying retain the right contribution. It resolves strong/weak definitions and coalesces common symbols into `.bss`. It applies `SHT_REL` `R_386_NONE`, `R_386_32`, `R_386_PC32`, `R_386_PLT32`, `R_386_16`, `R_386_PC16`, `R_386_8`, and `R_386_PC8` relocations using validated in-section implicit addends. The narrow absolute forms truncate `S+A` to the encoded 16- or 8-bit field; narrow PC-relative forms sign-extend their stored addend and require the final displacement to fit the signed field. `R_386_PC16` and `R_386_PC8` are accepted only when source and target belong to the same merged output section; 16-bit segment-wrap cases are rejected instead of guessing a segment base. Unsupported allocated section layouts, relocation kinds, malformed fields, unresolved strong symbols, and out-of-range PC-relative results fail before the CLI publishes output. This path emits an ELF32 `ET_REL`; i386 executable output, big-endian objects, GOT/TLS/COMDAT, and relocation types outside the listed subset remain unsupported. These narrow relocations are documented in the [System V i386 ABI](https://www.uclibc.org/docs/psABI-i386.pdf), which notes that they are nonconforming and retained for documentation/legacy 16-bit use.

## AArch64 static archive linking

`archive link`, `archive link-exec`, and `archive link-audit` also support ELF64 little-endian AArch64 objects. The root object's ELF machine selects the linker; every selected member must match that machine, class, byte order, and relocatable object type. The existing bounded fixed-point selector supplies transitive members, and the shared section layout and strong/weak symbol resolution apply to both architectures. The public library entry points are `link_elf64_aarch64_text` and `link_elf64_aarch64_executable`; the x86-64 entry points retain their architecture checks.

The AArch64 subset applies RELA types NONE (0), ABS64 (257), ABS32 (258), PREL64 (260), PREL32 (261), ADR_PREL_PG_HI21 (275), ADD_ABS_LO12_NC (277), TSTBR14 (279), CONDBR19 (280), JUMP26 (282), CALL26 (283), and LDST64_ABS_LO12_NC (286). Instruction relocations preserve register and opcode bits, validate compatible instruction encodings and four-byte places, and reject misaligned branch or scaled load/store targets. TSTBR14 accepts TBZ/TBNZ and checks the signed 14-bit byte displacement; CONDBR19 accepts B.cond/CBZ/CBNZ and checks the signed 19-bit byte displacement. Checked arithmetic covers branch, page, ABS32, and PREL32 ranges; ABS32 accepts both signed and unsigned 32-bit results. ABS64 stores the low 64 bits, including negative addends. These operations follow the [Arm AAELF64 static relocation definitions](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#static-aarch64-relocations).

AArch64 executable output resolves relocations against final virtual addresses, records `EM_AARCH64`, resolves the requested entry in `.text`, and separates RX, optional R, and RW load segments on 64KiB boundaries. Segment alignment and file/virtual offset congruence accommodate 4KiB, 16KiB, and 64KiB host pages. The default base remains `0x400000`; a caller-supplied base must satisfy 64KiB and the maximum input section alignment. Generated objects and executables are inspected, never run, by the tests; native AArch64 execution has not been validated on this Windows host.

The linked ET_REL form is an analysis artifact using merged section-relative symbol values and already-applied relocation fields. It omits relocation tables, so it is not a general `ld -r` substitute: later links cannot reapply cross-section references after changing section addresses. Use ET_EXEC when references need final virtual addresses. ELF inputs may contain allocated executable `.text`, read-only `.rodata`, initialized writable `.data`, and writable SHT_NOBITS `.bss`; BSS symbols are rebased and `.text`/`.rodata`/`.data` relocations can target them. Executable output maps `.rodata` in a separate read-only PT_LOAD segment when nonempty. Relocations stored inside `.bss` are rejected because it has no input bytes. Executable output represents `.bss` as zero-filled PT_LOAD memory beyond the writable segment's file size. ELF `SHN_COMMON` symbols are coalesced into `.bss` with their maximum size/alignment. This subset does not produce GOT/PLT/TLS structures, process COMDAT or big-endian objects, relax instructions, or generate branch veneers. Out-of-range branches are explicit errors. Mach-O link output remains unsupported; COFF uses the separate bounded PE32+ subset described above.

`tests/archive_aarch64_tests.py`, run by `archive_cli`, generates a root and two transitive ar members and checks the resulting machine, entry, sections, symbols, literal branch/page/low12 encodings, absolute and PC-relative data fields, and RX/RW mapping separation for its no-`.rodata` fixture. It covers mixed architectures, unsupported types, field bounds, incompatible instructions, range/alignment failures, signed boundary values, and output absence after rejected links. When pinned LLVM oracles are enabled, `archive_aarch64_oracle` separately assembles authored AArch64 sources with the pinned clang, links them with LLD using the same final section addresses and `--no-relax`, compares `.text`/`.data` bytes and five symbols, and inspects the output with llvm-readobj. Tool hashes are verified against `tests/fixtures/elf_oracle/tools.json`; command evidence is retained in the build's `tests/archive-aarch64-oracle/<config>/oracle-commands.json`.


## GNU thin archive member resolution

Thin archives retain external member names and declared sizes. The library exposes an opt-in ArThinMemberResolver callback for callers that already have an archive-root/path policy. The loader does not access the filesystem or interpret paths. A resolver result must have exactly the declared member size; extraction still observes the configured byte cap and cancellation token.

For applications that want the standard contained-directory policy, `make_ar_thin_member_resolver(root, limits)` creates a reusable resolver rooted at the explicitly supplied directory. It accepts only valid UTF-8 relative member paths, rejects absolute/rooted paths, drive/stream colons, empty/dot/dot-dot components, and performs no basename fallback or implicit search. Reads use the opened file handle: Windows checks the final handle path remains beneath the opened root (including reparse-point targets), while POSIX walks with `openat` and refuses symlinks in path components. Only regular files are snapshotted. The resolver caches each stored path for its lifetime and enforces configurable cumulative-byte, unique-path, and path-length caps (defaults: 512 MiB, 100,000, and 4096 bytes). `open_ar_member` then verifies the snapshot length exactly matches the archive member's declared size. `extract_ar_member(storage, member, resolver)` applies the same exact-size check, extraction byte cap, bounded reads, and cancellation behavior to a thin external member. Applications with different policies can still supply their own `ArThinMemberResolver`.

The fixed-point selector accepts summaries for both regular and external thin
members. Callers resolve each thin member with the resolver overload of
`open_ar_member`, pass that storage to the appropriate `summarize_*_ar_member`
reader with the original member index, and pass the summaries to
`select_ar_members_fixed_point`. Archive order, transitive undefined-symbol
discovery, selected-for provenance, cancellation and work/member limits apply
equally to both kinds. Special symbol-index and long-name members cannot be
supplied as objects. Selection is independent of the potentially incomplete
archive symbol index and does not open any paths. Callers remain responsible
for architecture filtering and supplying the same resolved object storage to
the chosen linker.

CLI `archive open`, `extract`, `link-select`, `link-audit`, `link`, `link-exec`,
`link-pe` and `link-macho` accept `--thin-root <directory>` after the archive
path. Thin-member reads require this explicit opt-in. Stored member paths are
UTF-8 paths relative to that directory; the CLI never searches the current
directory, archive directory or other directories implicitly. Absolute/rooted
paths, drive/stream colons, NULs and dot/dot-dot components are rejected.
Backslashes are treated as separators. The original stored member name remains
the archive identity, including when the root is separate from the archive's
directory.

`archive extract` resolves only the selected external member, checks its snapshot against the declared member size, then applies the standard extraction byte and output overwrite limits. It does not eagerly read unrelated thin members.

On Windows, the CLI opens the root and member handles, validates the member's
final handle path is below the root's final handle path, and reads from that
same validated handle. A symlink/junction escaping the root is rejected. On
POSIX, directory-relative `openat` walks reject symlinks in every member-path
component. Only regular disk files are accepted. Resolved contents are copied
to immutable command-local snapshots with a cumulative 512 MiB budget and a
100,000 unique-path cap; repeated paths reuse their snapshot, so selection,
audit and link consume the same bytes. The loader still checks each snapshot's
size against its member's declared size. Missing, changed-size or rejected
members fail before publishing output. All external candidates needed for the
existing object-summary scan are resolved, including candidates that selection
eventually does not choose; this is a bounded eager scan, not lazy extraction.
Archive listing remains path-free and needs no root option.

`archive open` imports the selected storage directly and persists
`archive-path!stored-member-name` as its logical source provenance. It no longer
stages a temporary input path. Existing format/machine/linker restrictions still
apply; this path does not add nested archives, unrestricted absolute paths or
GNU thin nested-member references.
