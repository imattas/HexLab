# ELF32/ELF64 loading and analysis design

## Intent and authorization

Continue the original IDA-class C++20/wxWidgets multi-tool/DLL monorepo with native ELF loading, analysis and persistent workflows. The user's standing instruction forbids further approval questions. Retain architectural design, inline implementation, tests and final review; proceed without approval/check-in/menu pauses. This stage advances the full goal and does not replace its remaining requirements.

The preceding segmented stage is accepted; preserve its source behavior and `out/install/SegmentedDebug`, `X86ModeDebug` and `ProjectAnalysisDebug` baselines. Existing unborn `feat/foundation` has no base/identity; do not invent commits or perform cleanup.

## Choices and selected architecture

Three alternatives were considered: use a foreign ELF parsing library; add a CLI-only parser detached from the shared project service; or build an original bounded loader atop ByteStorage, Image and the shared recipe path. Select the third, consistent with the existing original PE/raw engines. It costs parser/test work but gives every frontend the same authoritative mappings and persistence. No new production dependency.

ELF executable/shared-object mappings derive from PT_LOAD, not section addresses. Relocatable objects have no final linked address: allocated sections occupy stable distinct AddressSpaceIds equal to their nonzero section indexes and section-relative offsets. No fabricated contiguous linked address or relocation application. Primary space0 remains available as the container default; a REL function seed must identify its section domain. Symbol/relocation provenance must retain original table/index/section identity.

## Container parsing

Provide an original checked ELF header API supporting class32/64 and little/big endian. Read fixed scalar fields rather than native struct casts. Require full magic, supported class/data/version, correct ELF header size, and sufficient program/section entry stride when present; allow extra bytes in larger entry strides. Ignore reserved identification padding. Recognize REL=1, EXEC=2, DYN=3; core and OS/processor-specific object types are reported unsupported by the loader rather than guessed. Class width is container width, not a promise of decoder availability.

Resolve extended section count (`e_shnum=0` with a section table), section-name index (`SHN_XINDEX`) and program count (`PN_XNUM`) from section0, validating its null type and table bounds before reading. Distinguish no section table from extended count. Reject inconsistent offsets/counts, absent carriers, out-of-file extents, multiplication/addition overflow and unsupported field versions. Counts bounded to65536 program headers and1048576 section headers; overall metadata bytes64MiB. Cancellation before I/O and between bounded loops; allocation failure becomes resource_limit. Do not read/allocate the complete source file.

## Mappings and context

EXEC/DYN use declared virtual coordinates with no ASLR/load-bias guess. Validate file_size<=memory_size, address/file extents, power-of-two alignment (0/1 unconstrained), congruence and declared class width. Empty memory spans do not own bytes. BSS is readable zero-filled memory with no canonical file offset; gaps stay unmapped. Normalize compatible overlapping PT_LOAD intervals with identical file provenance and compatible zero-fill; union permissions. Conflicting initialized bytes/backing or zero-fill provenance is an explicit unsupported/malformed diagnostic, never chosen silently. Entry0 means absent; nonzero entry must be mapped executable initialized memory or receive an honest diagnostic with no invented function seed.

REL maps SHF_ALLOC PROGBITS/NOBITS-style sections into section domains using their flags/alignment and full64-bit sizes; nonallocated debug/string/symbol tables remain metadata/file data. Retain all section declarations separately from PE's32-bit RVA records. Compressed sections and processor extensions stay typed/diagnosed unsupported until implemented; never decode compressed bytes as executable code.

EM_386 with ELFCLASS32 little endian selects x86_32; EM_X86_64 with ELFCLASS64 little endian selects x86_64. Recognized ARM/AArch64 can retain architecture with unknown execution mode until processor stages exist. Other machine/class/endian combinations remain inspectable with unknown context and explicit analysis stops. Do not label an unknown machine x86 by width.

## Metadata and analysis

Append optional typed ELF metadata to ImageMetadata, preserving existing members and old serializers. Include ELF identity/header, section headers, symbol table records (binding/type/visibility, raw value/size/index, optional resolved Address), needed libraries/dynamic tags and relocation rows. Never squeeze ELF64 addresses into PE RVA/ordinal structures. Move the shared LoadedImage definition into a generic header, preserving the old pe.hpp include API.

Read SYMTAB/DYNSYM using linked bounded STRTAB; support extended symbol section indexes through SYMTAB_SHNDX. Validate entry strides/divisibility, string offsets/termination, section indexes and symbol extents. Undefined, absolute, common and TLS symbols retain their distinct states. Seed only valid initialized executable FUNC definitions; preserve local symbols for presentation without treating all symbols as exports. Resolve names by full space/offset identity. Symbol naming must not override user annotations.

Parse REL/RELA entries with exact class-specific info fields and signed addends. Preserve relocation type/symbol/table/place/addend and unresolved reasons; no runtime relocation execution or source patching. Known x86 absolute/PC-relative/import relocation facts can drive provenance-labelled references when authoritative. Unsupported TLS/IFUNC/versioned/runtime resolution remains symbolic. Dynamic tables work without sections where bounds can be derived from PT_DYNAMIC plus validated mapped ranges; never scan unbounded hash/symbol memory. Record DT_NEEDED and bounded interpreter names; no host library loading.

Metadata reads must enter ReadSet so header/table/string patches invalidate affected derivations. All ELF source identities, recipes and fact adoption use existing revisions/cache contracts. Extend canonical cache/reference formats if new typed facts require it, retaining genuine old-cache recomputation and user history. Metadata absence/partial decoding must remain explicit.

## Frontends and persistence

Append Format::elf and DetectedFormat::elf_candidate preserving enum ordinals. Full four-byte magic selects ELF candidate, and malformed candidates do not fall back to raw/PE. Automatic and explicit `--format elf` share load_image and worker opening. Durable ELF recipe gets a new unambiguous tag while old PE/raw/segmented recipe bytes remain unchanged. Centralize automatic format resolution used by import/CLI/desktop to avoid PE-only branches.

CLI inspect/disassemble/project creation expose class/order/type/machine, sections, symbols, dynamic dependencies and relocations with safe escaping. Native menus/drag-or-command-line binary opening use the shared worker; inspectable ELF metadata and function/reference navigation work for32/64 executable and REL domain fixtures. User names/comments/patches/code decisions/history, exact export, SaveAs, source-missing readonly reopen and cancellation remain required. Zero-fill patches reject file-less addresses; never write original sources. No parsing/I/O/SQL/decoding in GUI handlers.

## Verification and delivery

Literal independent fixtures cover32/64 both endian, EXEC/DYN/REL, sparse/BSS/aliases, sectionless dynamic input, extended counts, large addresses/strides, table/string overflow and truncation/cancellation. Host tools (LLVM llvm-readobj/readelf or equivalent) independently inspect authored fixture bytes and compiler-generated ELF objects; tools are test-only and inputs never executed. Missing oracle is a failure, not a silent skip. Pin observed tool provenance and record limits.

Use RED/GREEN for each implementation contract; rebuild all consumers on public layout changes. No edits to shared source/header/CMake while dependent builds/tests run. No simultaneous Debug/Release builds in one tree. Full headless Debug/Release, desktop, fresh disconnected and production BTOFF gates; installed new `out/install/ElfDebug` multi-file bundle with SDK/CLI/native/module-path checks. One fresh independent read-only whole-stage review, regrade/fix material findings with affected proof, retain scoped limitations. Do not overwrite accepted installation baselines.

## Scope continuity and references

Full DWARF/type import, runtime dynamic linking, core-dump debugging, all machine psABI variants and Linux/macOS shipping remain subsequent full-goal requirements; metadata containers and unknown states must allow those extensions. This stage must deliver actual ELF frontend/project workflows, not just a magic check or header parser.

Primary references inspected2026-10-20: [gABI ELF header](https://gabi.xinuos.com/elf/02-eheader.html), [sections](https://gabi.xinuos.com/elf/03-sheader.html), [symbols](https://gabi.xinuos.com/elf/05-symtab.html), [relocations](https://gabi.xinuos.com/elf/06-reloc.html), [program loading](https://gabi.xinuos.com/elf/07-pheader.html), [dynamic linking](https://gabi.xinuos.com/elf/08-dynamic.html). Processor-specific relocation semantics require primary psABI references before implementation.
