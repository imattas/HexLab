# Mach-O analysis design

## Intent and scope

Continue the approved original C++20/wxWidgets IDA-class suite in the existing modular monorepo. Mach-O is the next loader obligation in stage4. It must serve the shared analysis/project engines, CLI, native GUI and installed SDK. It does not replace the full objective; ARM/AArch64 decoding, complete debug/types, decompiler, debugger, extension and platform work remain required.

The user supplied standing authorization to proceed without approval prompts. Implement inline, preserving the unborn feat/foundation branch and existing index/source and accepted installations. No commits, destructive cleanup, new production parser dependencies or execution of inputs.

## Architecture and alternatives

Implement an original checked Mach-O loader in hexlab_loaders, with full-width typed metadata in hexlab_image. This keeps parsing and expensive indexing on workers and shares one interpretation across consumers. A foreign parser would add a production dependency and contradict the original-engine requirement; a CLI-only parser would leave projects and native navigation unsupported. Retain the original shared-loader approach despite its greater implementation and validation cost.

## Containers, coordinates and budgets

Support thin32/64 little/big endian and universal FAT32/FAT64 descriptors, including byte-swapped forms. All file coordinates exposed to the host are absolute offsets in the original whole container. Slice-relative fields remain available as raw declarations, with every conversion checked against that slice, never only against the outer file. Nested universal containers, overlapping slices, descriptors overlapping the container table, CPU descriptor/header mismatch, misalignment and incomplete reads fail with checked errors.

Parse at most4096 universal slices,65536 commands per slice and1048576 commands in aggregate. Declared command extents plus universal descriptors share a64MiB budget. Reject excessive counts before allocation or iteration. Mach headers are28/32 bytes; FAT descriptors20/32 bytes; load command envelopes are8 bytes. Commands must be at least8 bytes, aligned to4/8 according to the thin class, wholly within sizeofcmds, and consume exactly that extent. Unknown commands remain raw descriptors; they do not grant support for their semantics. Preserve CPU/subtype/filetype/flags/reserved bits as32-bit values.

`read_macho_container(const ByteStorage&,std::stop_token)` returns `MachOContainer`, containing `MachOSlice` descriptors with parsed `MachOHeader` and `MachOLoadCommand` envelopes. This first layer validates containers and command bounds only. Later command parsers use these checked envelopes and the slice bound. Parsing is cancellable before and between reads and records. Metadata allocations and parsed strings also share the64MiB loader budget.

## Selection and durable recipes

Append Format::macho and DetectedFormat::macho_candidate without moving existing enum ordinals. Append optional MachOOptions{optional<uint32_t> slice_index} to LoadRecipe/OpenRequest. Thin files accept no slice or index0; other explicit indexes fail. Default universal selection prefers a supported little-endian x86_64 slice, then x86, then first declared slice with explicit unsupported context. Expose every descriptor and the selected index; permit explicit --slice in both CLI parsers and a native selection workflow.

Persist the actual selected universal index in the concrete recipe before project import. Existing raw/segmented/PE/ELF recipe bytes stay exact. New Mach-O recipe tag5 uses version1, flag0 for thin and flag1 plus a big-endian uint32 slice index for universal selection. A source patch must revalidate the same slice, not silently select another architecture. Original embedded bytes and history remain authoritative; SaveAs and exports preserve the whole container, including unselected slices.

## Images and symbols

For linked EXECUTE/DYLIB/BUNDLE use LC_SEGMENT/LC_SEGMENT_64 mappings with initialized extents and BSS; no slide is guessed. __PAGEZERO with no access remains reserved/unmapped. Normalize only compatible identical backing overlaps; reject conflicting aliases. Section declarations cannot override segment authority. SG_HIGHVM requires explicit high-placement backing, not low-address assumptions. Unknown CPU/endian combinations remain inspectable without fabricated x86 flow.

For MH_OBJECT give each section ordinal a separate domain with offset0; raw section.addr is retained, and n_value is converted by subtracting that section's declared address. Zero-fill section types do not invent file backing. Handle pure instruction flags and mapped executable sections honestly. Full CPU type remains in Mach-O metadata rather than truncating into the legacy PE machine field.

Bound LC_SYMTAB and nlist32/64/string tables, preserving raw name indexes, names, STAB records, undefined/common/absolute/indirect/section definitions, weak/private-external bits and library ordinals. Do not invent function types absent from nlist. Valid executable definitions, entry declarations, exports and LC_FUNCTION_STARTS may seed analysis. Parse LC_DYSYMTAB ranges/indirect symbols with exact namespace identity. Library commands preserve names, command kinds and ordinal order. Keep unknown/conflicting entry sources explicit. LC_MAIN entryoff is a VM offset from the mapped Mach header, matching dyld; a missing or ambiguous header mapping leaves the declaration unresolved; legacy thread entries are architecture/flavor-specific and checked.

## Relocations and dyld metadata

Preserve original section and dynamic relocation words, scattered forms and pair order. Distinguish object fixups from retained linked static records; linked bytes are not unapplied addends. Implement supported x86/x86_64 relationships from primary declarations, with exact operand encoding match, original symbol/section identity and typed unresolved outcomes for unsupported/ambiguous pairs, GOT/TLV/runtime binding. Do not apply linker bytes or assign host libraries by name. Undefined object calls must not fabricate numeric callee roots.

Parse bounded LC_DYLD_INFO rebase/bind/lazy/weak streams, export tries and LC_DYLD_CHAINED_FIXUPS declarations with checked ULEB/SLEB, offsets, cycle/work budgets and namespaces. Supported static associations carry provenance; unsupported pointer/authentication forms remain unresolved and diagnostically partial. Code signatures and encrypted ranges are declared, not decrypted or claimed authenticated. DWARF/core/fileset/kernel-cache/runtime-link semantics remain later full-goal obligations, with unsupported features explicit.

## Persistence and frontends

Track every interpreted header/command/table/string/addend byte in metadata ReadSet. Patches invalidate appropriate mappings/metadata/analysis and retain old snapshots. Extend canonical cache validation and engine fingerprints for new derived facts; retain genuine older payloads without forged version rewrites. New provenance must own sufficient source/record identity for standalone reference serialization. Preserve ordinary reference IDs.

Expose headers, slices, segments/sections, symbols, relocations, libraries and dyld metadata through worker-owned paged/indexed presentation. Undefined symbols activate their original record. Follow uses source-bound derived targets. Whole-container bytes, explicit domains, slice selection, rename/comment/patch/undo/redo/export/SaveAs/source-missing read-only reopen must work through actual project/CLI/native paths. No GUI parsing, SQL, decoding or large scans.

## Verification and delivery

Use independent literal fixtures for every integer width/order and failure bound, sparse storage for offsets above4GiB, and compiler-generated i386/x86_64/arm64 Mach-O objects. Compare original parser projections to observed test-only LLVM; link Mach-O with test-only ld64.lld where supported, no Apple SDK/runtime dependency or input execution. Record exact tool identities, commands and limitations; missing/mismatching oracle fails rather than skips.

Run full headlessDebug/Release and desktopDebug, disconnected and BUILD_TESTING=OFF production checks; all8 engines remain free of wx/oracle dependencies and production test exports. Install a new MachODebug prefix, never overwrite accepted ElfDebug/SegmentedDebug/X86ModeDebug/ProjectAnalysisDebug. Validate a public installed SDK consumer, actual CLI/native workflows, source-missing caches, all runtime paths and own-window PrintWindow captures, then inventory hashes. One fresh whole-stage review at stage end, regrade by user effect, fix material findings with RED/GREEN plus full suites; no per-task implementer/reviewer agents.

Primary references: [Apple loader declarations](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h), [FAT32/64 declarations](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h), [nlist](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/nlist.h), [generic relocations](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/reloc.h), [x86_64 relocations](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/x86_64/reloc.h). Read as format documentation; production parser is original scalar C++.
