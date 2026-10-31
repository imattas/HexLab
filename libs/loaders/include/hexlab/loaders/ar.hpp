#pragma once
#include "hexlab/loaders/loader.hpp"
#include <cstddef>
#include <functional>
#include <filesystem>
#include <optional>
#include <stop_token>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab {

enum class ArMemberKind { regular, thin_external, symbol_index, long_name_table, member_table };

struct ArMember {
    std::string name;
    FileOffset header_offset;
    FileOffset data_offset;
    std::uint64_t size = 0;
    ArMemberKind kind = ArMemberKind::regular;
    // Metadata from the fixed-width ar header. Mode is stored as its numeric
    // octal value (for example, 0644 is represented as decimal 420).
    std::uint64_t timestamp = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint32_t mode = 0;
};

struct ArSymbol {
    std::string name;
    std::size_t member_index = 0; // Index into ArArchive::members, including special members.
};

struct ArArchive {
    std::vector<ArMember> members;
    std::vector<ArSymbol> symbols;
    bool thin = false;
    bool aix_big = false;
    bool has_symbol_index = false;
    bool symbol_index_complete = true;
    std::vector<std::string> diagnostics;
};

// Selects indexed regular members needed to satisfy unresolved symbols. The
// first indexed definition wins, matching deterministic archive search order.
struct ArSymbolSelection {
    std::vector<std::size_t> member_indices;
    std::vector<std::string> unresolved_symbols;
    bool archive_index_complete = true;
};

struct ArSymbolLookup {
    std::optional<std::size_t> member_index;
    // All indexed providers for the requested symbol, unique and ordered by
    // archive member order. member_index is the first candidate when present.
    std::vector<std::size_t> candidate_member_indices;
    bool has_symbol_index = false;
    bool index_complete = true;
};

// Object-level symbol summary supplied by a format-specific object reader.
// Members without a summary are ignored by fixed-point selection.
struct ArMemberSymbols {
    std::size_t member_index = 0;
    std::vector<std::string> definitions;
    std::vector<std::string> undefined;
};

struct ArObjectLimits {
    std::uint64_t max_metadata_bytes = 64ULL * 1024 * 1024;
    std::size_t max_sections = 1'000'000;
    std::size_t max_symbols = 1'000'000;
    std::size_t max_name_bytes = 4096;
};

struct ArSelectedMember {
    std::size_t member_index = 0;
    // Unresolved symbols which caused this member to be selected.
    std::vector<std::string> selected_for;
};

struct ArLinkSelection {
    std::vector<ArSelectedMember> members;
    std::vector<std::string> unresolved_symbols;
};

struct ArLinkLimits {
    std::size_t max_selected_members = 100'000;
    std::size_t max_symbol_work = 10'000'000;
};

struct LoadedArchive {
    std::shared_ptr<const ByteStorage> storage;
    ArArchive archive;
};

struct ArLimits {
    std::size_t max_members = 1'000'000;
    std::size_t max_name_bytes = 4096;
    std::size_t max_symbols = 10'000'000;
    std::uint64_t max_extracted_bytes = 512ULL * 1024 * 1024;
};

// Caller-controlled lookup for a thin archive's external member path. The
// callback owns path resolution and must return storage for exactly the
// declared member extent; the loader never opens archive paths itself.
using ArThinMemberResolver = std::function<Result<std::shared_ptr<const ByteStorage>>(std::string_view)>;
struct ArThinResolverLimits {
    std::uint64_t max_total_bytes = 512ULL * 1024 * 1024;
    std::size_t max_unique_paths = 100'000;
    std::size_t max_path_bytes = 4096;
};

// Creates an opt-in resolver rooted at exactly `root`. Member names must be
// valid UTF-8 relative paths; traversal, rooted paths, symlinks/reparse points
// escaping the root, and non-regular files are rejected. Paths are resolved
// exactly as stored (there is no basename fallback or implicit search). Each
// unique stored path is snapshotted once and cached for the resolver lifetime.
HEXLAB_LOADERS_EXPORT Result<ArThinMemberResolver> make_ar_thin_member_resolver(
    std::filesystem::path root, ArThinResolverLimits = {});

// Supports standard ar headers, GNU long-name tables and 32-/64-bit GNU symbol
// indexes, plus BSD #1/ extended member names. BSD ranlib indexes are reported
// as unsupported while the archive's regular members remain available.
HEXLAB_LOADERS_EXPORT Result<ArArchive> read_ar_archive(const ByteStorage &, std::stop_token = {},
                                                       ArLimits = {});
HEXLAB_LOADERS_EXPORT Result<ArSymbolSelection> select_ar_members(
    const ArArchive &, std::span<const std::string_view> unresolved_symbols);
// Looks up the earliest indexed definition in archive member order. The full
// ordered candidate list retains duplicate-provider provenance. The returned
// member indices address ArArchive::members, which retains raw offsets and
// decoded names. Completeness distinguishes an absent/partial index from a
// complete miss.
HEXLAB_LOADERS_EXPORT Result<ArSymbolLookup> lookup_ar_member_by_symbol(
    const ArArchive &, std::string_view symbol);
// Repeatedly selects the earliest unselected member defining a currently
// unresolved symbol, adds that member's undefined symbols, and rescans until
// no further member can be selected. Results preserve archive order and record
// the symbols that caused each selection. This consumes caller-provided object
// summaries; it does not parse object formats or combine relocations. Thin
// external members are eligible when the caller has resolved their storage
// with open_ar_member and supplied an object summary for that member index.
HEXLAB_LOADERS_EXPORT Result<ArLinkSelection> select_ar_members_fixed_point(
    const ArArchive &, std::span<const ArMemberSymbols>,
    std::span<const std::string_view> unresolved_symbols,
    std::span<const std::string_view> already_defined = {}, std::stop_token = {}, ArLinkLimits = {});
// Reads an ELF ET_REL member's global/weak definitions and strong unresolved
// globals. Weak undefined symbols are omitted because they do not pull archive
// members in conventional ELF linkers.
HEXLAB_LOADERS_EXPORT Result<ArMemberSymbols> summarize_elf_ar_member(
    const ByteStorage &, std::size_t member_index, std::stop_token = {}, ArObjectLimits = {});
// Summarizes bounded big-endian XCOFF64 relocatable members for archive
// selection. It does not link XCOFF objects or interpret relocations.
HEXLAB_LOADERS_EXPORT Result<ArMemberSymbols> summarize_xcoff64_ar_member(
    const ByteStorage &, std::size_t member_index, std::stop_token = {}, ArObjectLimits = {});
// Summarizes bounded big-endian XCOFF32 relocatable members for archive
// selection. It does not link XCOFF objects or interpret relocations.
HEXLAB_LOADERS_EXPORT Result<ArMemberSymbols> summarize_xcoff32_ar_member(
    const ByteStorage &, std::size_t member_index, std::stop_token = {}, ArObjectLimits = {});
// Summarizes ordinary COFF (including ARM64), bigobj, and bounded XCOFF32/64
// relocatable symbol tables for
// fixed-point archive selection. Linking callers must filter by machine before
// selection; a symbol name alone does not establish architecture compatibility.
// Import/short-import members contribute the public code and IAT
// names (or IAT names for data) used by the AMD64 static PE linker.
HEXLAB_LOADERS_EXPORT Result<ArMemberSymbols> summarize_coff_ar_member(
    const ByteStorage &, std::size_t member_index, std::stop_token = {}, ArObjectLimits = {});
// Summarizes bounded 64-bit Mach-O object members for archive selection.
HEXLAB_LOADERS_EXPORT Result<ArMemberSymbols> summarize_macho_ar_member(
    const ByteStorage &, std::size_t member_index, std::stop_token = {}, ArObjectLimits = {});
HEXLAB_LOADERS_EXPORT Result<LoadedArchive> load_ar_archive(std::shared_ptr<const ByteStorage>, std::stop_token = {},
                                                            ArLimits = {});
// A bounded zero-copy ByteStorage view over a regular member. Compatible with
// the existing PE/ELF loaders and any other ByteStorage consumer.
HEXLAB_LOADERS_EXPORT Result<std::shared_ptr<const ByteStorage>> open_ar_member(std::shared_ptr<const ByteStorage>,
                                                                               const ArMember &);
HEXLAB_LOADERS_EXPORT Result<std::shared_ptr<const ByteStorage>> open_ar_member(
    std::shared_ptr<const ByteStorage>, const ArMember &, const ArThinMemberResolver &);
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> extract_ar_member(const ByteStorage &, const ArMember &,
                                                                       std::stop_token = {}, ArLimits = {});
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> extract_ar_member(
    std::shared_ptr<const ByteStorage>, const ArMember &, const ArThinMemberResolver &,
    std::stop_token = {}, ArLimits = {});

} // namespace hexlab
