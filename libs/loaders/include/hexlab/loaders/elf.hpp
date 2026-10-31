#pragma once
#include "hexlab/core/sha256.hpp"
#include "hexlab/image/external_inputs.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/symbols/dwarf.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <span>
#include <string>
#include <vector>

namespace hexlab {
using ElfDwoStorageResolver = std::function<Result<std::shared_ptr<const ByteStorage>>(
    const symbols::DwarfSplitUnitRequest &)>;

struct ElfLoadOptions {
    // Optional caller-owned lookup for DWARF v5 DWO/DWP contributions. The
    // loader never opens a path from DW_AT_dwo_name itself; the callback must
    // resolve the requested DWO ID and return a split ImportResult carrying
    // the same identity.
    symbols::DwarfSplitUnitResolver dwarf_split_resolver;
    // Stable caller-assigned identity for the split resolver implementation
    // and its captured configuration. Required for derived-cache reuse.
    std::optional<Sha256Digest> dwarf_split_resolver_identity;
    // Caller-owned selection and verification of the supplementary object.
    // Direct load_elf callers supply this resolver explicitly. Top-level
    // load_image may discover a basename-only .dwp beside a FileStorage input.
    symbols::DwarfSupplementaryTypeResolver dwarf_supplementary_resolver;
    // Stable caller-assigned identity for the supplementary resolver
    // implementation and its captured configuration. Required for reuse.
    std::optional<Sha256Digest> dwarf_supplementary_resolver_identity;
    // Optional caller-selected supplementary ELF object or DWARF v5 DWP.
    // The loader verifies its .debug_sup checksum and builds a bounded type-unit
    // resolver. Direct load_elf does not discover paths; load_image performs
    // restricted same-directory .dwp discovery from the validated .debug_sup.
    std::uint64_t dwarf_supplementary_max_bytes = 64u * 1024u * 1024u;
    std::uint32_t dwarf_supplementary_max_requests = 100000;
    std::shared_ptr<const ByteStorage> dwarf_supplementary_package;
    // Optional caller-selected ELF DWP companion. Its CU index is used only
    // when no explicit split-unit resolver was supplied.
    std::shared_ptr<const ByteStorage> dwarf_split_debug_package;
    // When supplied, build an additional copy-on-write runtime image after
    // parsing metadata. LoadedImage::image remains the unrebased ELF view.
    std::optional<std::uint64_t> runtime_load_bias;
    // Optional complete byte-input manifests for caller resolvers. Presence
    // declares that every external byte dependency is listed; an empty list
    // declares a resolver with no external byte inputs. A matching callback
    // and stable code/configuration identity are still required. Contents are
    // fingerprinted before and after parsing, and changes reject publication.
    std::optional<std::vector<ExternalAnalysisInput>> dwarf_split_resolver_inputs;
    std::optional<std::vector<ExternalAnalysisInput>> dwarf_supplementary_resolver_inputs;
    ExternalInputLimits dwarf_resolver_input_limits;
};
struct ElfDwoTypeSource {
    // Exact caller-selected skeleton/DWO pairing. The storage is never
    // discovered from DW_AT_dwo_name or DW_AT_comp_dir.
    symbols::DwarfSplitUnitRequest identity;
    std::shared_ptr<const ByteStorage> storage;
};
struct ElfDwoTypeResolverLimits {
    std::uint32_t max_sources = 4096;
    std::uint32_t max_requests = 4096;
    std::uint64_t max_bytes = 64u * 1024u * 1024u;
    std::uint64_t max_bytes_per_dwo = 64u * 1024u * 1024u;
};
struct ElfDwoDirectoryResolverLimits {
    std::uint32_t max_requests = 4096;
    std::uint64_t max_file_bytes = 64u * 1024u * 1024u;
    std::uint64_t max_total_file_bytes = 256u * 1024u * 1024u;
    std::uint64_t max_metadata_bytes_per_dwo = 64u * 1024u * 1024u;
};
struct ElfDwpMacroContribution {
    std::uint64_t signature = 0; // CU DWO ID or TU type signature, according to index_kind.
    symbols::DwarfPackageIndexKind index_kind = symbols::DwarfPackageIndexKind::compile_units;
    std::uint32_t package_index_version = 0;
    std::uint32_t section_id = 0;
    std::uint32_t package_section_offset = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> strings;
    std::vector<std::uint8_t> line_strings;
};
struct ElfDwpLineContribution {
    std::uint64_t signature = 0;
    symbols::DwarfPackageIndexKind index_kind = symbols::DwarfPackageIndexKind::compile_units;
    std::uint32_t package_index_version = 0;
    std::uint32_t section_id = 4;
    std::uint32_t package_section_offset = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> strings;
    std::vector<std::uint8_t> line_strings;
};
// One bounded, explicitly indexed DWP section contribution. The ID follows
// the selected package-index version (v2 or v5); strings are shared package
// sections, while bytes contains only the selected contribution.
struct ElfDwpSectionContribution {
    std::uint64_t signature = 0;
    symbols::DwarfPackageIndexKind index_kind = symbols::DwarfPackageIndexKind::compile_units;
    std::uint32_t package_index_version = 0;
    std::uint32_t section_id = 0;
    std::uint32_t package_section_offset = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> strings;
    std::vector<std::uint8_t> line_strings;
};
struct ElfDwpSourceLine {
    std::uint64_t signature = 0;
    symbols::DwarfPackageIndexKind index_kind = symbols::DwarfPackageIndexKind::compile_units;
    std::uint32_t package_index_version = 0, package_section_offset = 0, line_unit_index = 0;
    std::uint16_t line_unit_version = 0;
    std::uint64_t address = 0, directory_index = 0, column = 0;
    std::int64_t line = 0;
    std::string file_name;
    bool end_sequence = false;
};
// Reads one explicitly selected DW_SECT_MACRO contribution (section ID 8 in
// package-index v2 or ID 7 in v5), including shared string tables.
// The caller owns package discovery and identity verification.
HEXLAB_LOADERS_EXPORT Result<ElfDwpMacroContribution> read_elf_dwp_macro_contribution(
    const ByteStorage &, symbols::DwarfPackageIndexKind, std::uint64_t signature,
    std::stop_token = {}, std::uint64_t max_bytes = 64u * 1024u * 1024u);
// Reads one explicitly selected DW_SECT_LINE contribution (section ID 4),
// including shared string tables; this extracts bytes but does not parse rows.
HEXLAB_LOADERS_EXPORT Result<ElfDwpLineContribution> read_elf_dwp_line_contribution(
    const ByteStorage &, symbols::DwarfPackageIndexKind, std::uint64_t signature,
    std::stop_token = {}, std::uint64_t max_bytes = 64u * 1024u * 1024u);
// Reads an explicitly selected indexed DWP contribution by DW_SECT_* ID.
// Supported IDs map the standard v2/v5 index sections to their .dwo section
// names; shared string tables are returned and ELF DWARF relocations applied.
HEXLAB_LOADERS_EXPORT Result<ElfDwpSectionContribution> read_elf_dwp_section_contribution(
    const ByteStorage &, symbols::DwarfPackageIndexKind, std::uint64_t signature,
    std::uint32_t section_id, std::stop_token = {},
    std::uint64_t max_bytes = 64u * 1024u * 1024u);
// Checks an explicitly supplied debug companion against one parsed
// .gnu_debuglink CRC. No filename from the ELF is opened or resolved here.
HEXLAB_LOADERS_EXPORT Result<bool> verify_elf_gnu_debuglink_crc(
    const ElfGnuDebugLink &, const ByteStorage &, std::stop_token = {},
    std::uint64_t max_bytes = 512ULL * 1024 * 1024);
// Parses one explicit line contribution into address/file/line rows. The
// caller supplies target address size and byte order; directory indexes remain
// metadata and are not resolved into paths.
HEXLAB_LOADERS_EXPORT Result<std::vector<ElfDwpSourceLine>> parse_elf_dwp_line_contribution(
    const ElfDwpLineContribution &, std::uint8_t address_size, bool little_endian,
    std::stop_token = {}, std::size_t max_rows = 1'000'000,
    std::uint64_t max_bytes = 64u * 1024u * 1024u);
// Imports a split-compile unit from an ELF DWO object, checking its DWO ID and
// address size against the requesting skeleton. The caller owns DWO discovery.
HEXLAB_LOADERS_EXPORT Result<symbols::ImportResult> import_elf_dwo(
    const ByteStorage &, const symbols::DwarfSplitUnitRequest &,
    std::stop_token = {}, std::uint64_t max_metadata_bytes = 64u * 1024u * 1024u,
    symbols::DwarfTypeSignatureResolver = {}, symbols::DwarfSupplementaryIdentity = {},
    symbols::DwarfSupplementaryTypeResolver = {});
// Builds a safe split-unit callback from caller-controlled storage selection.
// No path in DW_AT_dwo_name or DW_AT_comp_dir is opened by this helper.
HEXLAB_LOADERS_EXPORT symbols::DwarfSplitUnitResolver make_elf_dwo_resolver(
    ElfDwoStorageResolver, std::stop_token = {},
    std::uint64_t max_metadata_bytes = 64u * 1024u * 1024u,
    symbols::DwarfTypeSignatureResolver = {}, symbols::DwarfSupplementaryIdentity = {},
    symbols::DwarfSupplementaryTypeResolver = {});
// Opt-in conventional `.dwo` discovery confined to one caller-selected
// directory. Only the basename of DW_AT_dwo_name is considered; the selected
// object must be a regular non-symlink `.dwo` file inside that directory and
// its split-unit ID/address size are verified by import_elf_dwo. The caller
// remains responsible for assigning a stable resolver identity in ElfLoadOptions.
// Limits bound request count, each mapped file, aggregate mapped files, and
// per-DWO metadata import.
HEXLAB_LOADERS_EXPORT Result<symbols::DwarfSplitUnitResolver> make_elf_dwo_directory_resolver(
    std::filesystem::path directory, std::stop_token = {}, ElfDwoDirectoryResolverLimits = {});
// Resolves DW_FORM_ref_sig8 over a caller-selected set of paired DWO objects.
// Duplicate DWO IDs or signatures are treated as ambiguous; imports are lazy,
// cached, cycle-checked, and bounded by the supplied aggregate limits.
HEXLAB_LOADERS_EXPORT symbols::DwarfTypeSignatureResolver make_elf_dwo_type_signature_resolver(
    std::vector<ElfDwoTypeSource>, std::stop_token = {}, ElfDwoTypeResolverLimits = {});
// Container validation only; does not claim architecture/relocation support.
// Reads the fixed header and, for extended counts, the first section record.
// Table extents are checked without materializing the tables or whole input.
HEXLAB_LOADERS_EXPORT Result<ElfHeader> read_elf_header(const ByteStorage &, std::stop_token);
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_elf(std::shared_ptr<const ByteStorage>, std::stop_token);
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_elf(std::shared_ptr<const ByteStorage>, const ElfLoadOptions &,
                                                   std::stop_token);

struct ElfRuntimeRelocationSkip {
    std::uint64_t relocation_index = 0;
    std::string reason;
    bool operator==(const ElfRuntimeRelocationSkip &) const = default;
};
struct ElfRuntimeImage {
    std::shared_ptr<const Image> image;
    std::uint64_t load_bias = 0;
    std::vector<std::uint64_t> applied_indices;
    struct ResolvedSymbol {
        std::uint64_t relocation_index = 0;
        std::size_t binding_index = 0;
        std::uint64_t runtime_address = 0;
        bool operator==(const ResolvedSymbol &) const = default;
    };
    // External bindings actually used by applied relocations. binding_index
    // indexes the caller-owned table passed to apply_elf_runtime_relocations.
    std::vector<ResolvedSymbol> resolved_symbols;
    std::vector<ElfRuntimeRelocationSkip> skipped;
    bool complete = true;
};
struct ElfRuntimeSymbolBinding {
    std::string library_name;
    std::string symbol_name;
    std::optional<std::string> version_name;
    std::uint64_t runtime_address = 0;
    // A versioned export is eligible for an unversioned import only when it
    // is marked as the default version in the dependency's versym table.
    bool default_version = false;
    // ELF symbol size used by size relocations such as R_X86_64_SIZE32/64.
    std::uint64_t symbol_size = 0;
};
// One caller-owned dependency-manifest entry. Names and aliases are compared
// byte-for-byte with DT_NEEDED; this API never searches directories or opens
// paths named by the input image.
struct ElfLibraryManifestEntry {
    std::string library_name;
    std::vector<std::string> aliases;
    // Optional caller-supplied target path. The resolver treats this as an
    // opaque ELF namespace path and performs lexical comparisons only.
    std::optional<std::string> path;
};
enum class ElfLibraryResolutionState { resolved, missing, ambiguous };
enum class ElfLibrarySearchSource { manifest_name, rpath, runpath, environment };
struct ElfLibraryResolution {
    std::string needed_name;
    ElfLibraryResolutionState state = ElfLibraryResolutionState::missing;
    // Index into the caller's manifest when state is resolved.
    std::optional<std::size_t> manifest_index;
    // Sorted manifest indexes, retained to explain ambiguous matches.
    std::vector<std::size_t> candidates;
    ElfLibrarySearchSource source = ElfLibrarySearchSource::manifest_name;
    std::optional<std::string> matched_directory;
};
struct ElfLibraryResolutionLimits {
    std::size_t max_needed = 4096;
    std::size_t max_manifest_entries = 16384;
    std::size_t max_manifest_names = 65536;
    std::size_t max_name_bytes = 4096;
};
// Resolves the image's ordered DT_NEEDED entries against a caller-provided
// manifest using exact canonical-name/alias matches. Duplicate declarations
// are reported once in DT_NEEDED order. No filesystem access occurs.
HEXLAB_LOADERS_EXPORT Result<std::vector<ElfLibraryResolution>> resolve_elf_needed_libraries(
    const LoadedImage &, std::span<const ElfLibraryManifestEntry>, std::stop_token = {},
    ElfLibraryResolutionLimits = {});
struct ElfLibrarySearchContext {
    // Explicit importer path in the target ELF namespace; must be absolute.
    // It is used only to expand $ORIGIN/${ORIGIN}; no environment is read.
    std::string importer_path;
    std::size_t max_search_entries = 1024;
    std::size_t max_path_bytes = 4096;
    // Caller-supplied absolute paths representing LD_LIBRARY_PATH in the
    // target environment. The resolver never reads the host environment.
    std::vector<std::string> environment_search_paths;
};
// Applies caller-supplied environment directories and DT_RUNPATH/DT_RPATH to
// the caller-owned manifest's optional candidate paths in direct-dependency
// search order. Directory order is preserved; the first directory with
// candidates wins, and duplicates there remain ambiguous. This is metadata
// only and performs no file I/O or host environment lookup.
HEXLAB_LOADERS_EXPORT Result<std::vector<ElfLibraryResolution>> resolve_elf_needed_libraries(
    const LoadedImage &, std::span<const ElfLibraryManifestEntry>, const ElfLibrarySearchContext &,
    std::stop_token = {}, ElfLibraryResolutionLimits = {});
struct ElfRuntimeDependencyImage {
    std::string needed_name;
    std::vector<std::string> aliases;
    const LoadedImage *loaded = nullptr;
    std::uint64_t load_bias = 0;
};
struct ElfRuntimeBindingIssue {
    std::string symbol_name;
    std::optional<std::string> version_name, dependency_name;
    std::string reason;
};
struct ElfRuntimeBindingSet {
    std::vector<ElfRuntimeSymbolBinding> bindings;
    std::vector<ElfLibraryResolution> unresolved_dependencies;
    std::vector<ElfRuntimeBindingIssue> unresolved_symbols;
    bool complete = true;
};
struct ElfRuntimeBindingLimits {
    std::size_t max_dependency_images = 4096;
    std::size_t max_symbols_scanned = 1'000'000;
    std::size_t max_bindings = 65'536;
    std::size_t max_issues = 65'536;
    std::size_t max_name_bytes = 4096;
};
// Derives exact caller bindings from fully supplied DT_NEEDED images. It does
// not search paths or load libraries. If a needed library is missing or
// ambiguous, no symbol bindings are emitted from the partial provider set.
HEXLAB_LOADERS_EXPORT Result<ElfRuntimeBindingSet> resolve_elf_runtime_symbol_bindings(
    const LoadedImage &, std::span<const ElfRuntimeDependencyImage>, std::stop_token = {},
    ElfRuntimeBindingLimits = {});
struct ElfRuntimeRelocationLimits {
    std::size_t max_records = 4'000'000;
    std::size_t max_symbol_bindings = 65'536;
};
// Applies packed RELR pointer-relative entries for ELF32/ELF64 ET_DYN images
// in either byte order, plus ELF32 ARM/PPC/MIPS in either byte order,
// little-endian ELF32 i386/RISC-V and ELF64 x86-64/AArch64/RISC-V, ELF64
// PPC64 in either byte order, and big-endian s390x ordinary REL/RELA subsets,
// including s390x narrow/word absolute and PC-relative fields. RELATIVE uses B + A;
// supported symbol relocations use
// the architecture-specific S/A formulas described in elf-runtime-relocations.md.
// ARM ABS16/ABS8 use byte-aligned narrow fields, signed REL addends, and
// AAELF32 signed-or-unsigned range checks after modulo-32-bit arithmetic.
// ELF32 i386 RELATIVE uses an unsigned implicit 32-bit addend; ELF64 REL
// uses the validated signed implicit addend, while ELF64 RELA uses its
// explicit signed addend. Symbol slots are not addend based.
// The argument is the ELF load bias B, not the preferred base. The source
// LoadedImage and its original file bytes remain unchanged.
HEXLAB_LOADERS_EXPORT Result<ElfRuntimeImage> apply_elf_runtime_relocations(
    const LoadedImage &, std::uint64_t load_bias, std::stop_token = {}, ElfRuntimeRelocationLimits = {});
// Applies unresolved dynamic symbol relocations using caller-selected runtime
// exports. Matching is exact by DT_NEEDED library, base name, and GNU version;
// dependency discovery/loading remains caller-owned.
HEXLAB_LOADERS_EXPORT Result<ElfRuntimeImage> apply_elf_runtime_relocations(
    const LoadedImage &, std::uint64_t load_bias, std::span<const ElfRuntimeSymbolBinding>, std::stop_token = {},
    ElfRuntimeRelocationLimits = {});
} // namespace hexlab
