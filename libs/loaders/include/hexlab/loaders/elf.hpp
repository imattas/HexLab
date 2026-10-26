#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/symbols/dwarf.hpp"
#include <cstddef>
#include <cstdint>
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
    // Caller-owned selection and verification of the supplementary object.
    // The loader never follows the filename stored in .debug_sup.
    symbols::DwarfSupplementaryTypeResolver dwarf_supplementary_resolver;
    // Optional caller-selected DWARF v5 DWP supplementary package. When set,
    // the loader verifies its .debug_sup checksum and builds a bounded type-unit
    // resolver; it never discovers or opens a path from the input ELF.
    std::uint64_t dwarf_supplementary_max_bytes = 64u * 1024u * 1024u;
    std::uint32_t dwarf_supplementary_max_requests = 100000;
    std::shared_ptr<const ByteStorage> dwarf_supplementary_package;
    // Optional caller-selected ELF DWP companion. Its CU index is used only
    // when no explicit split-unit resolver was supplied.
    std::shared_ptr<const ByteStorage> dwarf_split_debug_package;
    // When supplied, build an additional copy-on-write runtime image after
    // parsing metadata. LoadedImage::image remains the unrebased ELF view.
    std::optional<std::uint64_t> runtime_load_bias;
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
// Imports a split-compile unit from an ELF DWO object, checking its DWO ID and
// address size against the requesting skeleton. The caller owns DWO discovery.
HEXLAB_LOADERS_EXPORT Result<symbols::ImportResult> import_elf_dwo(
    const ByteStorage &, const symbols::DwarfSplitUnitRequest &,
    std::stop_token = {}, std::uint64_t max_metadata_bytes = 64u * 1024u * 1024u,
    symbols::DwarfTypeSignatureResolver = {});
// Builds a safe split-unit callback from caller-controlled storage selection.
// No path in DW_AT_dwo_name or DW_AT_comp_dir is opened by this helper.
HEXLAB_LOADERS_EXPORT symbols::DwarfSplitUnitResolver make_elf_dwo_resolver(
    ElfDwoStorageResolver, std::stop_token = {},
    std::uint64_t max_metadata_bytes = 64u * 1024u * 1024u,
    symbols::DwarfTypeSignatureResolver = {});
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
};
struct ElfRuntimeRelocationLimits {
    std::size_t max_records = 4'000'000;
    std::size_t max_symbol_bindings = 65'536;
};
// Applies packed RELR pointer-relative entries for ELF32/ELF64 ET_DYN images
// in either byte order, plus little-endian ELF32 i386/ARM/RISC-V and ELF64
// x86-64/AArch64/PPC64/RISC-V ordinary REL/RELA subsets. RELATIVE uses B + A;
// supported symbol relocations use
// the architecture-specific S/A formulas described in elf-runtime-relocations.md.
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
