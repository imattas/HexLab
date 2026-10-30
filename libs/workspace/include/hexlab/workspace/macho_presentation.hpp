#pragma once
#include "hexlab/workspace/project.hpp"
namespace hexlab {
enum class MachOMetadataKind {
    header,
    slice,
    command,
    segment,
    section,
    symbol_table,
    symbol,
    library,
    path,
    entry,
    function_start,
    dynamic_symbols,
    relocation_table,
    relocation,
    dyld_stream,
    dyld_operation,
    dyld_fixup,
    dyld_export,
    chain_header,
    chain_import,
    chain_start,
    chain_pointer,
    data_in_code_table,
    data_in_code,
    encryption,
    signature,
    eh_frame_function,
    eh_frame_personality,
    eh_frame_call_site,
    eh_frame_action,
    eh_frame_type_info,
    chain_start_offset,
    dyld_environment,
    count
};
struct MachOMetadataRow {
    MachOMetadataKind kind;
    std::uint64_t index;
    FileOffset source;
    std::uint64_t owner_index = 0, item_index = 0;
};
// Counts and category boundaries are built on the project worker. Row access is
// bounded by the fixed category count and borrows no mutable state.
HEXLAB_WORKSPACE_EXPORT std::uint64_t macho_metadata_row_count(const ProjectSnapshot &) noexcept;
HEXLAB_WORKSPACE_EXPORT std::optional<MachOMetadataRow> macho_metadata_row_at(const ProjectSnapshot &,
                                                                              std::uint64_t) noexcept;
struct MachOMetadataPage {
    std::uint64_t begin = 0, total = 0;
    std::vector<MachOMetadataRow> rows;
};
HEXLAB_WORKSPACE_EXPORT Result<MachOMetadataPage> make_macho_metadata_page(const ProjectSnapshot &, std::uint64_t begin,
                                                                           std::size_t count, std::stop_token);
} // namespace hexlab
