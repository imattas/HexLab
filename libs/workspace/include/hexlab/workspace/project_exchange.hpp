#pragma once
#include "hexlab/workspace/project.hpp"

namespace hexlab {
enum class ExchangeConflictPolicy { fail, skip, replace };
enum class ExchangeRecordKind { annotation, bookmark, reference, region, function, type_definition, type_assignment, debug_variable };
enum class ExchangeConflictResolution { kept_existing, imported, preserved_both };
struct ExchangeConflict {
    ExchangeRecordKind kind = ExchangeRecordKind::annotation;
    Location location = FileOffset{};
    // For references this is the alternate target; otherwise it is empty.
    std::optional<Location> related_location;
    ExchangeConflictResolution resolution = ExchangeConflictResolution::kept_existing;
};
struct ExchangeImport {
    std::vector<ProjectCommand> commands;
    std::vector<ExchangeConflict> conflicts;
    std::size_t annotations = 0, bookmarks = 0, references = 0, regions = 0, functions = 0,
                type_definitions = 0, type_assignments = 0, debug_variables = 0, skipped = 0;
};
// Portable v6 also exchanges type and debug-variable records by portable names and source origins, never project IDs.
// Input SHA256/size bind the exchange to identical original bytes; project/entity IDs are never serialized.
HEXLAB_WORKSPACE_EXPORT Result<std::vector<std::byte>> export_project_exchange(const ProjectSnapshot &,
                                                                                std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_WORKSPACE_EXPORT Result<ExchangeImport> import_project_exchange(const ProjectSnapshot &,
                                                                       std::span<const std::byte>,
                                                                       ExchangeConflictPolicy = ExchangeConflictPolicy::fail,
                                                                       std::size_t max_bytes = 16u * 1024u * 1024u);
} // namespace hexlab
