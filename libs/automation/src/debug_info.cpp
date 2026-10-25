#include "hexlab/automation/api.hpp"
#include <algorithm>
#include <type_traits>

namespace hexlab::automation {
namespace {
Result<ProjectCommand> import_command(DebugImportKind kind) {
    switch (kind) {
    case DebugImportKind::symbols: return ProjectCommand{ImportSymbols{}};
    case DebugImportKind::dwarf: return ProjectCommand{ImportDwarfInfo{}};
    }
    return Error{ErrorCode::invalid_argument, "Unknown debug-information import kind"};
}
Result<std::shared_ptr<const ProjectSnapshot>> debug_snapshot(
    const Project& project, std::optional<std::uint64_t> expected, std::stop_token stop) {
    auto current = project.snapshot(); if (!current) return current.error();
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
    if (expected && current.value()->state->revisions.edit != *expected)
        return Error{ErrorCode::conflict, "Debug-information query expected a different project edit revision"};
    return current.value();
}
template<class T>
Result<std::vector<T>> page(const std::vector<T>& rows, std::size_t start, std::size_t count,
                           std::stop_token stop) {
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    const auto first = std::min(start, rows.size());
    const auto last = first + std::min(count, rows.size() - first);
    std::vector<T> result; result.reserve(last - first);
    for (auto i = first; i < last; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
        result.push_back(rows[i]);
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
    return result;
}
Result<const database::DebugVariable*> variable_at(const ProjectSnapshot& snapshot, std::uint64_t id,
                                                  std::stop_token stop) {
    const auto& rows = snapshot.state->user->debug_variables;
    for (const auto& row : rows) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
        if (row.id == id) return &row;
    }
    return Error{ErrorCode::invalid_argument, "Unknown debug-variable identity"};
}
Error unknown_range() { return {ErrorCode::invalid_argument, "Unknown debug-variable location range"}; }
}

Result<DebugImportPreview> Project::preview_debug_import(DebugImportKind kind, std::stop_token stop) const {
    auto current = snapshot(); if (!current) return current.error();
    auto command = import_command(kind); if (!command) return command.error();
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information preview canceled"};
    DebugImportPreview result;
    result.project_uuid = current.value()->state->uuid;
    result.edit_revision = current.value()->state->revisions.edit;
    result.readonly = current.value()->mode == database::ProjectMode::read_only;
    // Validation constructs a detached delta. Allow read-only owners to inspect
    // that hypothetical delta without granting permission to commit anything.
    auto projected = *current.value();
    projected.mode = database::ProjectMode::read_write;
    auto delta = validate_command(projected, command.value(), stop);
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information preview canceled"};
    if (!delta) {
        if (delta.error().code == ErrorCode::canceled) return delta.error();
        result.reason = delta.error().message;
        result.error_code = delta.error().code;
        return result;
    }
    result.ready = true;
    result.changes = delta.value().changes.size();
    for (const auto& change : delta.value().changes) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information preview canceled"};
        std::visit([&](const auto& row) {
            using T = std::decay_t<decltype(row)>;
            if constexpr (std::is_same_v<T, database::AnnotationChange>) ++result.annotations;
            else if constexpr (std::is_same_v<T, database::TypeDefinitionChange>) ++result.types;
            else if constexpr (std::is_same_v<T, database::TypeAssignmentChange>) ++result.type_assignments;
            else if constexpr (std::is_same_v<T, database::FunctionChange>) ++result.functions;
            else if constexpr (std::is_same_v<T, database::DebugVariableChange>) ++result.variables;
        }, change);
    }
    return result;
}

Result<std::shared_ptr<const ProjectSnapshot>> Project::import_debug_info(
    DebugImportKind kind, std::uint64_t expected, std::uint64_t group, std::stop_token stop) {
    auto current = snapshot(); if (!current) return current.error();
    auto command = import_command(kind); if (!command) return command.error();
    if (current.value()->state->revisions.edit != expected)
        return Error{ErrorCode::conflict, "Debug-information import expected a different project edit revision"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information import canceled"};
    return execute(command.value(), group, stop);
}

Result<std::vector<DebugVariableInfo>> Project::debug_variables(
    std::optional<Address> entry, std::size_t start, std::size_t count,
    std::optional<std::uint64_t> expected, std::stop_token stop) const {
    auto current = debug_snapshot(*this, expected, stop); if (!current) return current.error();
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    std::vector<DebugVariableInfo> result;
    std::size_t skipped = 0;
    for (const auto& row : current.value()->state->user->debug_variables) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
        if (entry && row.function_entry != *entry) continue;
        if (skipped < start) { ++skipped; continue; }
        result.push_back({row.id, row.function_entry, row.name, row.type_id, row.is_parameter,
            row.scope_offset, row.address, row.cfa_offset, row.origin, row.location_expression.size(),
            row.location_operations.size(), row.location_ranges.size()});
        if (result.size() == count) break;
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
    return result;
}

Result<std::vector<DebugLocationRangeInfo>> Project::debug_location_ranges(
    std::uint64_t id, std::size_t start, std::size_t count,
    std::optional<std::uint64_t> expected, std::stop_token stop) const {
    auto current = debug_snapshot(*this, expected, stop); if (!current) return current.error();
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    auto found = variable_at(*current.value(), id, stop); if (!found) return found.error();
    const auto* variable = found.value();
    const auto& rows = variable->location_ranges;
    const auto first = std::min(start, rows.size());
    const auto last = first + std::min(count, rows.size() - first);
    std::vector<DebugLocationRangeInfo> result; result.reserve(last - first);
    for (auto i = first; i < last; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
        result.push_back({rows[i].begin, rows[i].end, rows[i].expression.size(), rows[i].operations.size()});
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
    return result;
}

Result<std::vector<database::DebugLocationOperation>> Project::debug_location_operations(
    std::uint64_t id, std::optional<std::size_t> range, std::size_t start, std::size_t count,
    std::optional<std::uint64_t> expected, std::stop_token stop) const {
    auto current = debug_snapshot(*this, expected, stop); if (!current) return current.error();
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    auto found = variable_at(*current.value(), id, stop); if (!found) return found.error();
    const auto* variable = found.value();
    if (range && *range >= variable->location_ranges.size()) return unknown_range();
    return page(range ? variable->location_ranges[*range].operations : variable->location_operations, start, count, stop);
}

Result<std::vector<std::byte>> Project::read_debug_expression(
    std::uint64_t id, std::size_t offset, std::size_t count, std::optional<std::size_t> range,
    std::optional<std::uint64_t> expected, std::stop_token stop) const {
    auto current = debug_snapshot(*this, expected, stop); if (!current) return current.error();
    if (count > maximum_read) return Error{ErrorCode::resource_limit, "Debug expression read exceeds 1 MiB"};
    auto found = variable_at(*current.value(), id, stop); if (!found) return found.error();
    const auto* variable = found.value();
    if (range && *range >= variable->location_ranges.size()) return unknown_range();
    const auto& expression = range ? variable->location_ranges[*range].expression : variable->location_expression;
    if (offset > expression.size() || count > expression.size() - offset)
        return Error{ErrorCode::out_of_bounds, "Debug expression read is outside the expression"};
    std::vector<std::byte> result; result.reserve(count);
    for (auto i = offset; i < offset + count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
        result.push_back(static_cast<std::byte>(expression[i]));
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Debug-information query canceled"};
    return result;
}
}
