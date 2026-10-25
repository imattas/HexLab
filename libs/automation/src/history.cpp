#include "hexlab/automation/api.hpp"
#include <algorithm>

namespace hexlab::automation {
namespace {
template<class T>
Result<std::vector<T>> page(const std::vector<T>& rows, std::size_t start, std::size_t count) {
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    const auto first = std::min(start, rows.size());
    const auto last = first + std::min(count, rows.size() - first);
    return std::vector<T>(rows.begin() + static_cast<std::ptrdiff_t>(first),
                          rows.begin() + static_cast<std::ptrdiff_t>(last));
}
}

Result<database::HistoryPage> Project::history(std::uint64_t after, std::size_t count,
    std::optional<std::uint64_t> expected, std::stop_token stop) const {
    auto current = snapshot(); if (!current) return current.error();
    if (!store_) return Error{ErrorCode::unsupported, "A workspace capture does not retain the durable history log; query the live project"};
    return store_->history_page(expected.value_or(current.value()->state->revisions.edit), after, count, stop);
}

Result<std::shared_ptr<const HistoricalState>> Project::preview_history(std::uint64_t target,
    database::HistoryPreviewLimits limits, std::optional<std::uint64_t> expected, std::stop_token stop) const {
    auto current = snapshot(); if (!current) return current.error();
    if (!store_) return Error{ErrorCode::unsupported, "A workspace capture does not retain the durable history log; query the live project"};
    auto preview = store_->preview_history_at(expected.value_or(current.value()->state->revisions.edit), target, limits, stop);
    if (!preview) return preview.error();
    if (preview.value().uuid != current.value()->state->uuid)
        return Error{ErrorCode::conflict, "History projection belongs to a different project identity"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "History preview canceled"};
    // Reuse the canonical patch validator/overlay: original-byte preconditions
    // are checked against the embedded input before exposing historical reads.
    auto effective = make_overlay(current.value()->original, preview.value().user->patches);
    if (!effective) return effective.error();
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "History preview canceled"};
    return std::shared_ptr<const HistoricalState>(new HistoricalState(std::move(preview.value()), std::move(effective.value())));
}

Result<std::vector<database::Annotation>> HistoricalState::annotations(std::size_t start, std::size_t count) const {
    return page(preview_.user->annotations, start, count);
}
Result<std::vector<database::Bookmark>> HistoricalState::bookmarks(std::size_t start, std::size_t count) const {
    return page(preview_.user->bookmarks, start, count);
}
Result<std::vector<database::TypeDefinition>> HistoricalState::types(std::size_t start, std::size_t count) const {
    return page(preview_.user->types, start, count);
}
Result<std::vector<database::TypeAssignment>> HistoricalState::type_assignments(std::size_t start, std::size_t count) const {
    return page(preview_.user->type_assignments, start, count);
}
Result<std::vector<HistoricalPatch>> HistoricalState::patches(std::size_t start, std::size_t count) const {
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    const auto& rows = preview_.user->patches;
    const auto first = std::min(start, rows.size());
    const auto last = first + std::min(count, rows.size() - first);
    std::vector<HistoricalPatch> result; result.reserve(last - first);
    for (auto i = first; i < last; ++i) result.push_back({rows[i].begin, rows[i].replacement.size()});
    return result;
}
Result<std::vector<RegionDecision>> HistoricalState::regions(std::size_t start, std::size_t count) const {
    return page(preview_.user->decisions.regions, start, count);
}
Result<std::vector<HistoricalFunctionDecision>> HistoricalState::function_decisions(std::size_t start, std::size_t count) const {
    if (!count || count > maximum_page)
        return Error{ErrorCode::resource_limit, "Automation page count must be 1..4096"};
    const auto& rows = preview_.user->decisions.functions;
    const auto first = std::min(start, rows.size());
    const auto last = first + std::min(count, rows.size() - first);
    std::vector<HistoricalFunctionDecision> result; result.reserve(last - first);
    for (auto i = first; i < last; ++i)
        result.push_back({rows[i].id, rows[i].entry, rows[i].suppressed, rows[i].chunks.size()});
    return result;
}
Result<std::vector<DecisionRange>> HistoricalState::function_chunks(std::uint64_t id, std::size_t start, std::size_t count) const {
    for (const auto& decision : preview_.user->decisions.functions)
        if (decision.id == id) return page(decision.chunks, start, count);
    return Error{ErrorCode::invalid_argument, "Unknown historical function decision identity"};
}
Result<std::vector<UserReference>> HistoricalState::user_references(std::size_t start, std::size_t count) const {
    return page(preview_.user->decisions.references, start, count);
}
Result<std::vector<std::byte>> HistoricalState::read(FileOffset offset, std::size_t count) const {
    if (count > maximum_read) return Error{ErrorCode::resource_limit, "Historical read exceeds 1 MiB"};
    if (offset.value > effective_->size() || count > effective_->size() - offset.value)
        return Error{ErrorCode::out_of_bounds, "Historical file read exceeds input"};
    auto bytes = effective_->read_at(offset, count); if (!bytes) return bytes.error();
    if (bytes.value().bytes.size() != count)
        return Error{ErrorCode::io, "Historical input returned a short read"};
    return std::vector<std::byte>(bytes.value().bytes.begin(), bytes.value().bytes.end());
}
}
