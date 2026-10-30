#include "hexlab/automation/api.hpp"
#include "hexlab/database/codec.hpp"
#include <map>
#include <set>
#include <tuple>

namespace hexlab::automation {
namespace {
using Key = std::tuple<unsigned, std::uint32_t, std::uint64_t>;
Key key_of(Location location) {
    if (const auto* address = std::get_if<Address>(&location))
        return {0, address->space.value, address->offset};
    return {1, 0, std::get<FileOffset>(location).value};
}
}
Result<AnnotationImportResult> Project::import_annotations(std::span<const AnnotationImportRow> rows,
        AnnotationMerge merge, std::uint64_t group, std::optional<std::uint64_t> expected, std::stop_token stop) {
    auto valid = live_owner(); if (!valid) return valid.error();
    if (rows.empty() || rows.size() > maximum_page)
        return Error{ErrorCode::resource_limit, "Annotation import requires 1..4096 rows"};
    if (merge != AnnotationMerge::replace && merge != AnnotationMerge::preserve)
        return Error{ErrorCode::invalid_argument, "Unknown annotation import merge policy"};
    const auto current = session_->snapshot();
    const auto revision = current->state->revisions.edit;
    if (expected && *expected != revision)
        return Error{ErrorCode::conflict, "Annotation import expected a different project edit revision"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Annotation import canceled"};
    try {
        // Validate all supplied text, even fields preserve mode would skip.
        // The database codec supplies the canonical UTF-8 and field limits.
        std::size_t text_bytes = 0, fields = 0;
        for (std::size_t index = 0; index < rows.size(); ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Annotation import canceled during input validation"};
            const auto& row = rows[index];
            const auto row_fields = std::size_t(row.name.has_value()) + row.comment.has_value() + row.bookmark.has_value();
            if (!row_fields) return Error{ErrorCode::invalid_argument, "Annotation import row " + std::to_string(index) + " has no fields"};
            fields += row_fields;
            if (fields > maximum_page) return Error{ErrorCode::resource_limit, "Annotation import exceeds 4096 supplied fields"};
            auto charge = [&](const std::string& value) {
                if (value.size() > 16 * 1024 * 1024 - text_bytes) return false;
                text_bytes += value.size(); return true;
            };
            if ((row.name && !charge(*row.name)) || (row.comment && !charge(*row.comment)) ||
                (row.bookmark && !charge(row.bookmark->label)))
                return Error{ErrorCode::resource_limit, "Annotation import text exceeds 16 MiB"};
            if (row.name && !std::holds_alternative<Address>(row.location))
                return Error{ErrorCode::invalid_argument, "Annotation import names require virtual addresses"};
            database::UserState input;
            if ((row.name && !row.name->empty()) || (row.comment && !row.comment->empty()))
                input.annotations.push_back({1, row.location, row.name.value_or(""), row.comment.value_or("")});
            if (row.bookmark) input.bookmarks.push_back({2, row.location, row.bookmark->label});
            auto checked = database::validate_user_state(input);
            if (!checked) return Error{checked.error().code, "Annotation import row " + std::to_string(index) + ": " + checked.error().message};
        }
        const auto& user = *current->state->user;
        std::map<Key, std::pair<bool, bool>> occupied;
        std::set<Key> bookmarks;
        std::map<std::pair<std::uint32_t, std::string_view>, Key> names;
        if (merge == AnnotationMerge::preserve) {
            if (user.annotations.size() > maximum_annotation_import_existing_rows ||
                user.bookmarks.size() > maximum_annotation_import_existing_rows)
                return Error{ErrorCode::resource_limit, "Preserve import exceeds 65536 existing annotation or bookmark rows"};
            for (const auto& row : user.annotations) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Annotation import canceled while indexing existing state"};
                const auto key = key_of(row.location);
                occupied.emplace(key, std::pair{!row.name.empty(), !row.comment.empty()});
                if (const auto* address = std::get_if<Address>(&row.location); address && !row.name.empty())
                    names.emplace(std::pair{address->space.value, std::string_view(row.name)}, key);
            }
            for (const auto& row : user.bookmarks) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Annotation import canceled while indexing existing bookmarks"};
                bookmarks.insert(key_of(row.location));
            }
        }
        std::vector<ProjectCommand> commands;
        commands.reserve(fields);
        std::size_t skipped = 0;
        for (const auto& row : rows) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Annotation import canceled during merge planning"};
            const auto key = key_of(row.location);
            auto& pending = occupied[key];
            if (row.name) {
                bool skip = merge == AnnotationMerge::preserve && (pending.first || row.name->empty());
                if (!skip && merge == AnnotationMerge::preserve) {
                    const auto space = std::get<Address>(row.location).space.value;
                    const auto found = names.find({space, *row.name});
                    skip = found != names.end() && found->second != key;
                    if (!skip) names[{space, *row.name}] = key;
                }
                if (skip) ++skipped;
                else { commands.emplace_back(Rename{row.location, *row.name}); pending.first = true; }
            }
            if (row.comment) {
                if (merge == AnnotationMerge::preserve && (pending.second || row.comment->empty())) ++skipped;
                else { commands.emplace_back(Comment{row.location, *row.comment}); pending.second = true; }
            }
            if (row.bookmark) {
                if (merge == AnnotationMerge::preserve && (row.bookmark->remove || bookmarks.contains(key))) ++skipped;
                else {
                    commands.emplace_back(BookmarkCommand{row.location, row.bookmark->label, row.bookmark->remove});
                    bookmarks.insert(key);
                }
            }
        }
        AnnotationImportResult result{current, revision, revision, commands.size(), skipped, false};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Annotation import canceled before commit"};
        if (commands.empty()) return result;
        auto committed = execute_batch(commands, group, revision, stop);
        if (!committed) return committed.error();
        result.snapshot = committed.value();
        result.result_revision = result.snapshot->state->revisions.edit;
        result.committed = result.result_revision != revision;
        return result;
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "Cannot allocate annotation import plan"};
    }
}
}
