#include "project_view.hpp"
#include <algorithm>
namespace hexlab::desktop {
wxString preview_text(std::string_view raw, std::size_t limit) {
    auto end = std::min(raw.size(), limit);
    while (end && end < raw.size() && (static_cast<unsigned char>(raw[end]) & 0xc0) == 0x80)
        --end;
    auto result = text(raw.substr(0, end));
    result.Replace("\r", "\\r");
    result.Replace("\n", "\\n");
    result.Replace("\t", "\\t");
    if (end < raw.size())
        result += "...";
    return result;
}
wxString analysis_state_text(const ProjectSnapshot &project) {
    switch (project.status) {
    case DerivedStatus::fresh:
        return "fresh";
    case DerivedStatus::pending:
        return "pending";
    case DerivedStatus::stale:
        return "stale";
    case DerivedStatus::incomplete:
        return "partial";
    case DerivedStatus::file_only:
        return "file only";
    }
    return "unknown";
}
bool location_mapped(const ProjectSnapshot &project, Location location) noexcept {
    if (auto address = std::get_if<Address>(&location))
        return project.loaded && project.loaded->image && project.loaded->image->segment_at(*address);
    return project.effective && std::get<FileOffset>(location).value < project.effective->size();
}
bool location_patched(const ProjectSnapshot &project, Location location, std::size_t size) {
    if (!project.state || !size)
        return false;
    auto overlaps = [&](FileOffset begin, uint64_t count) {
        auto input = project.state->input.size;
        if (begin.value >= input || !count)
            return false;
        count = std::min(count, input - begin.value);
        auto &spans = project.state->user->patches;
        auto next = std::upper_bound(spans.begin(), spans.end(), begin.value,
                                     [](auto at, auto &span) { return at < span.begin.value; });
        if (next != spans.begin()) {
            auto &previous = *std::prev(next);
            if (begin.value - previous.begin.value < previous.replacement.size())
                return true;
        }
        return next != spans.end() && next->begin.value - begin.value < count;
    };
    if (auto file = std::get_if<FileOffset>(&location))
        return overlaps(*file, size);
    if (!project.loaded)
        return false;
    auto cursor = std::get<Address>(location);
    uint64_t remaining = size;
    auto &image = *project.loaded->image;
    while (remaining) {
        auto segment = image.segment_at(cursor);
        if (!segment)
            return false;
        auto relative = cursor.offset - segment->begin.offset;
        auto amount = std::min(remaining, segment->size - relative);
        if (relative < segment->file_size &&
            overlaps({segment->file_begin.value + relative}, std::min(amount, segment->file_size - relative)))
            return true;
        auto next = advance(cursor, amount);
        if (!next)
            return false;
        cursor = next.value();
        remaining -= amount;
    }
    return false;
}
wxString listing_text(const DocumentSnapshot &document, const ListingRow &row, bool full_comment) {
    auto result = row.instruction ? text(format_instruction(*row.instruction)) : wxString("db ") + hex_bytes(row.bytes);
    if (document.project)
        if (auto annotation = annotation_at(*document.project, row.location)) {
            if (!annotation->name.empty())
                result = text(annotation->name) + ": " + result;
            if (!annotation->comment.empty())
                result += " ; " + (full_comment ? text(annotation->comment) : preview_text(annotation->comment));
        }
    return result;
}
} // namespace hexlab::desktop
