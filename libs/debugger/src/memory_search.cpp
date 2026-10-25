#include "hexlab/debugger/memory_search.hpp"
#include "hexlab/debugger/debugger.hpp"

#include <algorithm>
#include <utility>

namespace hexlab::debugger {
namespace {
struct Interval { std::uint64_t start; std::uint64_t end; };

bool space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}
int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
void coalesce(std::vector<Interval>& intervals) {
    std::sort(intervals.begin(), intervals.end(), [](const auto& a, const auto& b) {
        return a.start < b.start || (a.start == b.start && a.end < b.end);
    });
    std::size_t count = 0;
    for (const auto interval : intervals) {
        if (count && interval.start <= intervals[count - 1].end)
            intervals[count - 1].end = std::max(intervals[count - 1].end, interval.end);
        else intervals[count++] = interval;
    }
    intervals.resize(count);
}
Error invalid(const char* message) { return {ErrorCode::invalid_argument, message}; }
} // namespace

Result<MemorySearchPattern> parse_memory_search_pattern(std::string_view text) {
    // Bound parsing work even for inputs consisting entirely of whitespace.
    if (text.size() > max_memory_search_pattern * 4)
        return Error{ErrorCode::resource_limit, "memory search pattern text exceeds 16384 characters"};
    MemorySearchPattern pattern;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        while (cursor < text.size() && space(text[cursor])) ++cursor;
        if (cursor == text.size()) break;
        if (text.size() - cursor < 2)
            return invalid("memory search pattern requires two characters per byte");
        unsigned value = 0, mask = 0;
        for (unsigned i = 0; i < 2; ++i) {
            const char c = text[cursor++];
            value <<= 4;
            mask <<= 4;
            if (c == '?') continue;
            const int digit = nibble(c);
            if (digit < 0) return invalid("memory search pattern contains an invalid hex digit");
            value |= static_cast<unsigned>(digit);
            mask |= 15;
        }
        if (cursor < text.size() && !space(text[cursor]))
            return invalid("memory search pattern bytes must be separated by whitespace");
        if (pattern.bytes.size() == max_memory_search_pattern)
            return Error{ErrorCode::resource_limit, "memory search pattern exceeds 4096 bytes"};
        pattern.bytes.push_back(static_cast<std::byte>(value));
        pattern.mask.push_back(static_cast<std::byte>(mask));
    }
    if (pattern.bytes.empty()) return invalid("memory search pattern must not be empty");
    return pattern;
}

Result<MemorySearchReport> search_memory(DebugSession& session, const MemorySearchPattern& pattern,
    const MemorySearchOptions& options, std::stop_token cancellation) {
    if (pattern.bytes.empty() || pattern.bytes.size() > max_memory_search_pattern ||
        (!pattern.mask.empty() && pattern.mask.size() != pattern.bytes.size()))
        return invalid("memory search requires 1..4096 pattern bytes and an empty or equal-sized mask");
    if (!options.alignment || !options.chunk_size || options.chunk_size > max_inspection_read ||
        !options.max_bytes || options.max_bytes > max_memory_search_work ||
        !options.max_comparisons || options.max_comparisons > max_memory_search_work ||
        !options.max_results || options.max_results > max_memory_search_results ||
        !options.max_read_failures || options.max_read_failures > max_memory_search_failures ||
        options.ranges.size() > max_memory_search_ranges)
        return invalid("memory search options exceed supported nonzero work, chunk, range, or result limits");
    if (!session.process() || (session.state() != SessionState::running && session.state() != SessionState::stopped))
        return invalid("memory search requires a running or stopped debug session");

    std::vector<Interval> requested;
    for (const auto& range : options.ranges) {
        if (!range.length || range.start > UINT64_MAX - range.length)
            return invalid("memory search ranges must be nonempty and must not wrap the address space");
        requested.push_back({range.start, range.start + range.length});
    }
    coalesce(requested);
    MemorySearchReport report;
    if (cancellation.stop_requested()) {
        report.completion = MemorySearchCompletion::canceled;
        return report;
    }
    auto mapped = session.memory_regions();
    if (!mapped) return mapped.error();
    if (cancellation.stop_requested()) {
        report.completion = MemorySearchCompletion::canceled;
        return report;
    }
    std::vector<Interval> eligible;
    for (const auto& region : mapped.value()) {
        if (!region.length) continue;
        if (region.start > UINT64_MAX - region.length)
            return Error{ErrorCode::malformed, "backend returned a wrapping memory region"};
        if (!region.readable || (options.writable && *options.writable != region.writable) ||
            (options.executable && *options.executable != region.executable)) continue;
        eligible.push_back({region.start, region.start + region.length});
    }
    coalesce(eligible);
    if (!requested.empty()) {
        std::vector<Interval> intersections;
        std::size_t i = 0, j = 0;
        while (i < eligible.size() && j < requested.size()) {
            const auto start = std::max(eligible[i].start, requested[j].start);
            const auto end = std::min(eligible[i].end, requested[j].end);
            if (start < end) intersections.push_back({start, end});
            if (eligible[i].end < requested[j].end) ++i;
            else ++j;
        }
        eligible = std::move(intersections);
    }
    for (const auto interval : eligible) report.eligible_bytes += interval.end - interval.start;

    const auto pattern_size = pattern.bytes.size();
    std::vector<std::byte> tail;
    std::vector<std::byte> window;
    window.reserve(options.chunk_size + pattern_size - 1);
    const auto record_failure = [&](std::uint64_t address, std::uint64_t length, Error error) {
        report.failures.push_back({{address, length}, std::move(error)});
        if (options.stop_on_read_failure) {
            report.completion = MemorySearchCompletion::read_failed;
            return true;
        }
        if (report.failures.size() >= options.max_read_failures) {
            report.completion = MemorySearchCompletion::read_failure_limit_reached;
            return true;
        }
        return false;
    };
    for (const auto interval : eligible) {
        tail.clear();
        if (interval.end - interval.start < pattern_size) continue;
        const auto remainder = interval.start % options.alignment;
        const auto padding = remainder ? options.alignment - remainder : 0;
        if (padding > interval.end - interval.start - pattern_size) continue;
        std::uint64_t cursor = interval.start + padding;
        const auto last = interval.end - pattern_size;
        const auto scan_end = last - last % options.alignment + pattern_size;
        while (cursor < scan_end) {
            if (cancellation.stop_requested()) {
                report.completion = MemorySearchCompletion::canceled;
                return report;
            }
            if (report.bytes_requested == options.max_bytes) {
                report.completion = MemorySearchCompletion::byte_budget_exhausted;
                return report;
            }
            const auto size = static_cast<std::size_t>(std::min({
                static_cast<std::uint64_t>(options.chunk_size), scan_end - cursor,
                options.max_bytes - report.bytes_requested}));
            report.bytes_requested += size;
            auto read = session.read_memory(cursor, size);
            if (!read) {
                if (record_failure(cursor, size, read.error())) return report;
                tail.clear();
                cursor += size;
                continue;
            }
            const auto& bytes = read.value();
            if (bytes.size() > size) {
                report.failures.push_back({{cursor, size},
                    {ErrorCode::malformed, "backend returned more memory bytes than requested"}});
                report.completion = MemorySearchCompletion::backend_protocol_error;
                return report;
            }
            report.bytes_read += bytes.size();
            const bool short_read = bytes.size() < size;
            if (short_read && record_failure(cursor + bytes.size(), size - bytes.size(),
                {ErrorCode::io, "backend returned a short memory read"})) return report;
            window.assign(tail.begin(), tail.end());
            window.insert(window.end(), bytes.begin(), bytes.end());
            const auto base = cursor - tail.size();
            const auto mod = base % options.alignment;
            const auto first = mod ? options.alignment - mod : 0;
            if (window.size() >= pattern_size && first <= window.size() - pattern_size) {
                const auto end = window.size() - pattern_size;
                for (auto offset = first; offset <= end;) {
                    bool matches = true;
                    for (std::size_t byte = 0; byte < pattern_size; ++byte) {
                        if ((report.comparisons & 1023) == 0 && cancellation.stop_requested()) {
                            report.completion = MemorySearchCompletion::canceled;
                            return report;
                        }
                        if (report.comparisons == options.max_comparisons) {
                            report.completion = MemorySearchCompletion::comparison_budget_exhausted;
                            return report;
                        }
                        ++report.comparisons;
                        const auto mask = pattern.mask.empty() ? std::byte{0xff} : pattern.mask[byte];
                        if ((window[static_cast<std::size_t>(offset) + byte] & mask) != (pattern.bytes[byte] & mask)) {
                            matches = false;
                            break;
                        }
                    }
                    ++report.candidates_checked;
                    if (matches) {
                        report.matches.push_back(base + offset);
                        if (report.matches.size() == options.max_results) {
                            report.completion = MemorySearchCompletion::result_limit_reached;
                            return report;
                        }
                    }
                    if (options.alignment > end - offset) break;
                    offset += options.alignment;
                }
            }
            if (short_read) {
                tail.clear();
            } else {
                const auto keep = std::min(pattern_size - 1, window.size());
                tail.assign(window.end() - static_cast<std::ptrdiff_t>(keep), window.end());
            }
            cursor += size;
        }
    }
    report.completion = cancellation.stop_requested() ? MemorySearchCompletion::canceled :
        report.failures.empty() ? MemorySearchCompletion::completed : MemorySearchCompletion::completed_with_read_failures;
    return report;
}
} // namespace hexlab::debugger
