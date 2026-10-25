#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/debugger/debugger_export.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string_view>
#include <vector>

namespace hexlab::debugger {
class DebugSession;

inline constexpr std::size_t max_memory_search_pattern = 4096;
inline constexpr std::size_t max_memory_search_ranges = 4096;
inline constexpr std::size_t max_memory_search_results = 65536;
inline constexpr std::size_t max_memory_search_failures = 4096;
inline constexpr std::uint64_t max_memory_search_work = 1024ULL * 1024 * 1024;

// A bit set in mask must equal the corresponding bit in bytes. An empty
// mask means exact bytes. All-zero masks intentionally match every position.
struct MemorySearchPattern {
    std::vector<std::byte> bytes;
    std::vector<std::byte> mask;
};

// Parses whitespace-separated byte pairs, including nibble wildcards:
// "48 8B ?? A? ?F". Empty, oversized, and malformed patterns are rejected.
HEXLAB_DEBUGGER_EXPORT Result<MemorySearchPattern> parse_memory_search_pattern(std::string_view text);

// Half-open [start, start + length); wrapping address ranges are invalid.
struct MemorySearchRange {
    std::uint64_t start = 0;
    std::uint64_t length = 0;
};

struct MemorySearchOptions {
    // Empty means all eligible mapped memory. Overlapping and adjacent ranges
    // are coalesced. Reads never leave their intersection with eligible maps.
    std::vector<MemorySearchRange> ranges;
    // All selected regions must be readable. nullopt accepts either value.
    std::optional<bool> writable;
    std::optional<bool> executable;
    // Match addresses must be divisible by alignment (not relative to a range).
    std::uint64_t alignment = 1;
    std::size_t chunk_size = 64 * 1024;
    // Every requested byte is charged, including failed and short reads.
    std::uint64_t max_bytes = 64ULL * 1024 * 1024;
    // A separate comparison budget bounds wildcard-heavy/long-pattern work.
    std::uint64_t max_comparisons = 64ULL * 1024 * 1024;
    std::size_t max_results = 4096;
    std::size_t max_read_failures = 64;
    bool stop_on_read_failure = false;
};

enum class MemorySearchCompletion {
    completed,
    completed_with_read_failures,
    byte_budget_exhausted,
    comparison_budget_exhausted,
    result_limit_reached,
    canceled,
    read_failed,
    read_failure_limit_reached,
    backend_protocol_error
};

struct MemorySearchFailure {
    MemorySearchRange range;
    Error error;
};

struct MemorySearchReport {
    MemorySearchCompletion completion = MemorySearchCompletion::completed;
    std::vector<std::uint64_t> matches;
    std::vector<MemorySearchFailure> failures;
    std::uint64_t eligible_bytes = 0;
    std::uint64_t bytes_requested = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t comparisons = 0;
    std::uint64_t candidates_checked = 0;
    bool complete() const noexcept { return completion == MemorySearchCompletion::completed; }
};

// Requires an active session and memory-map support. Setup/validation failures
// use Result errors; interrupted scans retain matches, counters, and failures.
// Synchronous and read-only; cancellation cannot interrupt an in-flight backend
// call. The caller must serialize access to the session.
HEXLAB_DEBUGGER_EXPORT Result<MemorySearchReport> search_memory(
    DebugSession& session, const MemorySearchPattern& pattern,
    const MemorySearchOptions& options = {}, std::stop_token cancellation = {});
} // namespace hexlab::debugger
