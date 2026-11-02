#pragma once

#include "hexlab/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace hexlab::debugger {
class DebugSession;
inline constexpr std::size_t max_memory_patch_ranges = 256;
inline constexpr std::size_t max_memory_patch_bytes = 1024 * 1024;

struct MemoryPatch {
    std::uint64_t address = 0;
    std::vector<std::byte> bytes;
    // Absent means snapshot the current bytes without a caller precondition.
    // When present, its size must equal bytes.size().
    std::optional<std::vector<std::byte>> expected;
};

enum class MemoryPatchState { untouched, applied, restored, uncertain };
struct MemoryPatchRecord {
    std::uint64_t address = 0;
    std::vector<std::byte> before;
    std::vector<std::byte> after;
    MemoryPatchState state = MemoryPatchState::untouched;
};
enum class MemoryPatchCompletion { applied, rolled_back, rollback_incomplete };
struct MemoryPatchFailure {
    std::size_t index = 0;
    Error error;
};

// Validation and preflight failures use Result errors and make no writes.
// After preflight, the report retains every snapshot, even when rollback fails.
// Records remain in caller order. A failed write may have modified its range.
class MemoryPatchReport {
public:
    MemoryPatchCompletion completion = MemoryPatchCompletion::applied;
    std::vector<MemoryPatchRecord> records;
    std::optional<MemoryPatchFailure> failure;
    std::vector<MemoryPatchFailure> rollback_failures;
private:
    friend class DebugSession;
    std::weak_ptr<const void> owner_;
};
} // namespace hexlab::debugger
