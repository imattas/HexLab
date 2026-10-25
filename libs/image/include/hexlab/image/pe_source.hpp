#pragma once
#include "hexlab/core/address.hpp"
#include <cstdint>
#include <vector>

namespace hexlab {
// File bytes backing a PE record, including records crossing adjacent sections.
struct PeSourceSpan {
    FileOffset offset{};
    std::uint64_t size = 0;
    bool operator==(const PeSourceSpan &) const = default;
};
struct PeRecordSource {
    std::uint32_t index = 0;
    std::vector<PeSourceSpan> spans;
    bool operator==(const PeRecordSource &) const = default;
};
} // namespace hexlab
