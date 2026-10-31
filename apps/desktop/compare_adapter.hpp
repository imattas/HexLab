#pragma once

#include "hexlab/analysis/functions.hpp"
#include "hexlab/compare/compare.hpp"
#include <span>

namespace hexlab::desktop {

// Adds direct-call edges only when both endpoints are functions represented in
// the supplied feature set. Addresses retain their per-image address spaces.
void populate_direct_call_neighborhoods(const FunctionSnapshot &snapshot,
                                       std::span<compare::FunctionFeature> features);

inline constexpr std::size_t compare_instruction_review_limit = 128;
// Returns a bounded prefix in the same function-block order used by desktop
// comparison features. No decoding or mutable project lookup is performed.
compare::Result<std::vector<std::shared_ptr<const InstructionFact>>> review_compare_instructions(
    const FunctionSnapshot &, const compare::FunctionAddress &function,
    std::uint64_t start, std::uint64_t count);

} // namespace hexlab::desktop
