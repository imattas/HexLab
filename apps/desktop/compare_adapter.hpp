#pragma once

#include "hexlab/analysis/functions.hpp"
#include "hexlab/compare/compare.hpp"
#include <span>

namespace hexlab::desktop {

// Adds direct-call edges only when both endpoints are functions represented in
// the supplied feature set. Addresses retain their per-image address spaces.
void populate_direct_call_neighborhoods(const FunctionSnapshot &snapshot,
                                       std::span<compare::FunctionFeature> features);

} // namespace hexlab::desktop
