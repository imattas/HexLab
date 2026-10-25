#pragma once

#include "hexlab/core/address.hpp"
#include <cstdint>
#include <optional>

namespace hexlab::desktop {

// Resolves the fast path for the Types view's Assign action. A selected type
// should be applied directly; only an absent type selection needs a chooser.
struct TypeAssignmentIntent {
    enum class Kind { unavailable, choose_type, assign_selected } kind = Kind::unavailable;
    Address address{};
    std::uint64_t type_id = 0;
};

inline TypeAssignmentIntent resolve_type_assignment_intent(
    std::optional<Address> address, std::optional<std::uint64_t> selected_type_id) noexcept {
    if (!address) return {};
    if (!selected_type_id || *selected_type_id == 0)
        return {TypeAssignmentIntent::Kind::choose_type, *address, 0};
    return {TypeAssignmentIntent::Kind::assign_selected, *address, *selected_type_id};
}

} // namespace hexlab::desktop
