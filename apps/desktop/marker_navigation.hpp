#pragma once

#include "hexlab/core/location.hpp"
#include <algorithm>
#include <optional>
#include <vector>

namespace hexlab::desktop {
inline bool location_before(const Location &left, const Location &right) {
    if (left.index() != right.index())
        return left.index() < right.index();
    if (const auto *address = std::get_if<Address>(&left)) {
        const auto &other = std::get<Address>(right);
        if (address->space.value != other.space.value)
            return address->space.value < other.space.value;
        return address->offset < other.offset;
    }
    return std::get<FileOffset>(left).value < std::get<FileOffset>(right).value;
}

inline std::optional<Location> adjacent_marker(std::vector<Location> locations,
                                               std::optional<Location> current, bool next) {
    std::sort(locations.begin(), locations.end(), location_before);
    locations.erase(std::unique(locations.begin(), locations.end()), locations.end());
    if (locations.empty())
        return {};
    if (!current)
        return next ? locations.front() : locations.back();
    if (next) {
        auto found = std::upper_bound(locations.begin(), locations.end(), *current, location_before);
        return found == locations.end() ? std::optional<Location>{} : *found;
    }
    auto found = std::lower_bound(locations.begin(), locations.end(), *current, location_before);
    return found == locations.begin() ? std::optional<Location>{} : *std::prev(found);
}
} // namespace hexlab::desktop
