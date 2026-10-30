#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <wx/string.h>

namespace hexlab::desktop {
// Exact, prefix, substring, then an ordered-character abbreviation. Inputs are
// already case folded. Every character comparison consumes shared query work.
inline std::optional<std::array<std::size_t, 4>> ranked_name_match(
    const wxString& name, const wxString& query, std::size_t& work, bool& exhausted) {
    if (query.empty() || name.length() < query.length()) return {};
    const auto equals_at = [&](std::size_t start) {
        for (std::size_t i = 0; i < query.length(); ++i) {
            if (!work) { exhausted = true; return false; }
            --work;
            if (name[start + i] != query[i]) return false;
        }
        return true;
    };
    if (equals_at(0)) return std::array<std::size_t, 4>{name.length() == query.length() ? 0u : 1u, 0, 0, name.length()};
    if (exhausted) return {};
    for (std::size_t start = 1; start <= name.length() - query.length(); ++start) {
        if (equals_at(start)) return std::array<std::size_t, 4>{2, 0, start, name.length()};
        if (exhausted) return {};
    }
    std::size_t matched = 0, first = 0;
    for (std::size_t i = 0; i < name.length(); ++i) {
        if (!work) { exhausted = true; return {}; }
        --work;
        if (name[i] != query[matched]) continue;
        if (!matched) first = i;
        if (++matched == query.length())
            return std::array<std::size_t, 4>{3, i - first + 1 - query.length(), first, name.length()};
    }
    return {};
}
}
