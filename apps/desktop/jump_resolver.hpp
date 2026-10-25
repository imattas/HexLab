#pragma once

#include "hexlab/core/location.hpp"
#include "hexlab/image/metadata.hpp"
#include "hexlab/workspace/navigation.hpp"
#include <algorithm>
#include <wx/string.h>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace hexlab::desktop {
struct NamedLocationCandidate {
    wxString name;
    Location location;
    // Section/segment expressions are accepted only while the relative
    // displacement remains inside the containing mapped extent.
    std::optional<std::uint64_t> relative_extent;
};

struct NamedLocationMatch {
    std::optional<Location> location;
    bool ambiguous = false;
    std::vector<NamedLocationCandidate> candidates;
};

struct NamedLocationExpression {
    wxString base_name;
    bool add = true;
    std::uint64_t displacement = 0;
};

struct NamedLocationSearch {
    std::vector<NamedLocationCandidate> candidates;
    bool truncated = false;
};

inline std::optional<NamedLocationExpression> parse_named_location_expression(const wxString &input) {
    wxString trimmed = input;
    trimmed.Trim(true).Trim(false);
    const auto text = trimmed.ToStdWstring();
    for (std::size_t cursor = text.size(); cursor > 1; --cursor) {
        const auto index = cursor - 1;
        if (text[index] != L'+' && text[index] != L'-')
            continue;
        wxString amount_text(text.substr(index + 1));
        amount_text.Trim(true).Trim(false);
        auto amount = hexlab::parse_address(amount_text.ToStdWstring());
        if (!amount)
            continue;
        wxString base(text.substr(0, index));
        base.Trim(true).Trim(false);
        if (base.empty())
            continue;
        return NamedLocationExpression{std::move(base), text[index] == L'+', amount.value()};
    }
    return {};
}

inline std::vector<std::pair<wxString, Location>> image_symbol_locations(const ImageMetadata &metadata) {
    std::vector<std::pair<wxString, Location>> entries;
    const auto append = [&](std::string_view name, Address address) {
        if (!name.empty())
            entries.emplace_back(wxString::FromUTF8(name.data(), name.size()), Location{address});
    };
    for (const auto &symbol : metadata.exports) {
        if (symbol.address) {
            if (symbol.name)
                append(*symbol.name, *symbol.address);
            else
                append("ordinal " + std::to_string(symbol.ordinal), *symbol.address);
        }
    }
    for (const auto &symbol : metadata.imports) {
        if (symbol.name)
            append(*symbol.name, symbol.iat);
        else if (symbol.ordinal)
            append("ordinal " + std::to_string(*symbol.ordinal), symbol.iat);
    }
    if (metadata.elf)
        for (const auto &symbol : metadata.elf->symbols)
            if (symbol.state == ElfSymbolState::defined && symbol.address)
                append(symbol.name, *symbol.address);
    if (metadata.macho) {
        for (const auto &symbol : metadata.macho->symbols)
            if (symbol.state == MachOSymbolState::defined && symbol.address)
                append(symbol.name, *symbol.address);
        for (const auto &symbol : metadata.macho->dyld_exports)
            if (symbol.is_definition())
                append(symbol.name, *symbol.address);
    }
    if (metadata.pe)
        for (const auto &symbol : metadata.pe->pdb_symbols)
            if (symbol.address)
                append(symbol.name, *symbol.address);
    return entries;
}

inline std::vector<NamedLocationCandidate> named_location_candidates(
    const std::vector<std::pair<wxString, Location>> &entries, const wxString &requested) {
    std::vector<NamedLocationCandidate> result;
    for (const auto &[name, location] : entries) {
        if (name.empty() || name.CmpNoCase(requested) != 0)
            continue;
        if (std::none_of(result.begin(), result.end(), [&](const auto &candidate) {
                return candidate.location == location;
            }))
            result.push_back({name, location, {}});
    }
    return result;
}

inline NamedLocationMatch resolve_named_location(
    const std::vector<std::pair<wxString, Location>> &entries, const wxString &requested) {
    auto candidates = named_location_candidates(entries, requested);
    if (candidates.size() == 1)
        return {candidates.front().location, false};
    return {{}, candidates.size() > 1};
}

inline bool apply_location_displacement(Location &location, bool add, std::uint64_t displacement) {
    auto adjust = [&](std::uint64_t &value) {
        if (add) {
            if (displacement > UINT64_MAX - value)
                return false;
            value += displacement;
        } else {
            if (displacement > value)
                return false;
            value -= displacement;
        }
        return true;
    };
    if (auto *address = std::get_if<Address>(&location))
        return adjust(address->offset);
    return adjust(std::get<FileOffset>(location).value);
}

inline NamedLocationMatch resolve_named_location_expression(
    const std::vector<std::pair<wxString, Location>> &entries,
    const std::vector<NamedLocationCandidate> &bounded_entries, const wxString &requested) {
    auto exact = named_location_candidates(entries, requested);
    for (const auto &candidate : bounded_entries)
        if (candidate.name.CmpNoCase(requested) == 0 &&
            std::none_of(exact.begin(), exact.end(), [&](const auto &existing) {
                return existing.location == candidate.location;
            }))
            exact.push_back(candidate);
    if (!exact.empty()) {
        NamedLocationMatch match;
        if (exact.size() == 1)
            match.location = exact.front().location;
        else
            match.ambiguous = true;
        match.candidates = std::move(exact);
        return match;
    }
    const auto expression = parse_named_location_expression(requested);
    if (!expression)
        return {};

    std::vector<NamedLocationCandidate> candidates;
    auto append_adjusted = [&](NamedLocationCandidate candidate) {
        if (candidate.relative_extent && (!expression->add ||
            expression->displacement >= *candidate.relative_extent))
            return;
        if (!apply_location_displacement(candidate.location, expression->add, expression->displacement))
            return;
        if (std::none_of(candidates.begin(), candidates.end(), [&](const auto &existing) {
                return existing.location == candidate.location;
            }))
            candidates.push_back(std::move(candidate));
    };
    for (auto candidate : bounded_entries)
        if (candidate.name.CmpNoCase(expression->base_name) == 0)
            append_adjusted(std::move(candidate));
    for (const auto &[name, location] : entries)
        if (name.CmpNoCase(expression->base_name) == 0)
            append_adjusted({name, location, {}});
    if (candidates.size() == 1)
        return {candidates.front().location, false};
    NamedLocationMatch match{{}, candidates.size() > 1};
    match.candidates = std::move(candidates);
    return match;
}

inline NamedLocationSearch search_named_locations(
    const std::vector<std::pair<wxString, Location>> &entries,
    const std::vector<NamedLocationCandidate> &bounded_entries,
    const wxString &requested, std::size_t limit = 128) {
    NamedLocationSearch result;
    wxString needle = requested;
    needle.Trim(true).Trim(false);
    needle.MakeLower();
    if (needle.length() < 2 || !limit)
        return result;

    const auto add = [&](const wxString &name, const Location &location) {
        if (name.empty()) return;
        wxString folded = name;
        folded.MakeLower();
        if (folded.Find(needle) == wxNOT_FOUND) return;
        if (std::any_of(result.candidates.begin(), result.candidates.end(),
                [&](const auto &candidate) { return candidate.location == location; })) return;
        if (result.candidates.size() == limit) {
            result.truncated = true;
            return;
        }
        result.candidates.push_back({name, location, {}});
    };
    for (const auto &[name, location] : entries) add(name, location);
    for (const auto &candidate : bounded_entries) add(candidate.name, candidate.location);
    std::sort(result.candidates.begin(), result.candidates.end(), [](const auto &left, const auto &right) {
        wxString left_folded = left.name, right_folded = right.name;
        left_folded.MakeLower(); right_folded.MakeLower();
        if (left_folded != right_folded) return left_folded < right_folded;
        if (left.name != right.name) return left.name < right.name;
        if (left.location.index() != right.location.index()) return left.location.index() < right.location.index();
        if (const auto *address = std::get_if<Address>(&left.location)) {
            const auto &other = std::get<Address>(right.location);
            if (address->space.value != other.space.value) return address->space.value < other.space.value;
            return address->offset < other.offset;
        }
        return std::get<FileOffset>(left.location).value < std::get<FileOffset>(right.location).value;
    });
    return result;
}
} // namespace hexlab::desktop
