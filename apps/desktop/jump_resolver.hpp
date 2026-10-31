#pragma once

#include "ranked_name_match.hpp"
#include "hexlab/core/location.hpp"
#include "hexlab/image/metadata.hpp"
#include "hexlab/symbols/demangle.hpp"
#include "hexlab/workspace/navigation.hpp"
#include <algorithm>
#include <atomic>
#include <set>
#include <map>
#include <iterator>
#include <tuple>
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
    // Only cross-document searches set this owner. Location alone is not a
    // unique destination when multiple documents share an address range.
    std::optional<std::uint64_t> document;
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
    wxString limitation;
    bool unique_exact_match = false;
};
enum class NamedLocationSearchMode { contains, prefix, exact, fuzzy };
enum class NamedLocationScope { all, symbols, annotations, bookmarks, functions, sections };

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

inline std::vector<std::pair<wxString, Location>> image_symbol_locations(
    const ImageMetadata &metadata, const std::atomic_bool *cancelled = nullptr) {
    std::vector<std::pair<wxString, Location>> entries;
    const auto append = [&](std::string_view name, Address address) {
        if (name.empty() || entries.size() >= 200000 ||
            (cancelled && cancelled->load(std::memory_order_relaxed))) return;
        entries.emplace_back(wxString::FromUTF8(name.data(), name.size()), Location{address});
        const auto rendered = symbols::demangle_cpp_name(name);
        if (rendered.status == symbols::DemangleStatus::demangled && rendered.text != name)
            entries.emplace_back(wxString::FromUTF8(rendered.text.data(), rendered.text.size()), Location{address});
    };
    for (const auto &symbol : metadata.exports) {
        if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
        if (symbol.address) {
            if (symbol.name)
                append(*symbol.name, *symbol.address);
            else
                append("ordinal " + std::to_string(symbol.ordinal), *symbol.address);
        }
    }
    for (const auto &symbol : metadata.imports) {
        if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
        if (symbol.name)
            append(*symbol.name, symbol.iat);
        else if (symbol.ordinal)
            append("ordinal " + std::to_string(*symbol.ordinal), symbol.iat);
    }
    if (metadata.elf) {
        for (const auto &symbol : metadata.elf->symbols) {
            if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
            if (symbol.state == ElfSymbolState::defined && symbol.address)
                append(symbol.name, *symbol.address);
        }
        // Keep DWARF-only subprogram names available even when the ELF symbol
        // table is stripped. Imported subprograms retain exact code ranges;
        // require that range provenance so declarations without code do not
        // become jumps to a fabricated zero address.
        if (metadata.elf->dwarf_info)
            for (const auto &symbol : metadata.elf->dwarf_info->symbols) {
                if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
                if (symbol.kind == symbols::SymbolKind::entry_point)
                    append(symbol.name, Address{AddressSpaceId{}, symbol.address});
                else if (symbol.kind == symbols::SymbolKind::function && !symbol.ranges.empty())
                    append(symbol.name, Address{AddressSpaceId{}, symbol.ranges.front().begin});
            }
    }
    if (metadata.macho) {
        for (const auto &symbol : metadata.macho->symbols) {
            if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
            if (symbol.state == MachOSymbolState::defined && symbol.address)
                append(symbol.name, *symbol.address);
        }
        for (const auto &symbol : metadata.macho->dyld_exports) {
            if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
            if (symbol.is_definition())
                append(symbol.name, *symbol.address);
        }
    }
    if (metadata.pe)
        for (const auto &symbol : metadata.pe->pdb_symbols) {
            if (cancelled && cancelled->load(std::memory_order_relaxed)) return entries;
            if (symbol.address)
                append(symbol.name, *symbol.address);
        }
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

inline NamedLocationSearch search_ranked_named_locations(
    const std::vector<std::pair<wxString, Location>>& entries,
    const std::vector<NamedLocationCandidate>& bounded_entries,
    const wxString& requested, std::size_t limit) {
    NamedLocationSearch result;
    auto needle = requested;
    needle.Trim(true).Trim(false).MakeLower();
    if (needle.length() < 2 || needle.length() > 256 || !limit) return result;
    limit = std::min<std::size_t>(limit, 4096);
    using Key = std::tuple<std::size_t, std::uint32_t, std::uint64_t>;
    const auto key = [](const Location& location) -> Key {
        if (const auto* address = std::get_if<Address>(&location))
            return {location.index(), address->space.value, address->offset};
        return {location.index(), 0, std::get<FileOffset>(location).value};
    };
    struct Ranked {
        std::array<std::size_t, 4> rank;
        wxString folded;
        NamedLocationCandidate candidate;
        Key destination;
    };
    const auto less = [](const Ranked& left, const Ranked& right) {
        if (left.rank != right.rank) return left.rank < right.rank;
        if (left.folded != right.folded) return left.folded < right.folded;
        if (left.candidate.name != right.candidate.name) return left.candidate.name < right.candidate.name;
        return left.destination < right.destination;
    };
    std::set<Ranked, decltype(less)> ranked(less);
    std::map<Key, decltype(ranked)::iterator> destinations;
    constexpr std::size_t record_limit = 50000, character_limit = 2 * 1024 * 1024, name_limit = 2048;
    std::size_t examined = 0, characters = 0, work = 2 * 1024 * 1024;
    bool stopped = false, skipped = false;
    const auto add = [&](const wxString& name, const Location& location) {
        if (++examined > record_limit || name.length() > character_limit - characters) {
            stopped = true; result.truncated = true;
            result.limitation = "partial ranked search: source budget reached; narrow the name-source scope";
            return;
        }
        if (name.length() > name_limit) { skipped = true; return; }
        characters += name.length();
        if (name.empty()) return;
        auto folded = name.Lower();
        bool exhausted = false;
        const auto rank = ranked_name_match(folded, needle, work, exhausted);
        if (exhausted) {
            stopped = true; result.truncated = true;
            result.limitation = "partial ranked search: comparison budget reached; narrow the name-source scope";
            return;
        }
        if (!rank) return;
        const auto destination = key(location);
        Ranked row{*rank, std::move(folded), {name, location, {}}, destination};
        if (const auto found = destinations.find(destination); found != destinations.end()) {
            if (!less(row, *found->second)) return;
            ranked.erase(found->second); destinations.erase(found);
        } else if (ranked.size() == limit) {
            result.truncated = true;
            const auto worst = std::prev(ranked.end());
            if (!less(row, *worst)) return;
            destinations.erase(worst->destination); ranked.erase(worst);
        }
        const auto inserted = ranked.insert(std::move(row)).first;
        destinations.emplace(destination, inserted);
    };
    for (const auto& [name, location] : entries) { add(name, location); if (stopped) break; }
    if (!stopped) for (const auto& candidate : bounded_entries) {
        add(candidate.name, candidate.location); if (stopped) break;
    }
    if (skipped) {
        result.truncated = true;
        if (!result.limitation.empty()) result.limitation += "; ";
        result.limitation += "names over 2048 characters omitted";
    }
    if (result.truncated && result.limitation.empty())
        result.limitation = "ranked destination limit reached; showing best matches in the scanned sources";
    result.candidates.reserve(ranked.size());
    for (const auto& row : ranked) result.candidates.push_back(row.candidate);
    return result;
}

inline NamedLocationSearch search_named_locations(
    const std::vector<std::pair<wxString, Location>> &entries,
    const std::vector<NamedLocationCandidate> &bounded_entries,
    const wxString &requested, std::size_t limit = 128,
    NamedLocationSearchMode mode = NamedLocationSearchMode::contains,
    std::size_t offset = 0, std::size_t page_size = 256, const std::atomic_bool *cancelled = nullptr) {
    if (mode == NamedLocationSearchMode::fuzzy)
        return search_ranked_named_locations(entries, bounded_entries, requested, limit);
    NamedLocationSearch result;
    wxString needle = requested;
    needle.Trim(true).Trim(false);
    needle.MakeLower();
    if (needle.length() < (mode == NamedLocationSearchMode::exact ? 1u : 2u) || !limit)
        return result;

    const auto less_location = [](const Location &left, const Location &right) {
        if (left.index() != right.index()) return left.index() < right.index();
        if (const auto *address = std::get_if<Address>(&left)) {
            const auto &other = std::get<Address>(right);
            if (address->space.value != other.space.value) return address->space.value < other.space.value;
            return address->offset < other.offset;
        }
        return std::get<FileOffset>(left).value < std::get<FileOffset>(right).value;
    };
    page_size = std::clamp<std::size_t>(page_size, 1, 256);
    limit = std::min<std::size_t>(limit, 200000);
    std::set<Location, decltype(less_location)> destinations(less_location);
    std::vector<NamedLocationCandidate> ordered_matches;
    std::size_t examined = 0;

    const auto add = [&](const wxString &name, const Location &location) {
        if (cancelled && cancelled->load(std::memory_order_relaxed)) { result.truncated = true; return; }
        if (name.empty() || ++examined > limit) { if (examined > limit) result.truncated = true; return; }
        wxString folded = name;
        folded.MakeLower();
        const bool matched = mode == NamedLocationSearchMode::exact ? folded == needle
            : mode == NamedLocationSearchMode::prefix ? folded.StartsWith(needle)
            : folded.Find(needle) != wxNOT_FOUND;
        if (!matched || destinations.contains(location)) return;
        destinations.insert(location);
        ordered_matches.push_back({name, location, {}});
    };
    for (const auto &[name, location] : entries) {
        add(name, location);
        if (result.truncated) break;
    }
    if (!result.truncated)
        for (const auto &candidate : bounded_entries) {
            add(candidate.name, candidate.location);
            if (result.truncated) break;
        }
    std::sort(ordered_matches.begin(), ordered_matches.end(), [](const auto &left, const auto &right) {
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
    const auto begin = std::min(offset, ordered_matches.size());
    const auto end = std::min(ordered_matches.size(), begin + page_size);
    result.truncated = end < ordered_matches.size() || result.truncated;
    result.candidates.assign(ordered_matches.begin() + static_cast<std::ptrdiff_t>(begin),
                             ordered_matches.begin() + static_cast<std::ptrdiff_t>(end));
    return result;
}
} // namespace hexlab::desktop
