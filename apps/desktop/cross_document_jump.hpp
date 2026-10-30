#pragma once

#include "jump_resolver.hpp"
#include "hexlab/workspace/document_manager.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include <array>
#include <atomic>
#include <map>
#include <set>
#include <tuple>

namespace hexlab::desktop {
inline constexpr std::size_t cross_jump_document_limit = 128;
struct CrossJumpSource {
    DocumentId id;
    SessionKey session;
    std::shared_ptr<const ProjectSnapshot> project;
    wxString label;
};

// Search retained immutable sources directly. No unbounded intermediate symbol
// vectors are built, and each refinement gets fresh scan/result budgets.
inline NamedLocationSearch search_cross_document_names(std::span<const CrossJumpSource> sources,
    const wxString &query, NamedLocationScope scope, NamedLocationSearchMode mode,
    const std::atomic_bool *cancelled = nullptr) {
    NamedLocationSearch result;
    if (query.length() > 256) return result;
    auto needle = query;
    needle.Trim(true).Trim(false).MakeLower();
    if (needle.length() > 256 || needle.length() < (mode == NamedLocationSearchMode::exact ? 1u : 2u)) return result;
    const bool fuzzy = mode == NamedLocationSearchMode::fuzzy;
    const std::size_t record_limit = fuzzy ? 50000 : 200000;
    const std::size_t name_byte_limit = fuzzy ? 2u * 1024u * 1024u : 16u * 1024u * 1024u;
    constexpr std::size_t single_name_limit = 2048, result_limit = 4096;
    std::size_t examined = 0, name_bytes = 0;
    bool stopped = false, skipped = false;
    using Destination = std::tuple<std::uint64_t, std::size_t, std::uint32_t, std::uint64_t>;
    std::set<Destination> destinations;
    struct RankedRow {
        std::array<std::size_t, 4> rank;
        wxString folded;
        NamedLocationCandidate candidate;
        Destination destination;
    };
    const auto ranked_less = [](const RankedRow &left, const RankedRow &right) {
        if (left.rank != right.rank) return left.rank < right.rank;
        if (left.folded != right.folded) return left.folded < right.folded;
        if (left.candidate.name != right.candidate.name) return left.candidate.name < right.candidate.name;
        if (left.candidate.document != right.candidate.document)
            return left.candidate.document < right.candidate.document;
        return left.destination < right.destination;
    };
    std::set<RankedRow, decltype(ranked_less)> ranked(ranked_less);
    std::map<Destination, decltype(ranked)::iterator> ranked_destinations;
    std::size_t comparison_work = 2u * 1024u * 1024u;
    for (const auto &source : sources.first(std::min(sources.size(), cross_jump_document_limit))) {
        if (cancelled && cancelled->load(std::memory_order_relaxed)) break;
        if (stopped) break;
        const auto &project = source.project;
        if (!project || !project->loaded || !project->loaded->image || !project->state) { skipped = true; continue; }
        const auto &image = *project->loaded->image;
        const auto add = [&](std::string_view name, std::optional<Location> location) {
            if (cancelled && cancelled->load(std::memory_order_relaxed)) {
                stopped = true;
                return false;
            }
            if (++examined > record_limit || name.size() > name_byte_limit - name_bytes) {
                stopped = true; result.truncated = true;
                result.limitation = fuzzy
                    ? "partial ranked search: scan budget reached; select a narrower name-source scope"
                    : "partial search: scan budget reached; select a narrower name-source scope";
                return false;
            }
            name_bytes += name.size();
            if (name.size() > single_name_limit) { skipped = true; return true; }
            if (name.empty() || !location) return true;
            if (const auto *address = std::get_if<Address>(&*location)) {
                if (!image.segment_at(*address)) return true;
            } else if (!project->effective || std::get<FileOffset>(*location).value >= project->effective->size()) return true;
            auto display = wxString::FromUTF8(name.data(), name.size());
            auto folded = display.Lower();
            const bool matches = mode == NamedLocationSearchMode::exact ? folded == needle
                : mode == NamedLocationSearchMode::prefix ? folded.StartsWith(needle) : folded.Find(needle) != wxNOT_FOUND;
            Destination key;
            if (const auto *address = std::get_if<Address>(&*location))
                key = {source.id.value, location->index(), address->space.value, address->offset};
            else key = {source.id.value, location->index(), 0, std::get<FileOffset>(*location).value};
            if (fuzzy) {
                bool exhausted = false;
                const auto rank = ranked_name_match(folded, needle, comparison_work, exhausted);
                if (exhausted) {
                    stopped = true; result.truncated = true;
                    result.limitation = "partial ranked search: comparison budget reached; narrow the name-source scope";
                    return false;
                }
                if (!rank) return true;
                RankedRow row{*rank, folded, {std::move(display), *location, {}, source.id.value}, key};
                if (const auto found = ranked_destinations.find(key); found != ranked_destinations.end()) {
                    if (!ranked_less(row, *found->second)) return true;
                    ranked.erase(found->second);
                    ranked_destinations.erase(found);
                } else if (ranked.size() == result_limit) {
                    result.truncated = true;
                    const auto worst = std::prev(ranked.end());
                    if (!ranked_less(row, *worst)) return true;
                    ranked_destinations.erase(worst->destination);
                    ranked.erase(worst);
                }
                const auto inserted = ranked.insert(std::move(row)).first;
                ranked_destinations.emplace(key, inserted);
                return true;
            }
            if (!matches || destinations.contains(key)) return true;
            if (result.candidates.size() == result_limit) {
                stopped = true; result.truncated = true;
                result.limitation = "partial search: 4096 destinations reached; refine the query";
                return false;
            }
            destinations.insert(key);
            result.candidates.push_back({std::move(display), *location, {}, source.id.value});
            return true;
        };
        const auto &metadata = project->loaded->metadata;
        if (!project->loaded->metadata_complete || project->status == DerivedStatus::pending ||
            project->status == DerivedStatus::stale) skipped = true;
        if (scope == NamedLocationScope::all || scope == NamedLocationScope::symbols) {
            for (const auto &symbol : metadata.exports) {
                const auto ordinal = symbol.name ? std::string{} : "ordinal " + std::to_string(symbol.ordinal);
                const std::string_view name = symbol.name ? std::string_view(*symbol.name) : std::string_view(ordinal);
                if (!add(name, symbol.address ? std::optional<Location>{*symbol.address} : std::nullopt)) break;
            }
            if (stopped) break;
            for (const auto &symbol : metadata.imports) {
                const auto ordinal = !symbol.name && symbol.ordinal ? "ordinal " + std::to_string(*symbol.ordinal) : std::string{};
                const std::string_view name = symbol.name ? std::string_view(*symbol.name) : std::string_view(ordinal);
                if (!add(name, Location{symbol.iat})) break;
            }
            if (stopped) break;
            if (metadata.elf) {
                for (const auto &symbol : metadata.elf->symbols)
                    if (!add(symbol.name, symbol.state == ElfSymbolState::defined && symbol.address
                            ? std::optional<Location>{*symbol.address} : std::nullopt)) break;
                if (stopped) break;
                if (metadata.elf->dwarf_info)
                    for (const auto &symbol : metadata.elf->dwarf_info->symbols)
                        if (!add(symbol.name, symbol.kind == symbols::SymbolKind::entry_point
                                ? std::optional<Location>{Address{AddressSpaceId{}, symbol.address}}
                                : symbol.kind == symbols::SymbolKind::function && !symbol.ranges.empty()
                                    ? std::optional<Location>{Address{AddressSpaceId{}, symbol.ranges.front().begin}}
                                    : std::nullopt)) break;
            }
            if (stopped) break;
            if (metadata.macho) {
                for (const auto &symbol : metadata.macho->symbols)
                    if (!add(symbol.name, symbol.state == MachOSymbolState::defined && symbol.address
                            ? std::optional<Location>{*symbol.address} : std::nullopt)) break;
                if (stopped) break;
                for (const auto &symbol : metadata.macho->dyld_exports)
                    if (!add(symbol.name, symbol.is_definition() ? std::optional<Location>{*symbol.address} : std::nullopt)) break;
            }
            if (stopped) break;
            if (metadata.pe)
                for (const auto &symbol : metadata.pe->pdb_symbols)
                    if (!add(symbol.name, symbol.address ? std::optional<Location>{*symbol.address} : std::nullopt)) break;
        }
        if (stopped) break;
        if (project->state->user) {
            if (scope == NamedLocationScope::all || scope == NamedLocationScope::annotations)
                for (const auto &item : project->state->user->annotations)
                    if (!add(item.name, item.location)) break;
            if (stopped) break;
            if (scope == NamedLocationScope::all || scope == NamedLocationScope::bookmarks)
                for (const auto &item : project->state->user->bookmarks)
                    if (!add(item.label, item.location)) break;
        }
        if (stopped) break;
        if (scope == NamedLocationScope::all || scope == NamedLocationScope::functions) {
            if (project->functions && (project->status == DerivedStatus::fresh || project->status == DerivedStatus::incomplete)) {
                if (project->status == DerivedStatus::incomplete) skipped = true;
                for (const auto &function : project->functions->functions) {
                    if (!function) { if (!add({}, {})) break; continue; }
                    if (!add(presentation_name(*project, function->entry), function->entry)) break;
                }
            } else skipped = true;
        }
        if (stopped) break;
        if (scope == NamedLocationScope::all || scope == NamedLocationScope::sections)
            for (const auto &segment : image.layout().segments) {
                if (segment.name.empty()) { if (!add({}, {})) break; continue; }
                if (segment.name.size() > single_name_limit) { if (!add(segment.name, {})) break; continue; }
                if (!add("section:" + segment.name, segment.begin) || !add("segment:" + segment.name, segment.begin)) break;
            }
    }
    if (!stopped && (skipped || sources.size() > cross_jump_document_limit)) {
        result.truncated = true;
        result.limitation = "partial search: unavailable/stale data or oversized names were omitted";
    }
    if (fuzzy) {
        for (const auto &row : ranked) result.candidates.push_back(row.candidate);
        if (result.truncated && result.limitation.empty())
            result.limitation = "partial ranked search: showing the best 4096 destinations in the scanned sources";
    }
    if (!fuzzy) std::sort(result.candidates.begin(), result.candidates.end(), [](const auto &left, const auto &right) {
        const auto a = left.name.Lower(), b = right.name.Lower();
        if (a != b) return a < b;
        if (left.name != right.name) return left.name < right.name;
        if (left.document != right.document) return left.document < right.document;
        if (left.location.index() != right.location.index()) return left.location.index() < right.location.index();
        if (const auto *address = std::get_if<Address>(&left.location)) {
            const auto other = std::get<Address>(right.location);
            return std::tie(address->space.value, address->offset) < std::tie(other.space.value, other.offset);
        }
        return std::get<FileOffset>(left.location).value < std::get<FileOffset>(right.location).value;
    });
    return result;
}
} // namespace hexlab::desktop
