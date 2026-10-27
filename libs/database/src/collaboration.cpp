#include "hexlab/database/collaboration.hpp"
#include "history_internal.hpp"
#include "project_internal.hpp"
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <tuple>

namespace hexlab::database {
using detail::take;
using detail::Failure;
struct ProjectCollaboration::Impl {
    std::shared_ptr<ProjectStore> project;
    std::shared_ptr<Connection> connection;
    std::mutex mutex;
};

namespace {
std::byte patch_value(std::span<const PatchSpan> patches,std::size_t& cursor,
                      std::uint64_t offset,std::byte original) {
    while(cursor<patches.size() &&
          patches[cursor].begin.value+patches[cursor].replacement.size()<=offset)++cursor;
    if(cursor<patches.size() && patches[cursor].begin.value<=offset)
        return patches[cursor].replacement[static_cast<std::size_t>(offset-patches[cursor].begin.value)];
    return original;
}

Result<std::optional<std::vector<PatchSpan>>> merge_patch_spans(
    const ByteStorage& original,std::span<const PatchSpan> base,
    std::span<const PatchSpan> proposed,std::span<const PatchSpan> current,
    std::stop_token stop) {
    try {
        auto checked_base=PatchSet::create(original,base);
        if(!checked_base)return checked_base.error();
        auto checked_proposed=PatchSet::create(original,proposed);
        if(!checked_proposed)return checked_proposed.error();
        auto checked_current=PatchSet::create(original,current);
        if(!checked_current)return checked_current.error();
        base=checked_base.value()->spans();
        proposed=checked_proposed.value()->spans();
        current=checked_current.value()->spans();

        std::vector<std::pair<std::uint64_t,std::uint64_t>> ranges;
        ranges.reserve(base.size()+proposed.size()+current.size());
        auto add_ranges=[&](std::span<const PatchSpan> spans)->Result<bool>{
            for(const auto& patch:spans){
                auto end=checked_add(patch.begin.value,patch.replacement.size());
                if(!end)return end.error();
                if(end.value()>patch.begin.value)ranges.emplace_back(patch.begin.value,end.value());
            }
            return true;
        };
        auto added=add_ranges(base);if(!added)return added.error();
        added=add_ranges(proposed);if(!added)return added.error();
        added=add_ranges(current);if(!added)return added.error();
        std::sort(ranges.begin(),ranges.end());
        std::vector<std::pair<std::uint64_t,std::uint64_t>> merged_ranges;
        merged_ranges.reserve(ranges.size());
        for(const auto& range:ranges){
            if(!merged_ranges.empty() && range.first<=merged_ranges.back().second)
                merged_ranges.back().second=std::max(merged_ranges.back().second,range.second);
            else merged_ranges.push_back(range);
        }

        constexpr std::uint64_t merge_byte_limit=64ull*1024*1024;
        std::uint64_t total=0;
        std::vector<PatchSpan> output;
        for(const auto& range:merged_ranges){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Patch rebase canceled"};
            const auto length=range.second-range.first;
            if(length>merge_byte_limit-total || length>std::numeric_limits<std::size_t>::max())
                return Error{ErrorCode::resource_limit,"Concurrent patch ranges exceed the rebase budget"};
            total+=length;
            auto original_view=original.read_at({range.first},static_cast<std::size_t>(length));
            if(!original_view)return original_view.error();
            if(original_view.value().bytes.size()!=length)
                return Error{ErrorCode::io,"Original input returned an incomplete patch rebase read"};
            std::vector<std::byte> replacement(original_view.value().bytes.begin(),original_view.value().bytes.end());
            std::size_t base_cursor=0,proposed_cursor=0,current_cursor=0;
            for(std::size_t i=0;i<replacement.size();++i){
                if((i&0xffffu)==0 && stop.stop_requested())return Error{ErrorCode::canceled,"Patch rebase canceled"};
                const auto offset=range.first+i;
                const auto base_byte=patch_value(base,base_cursor,offset,original_view.value().bytes[i]);
                const auto proposed_byte=patch_value(proposed,proposed_cursor,offset,original_view.value().bytes[i]);
                const auto current_byte=patch_value(current,current_cursor,offset,original_view.value().bytes[i]);
                if(proposed_byte==base_byte)replacement[i]=current_byte;
                else if(current_byte==base_byte || proposed_byte==current_byte)replacement[i]=proposed_byte;
                else return std::optional<std::vector<PatchSpan>>{};
            }
            output.push_back({FileOffset{range.first},
                              std::vector<std::byte>(original_view.value().bytes.begin(),original_view.value().bytes.end()),
                              std::move(replacement)});
        }
        auto normalized=PatchSet::create(original,output);
        if(!normalized)return normalized.error();
        const auto spans=normalized.value()->spans();
        return std::optional<std::vector<PatchSpan>>{std::vector<PatchSpan>(spans.begin(),spans.end())};
    } catch(const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit,"Cannot allocate merged patch ranges"};
    } catch(const std::length_error&) {
        return Error{ErrorCode::resource_limit,"Merged patch ranges exceed allocation limits"};
    }
}

// Three-way merge one scalar field. Returning nullopt means that both peers
// changed it to different values; callers must retain the proposal for review.
template<class T>
std::optional<T> merge_field(const T& base, const T& proposed, const T& current) {
    if (proposed == base) return current;
    if (current == base || proposed == current) return proposed;
    return {};
}

bool same_type(const types::TypePtr& left, const types::TypePtr& right) {
    if (!left || !right || left->id() != right->id()) return false;
    const auto left_bytes = types::encode(*left);
    const auto right_bytes = types::encode(*right);
    return left_bytes && right_bytes && left_bytes.value() == right_bytes.value();
}

bool same_definition(const TypeDefinition& left, const TypeDefinition& right) {
    return left.id == right.id && left.name == right.name && left.origin == right.origin && left.declaration_kind == right.declaration_kind &&
           same_type(left.type, right.type);
}

std::optional<types::TypePtr> merge_type(const types::TypePtr& base,
                                         const types::TypePtr& proposed,
                                         const types::TypePtr& current) {
    if (!base || !proposed || !current) return {};
    if (same_type(proposed, base)) return current;
    if (same_type(current, base) || same_type(proposed, current)) return proposed;
    return {};
}

bool references_named_type(const types::Type& type, std::string_view name,
                           std::set<std::uint64_t>& visited) {
    if (!visited.insert(type.id()).second) return false;
    if (type.kind() == types::Kind::named_reference && type.name() == name) return true;
    if (type.element() && references_named_type(*type.element(), name, visited)) return true;
    if (type.result_type() && references_named_type(*type.result_type(), name, visited)) return true;
    for (const auto& member : type.members()) {
        if (member.type && references_named_type(*member.type, name, visited)) return true;
        if (member.virtual_base && member.virtual_base->vbptr_type &&
            references_named_type(*member.virtual_base->vbptr_type, name, visited)) return true;
    }
    for (const auto& parameter : type.parameters())
        if (parameter.type && references_named_type(*parameter.type, name, visited)) return true;
    return false;
}

bool type_name_is_referenced(const std::vector<TypeDefinition>& definitions,
                             std::uint64_t except_id, std::string_view name) {
    for (const auto& definition : definitions) {
        if (definition.id == except_id || !definition.type) continue;
        std::set<std::uint64_t> visited;
        if (references_named_type(*definition.type, name, visited)) return true;
    }
    return false;
}

bool type_references_name(const types::TypePtr& type, std::string_view name) {
    if (!type) return false;
    std::set<std::uint64_t> visited;
    return references_named_type(*type, name, visited);
}

struct RegionExtent {
    Address begin{};
    std::uint64_t size=0;
    bool operator==(const RegionExtent&) const = default;
};

bool ranges_overlap(Address a, std::uint64_t a_size, Address b, std::uint64_t b_size) {
    if (a.space != b.space || a_size == 0 || b_size == 0) return false;
    if (a.offset <= b.offset) return b.offset - a.offset < a_size;
    return a.offset - b.offset < b_size;
}

bool region_value_equal(const RegionDecision& a, const RegionDecision& b) {
    return a.begin == b.begin && a.size == b.size && a.kind == b.kind;
}

bool reference_value_equal(const UserReference& a, const UserReference& b) {
    return a.source == b.source && a.target == b.target && a.kind == b.kind;
}

bool function_value_equal(const FunctionDecision& a, const FunctionDecision& b) {
    if (a.entry != b.entry || a.suppressed != b.suppressed) return false;
    auto a_chunks = a.chunks, b_chunks = b.chunks;
    const auto less = [](const DecisionRange& x, const DecisionRange& y) {
        return std::tie(x.begin.space.value, x.begin.offset, x.size) <
               std::tie(y.begin.space.value, y.begin.offset, y.size);
    };
    std::sort(a_chunks.begin(), a_chunks.end(), less);
    std::sort(b_chunks.begin(), b_chunks.end(), less);
    return a_chunks == b_chunks;
}

std::vector<DecisionRange> canonical_chunks(std::vector<DecisionRange> chunks) {
    std::sort(chunks.begin(), chunks.end(), [](const DecisionRange& a, const DecisionRange& b) {
        return std::tie(a.begin.space.value, a.begin.offset, a.size) <
               std::tie(b.begin.space.value, b.begin.offset, b.size);
    });
    return chunks;
}

bool chunks_valid(const std::vector<DecisionRange>& chunks) {
    for (std::size_t i = 0; i < chunks.size(); ++i) {
        if (chunks[i].size == 0 || !AddressRange::create(chunks[i].begin, chunks[i].size)) return false;
        if (i && chunks[i - 1].begin.space == chunks[i].begin.space &&
            ranges_overlap(chunks[i - 1].begin, chunks[i - 1].size, chunks[i].begin, chunks[i].size)) return false;
    }
    return true;
}

std::optional<std::vector<DecisionRange>> merge_function_chunks(
    const std::vector<DecisionRange>& base_input,
    const std::vector<DecisionRange>& proposed_input,
    const std::vector<DecisionRange>& current_input,
    std::stop_token stop) {
    const auto base = canonical_chunks(base_input);
    const auto proposed = canonical_chunks(proposed_input);
    const auto current = canonical_chunks(current_input);
    if (!chunks_valid(base) || !chunks_valid(proposed) || !chunks_valid(current)) return {};

    std::vector<DecisionRange> merged;
    const auto local_chunks = [](const std::vector<DecisionRange>& chunks, const DecisionRange& owner) {
        std::vector<DecisionRange> local;
        for (const auto& chunk : chunks)
            if (ranges_overlap(chunk.begin, chunk.size, owner.begin, owner.size)) local.push_back(chunk);
        return local;
    };
    for (const auto& owner : base) {
        if (stop.stop_requested()) return {};
        const std::vector<DecisionRange> original{owner};
        auto proposed_local = local_chunks(proposed, owner);
        auto current_local = local_chunks(current, owner);
        if (proposed_local == original && current_local == original) {
            merged.push_back(owner);
        } else if (proposed_local == original) {
            merged.insert(merged.end(), current_local.begin(), current_local.end());
        } else if (current_local == original) {
            merged.insert(merged.end(), proposed_local.begin(), proposed_local.end());
        } else if (proposed_local == current_local) {
            merged.insert(merged.end(), proposed_local.begin(), proposed_local.end());
        } else {
            // Both peers changed the same original ownership range in
            // incompatible ways. The caller keeps the proposal pending.
            return {};
        }
    }

    const auto overlaps_base = [&](const DecisionRange& chunk) {
        return std::any_of(base.begin(), base.end(), [&](const DecisionRange& owner) {
            return ranges_overlap(chunk.begin, chunk.size, owner.begin, owner.size);
        });
    };
    std::vector<DecisionRange> additions;
    for (const auto& chunk : proposed) {
        if (stop.stop_requested()) return {};
        if (!overlaps_base(chunk)) additions.push_back(chunk);
    }
    for (const auto& chunk : current) {
        if (stop.stop_requested()) return {};
        if (!overlaps_base(chunk)) additions.push_back(chunk);
    }
    additions = canonical_chunks(std::move(additions));
    additions.erase(std::unique(additions.begin(), additions.end()), additions.end());
    merged.insert(merged.end(), additions.begin(), additions.end());
    merged = canonical_chunks(std::move(merged));
    merged.erase(std::unique(merged.begin(), merged.end()), merged.end());
    if (!chunks_valid(merged)) return {};
    return merged;
}

bool function_contains(const FunctionDecision& function, Address address) {
    return std::any_of(function.chunks.begin(), function.chunks.end(), [&](const DecisionRange& chunk) {
        return chunk.begin.space == address.space && address.offset >= chunk.begin.offset &&
               address.offset - chunk.begin.offset < chunk.size;
    });
}

bool allocate_refreshed_id(std::uint64_t& next_entity, std::uint64_t& id) {
    if (next_entity == 0 || next_entity >= UINT64_MAX - 1) return false;
    id = next_entity++;
    return true;
}

// Rebase metadata, type-definition fields and address-local type assignments
// whose intent is clear. A changed assignment is never resolved by choosing
// an arbitrary side.
std::optional<StateDelta> rebase_metadata(const StateDelta& proposal,
                                          const ProjectState& head,
                                          const ByteStorage* original,
                                          std::stop_token stop,
                                          std::optional<Error>& failure) {
    const auto& current = *head.user;
    auto next_entity = head.next_entity;
    std::set<std::uint64_t> assignment_ids;
    std::set<std::pair<std::uint32_t, std::uint64_t>> assignment_locations;
    std::set<std::uint64_t> region_change_ids, function_change_ids, reference_change_ids;
    std::set<std::uint64_t> changed_region_extents;
    std::vector<std::pair<std::uint64_t, DecisionRange>> added_function_chunks;
    std::vector<std::pair<std::uint64_t, Address>> changed_function_entries;
    auto regions = current.decisions.regions;
    auto functions = current.decisions.functions;
    auto references = current.decisions.references;
    auto types = current.types;
    std::set<std::uint64_t> type_change_ids;
    std::set<std::uint64_t> inserted_type_ids;
    std::map<std::uint64_t, std::uint64_t> type_id_remap;
    bool patch_seen=false;
    StateDelta rebased;
    rebased.changes.reserve(proposal.changes.size());
    for (const auto& change : proposal.changes) {
        if (stop.stop_requested()) {
            failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"};
            return {};
        }
        if (const auto* annotation = std::get_if<AnnotationChange>(&change)) {
            if (!annotation->before || !annotation->after) return {};
            const auto found = std::find_if(current.annotations.begin(), current.annotations.end(),
                [&](const Annotation& row) { return row.id == annotation->before->id; });
            if (found == current.annotations.end() || found->location != annotation->before->location) return {};
            auto merged = *annotation->after;
            auto name = merge_field(annotation->before->name, annotation->after->name, found->name);
            auto comment = merge_field(annotation->before->comment, annotation->after->comment, found->comment);
            if (!name || !comment) return {};
            merged.name = std::move(*name);
            merged.comment = std::move(*comment);
            if(merged!=*found)rebased.changes.emplace_back(AnnotationChange{*found, std::move(merged)});
        } else if (const auto* bookmark = std::get_if<BookmarkChange>(&change)) {
            if (!bookmark->before || !bookmark->after) return {};
            const auto found = std::find_if(current.bookmarks.begin(), current.bookmarks.end(),
                [&](const Bookmark& row) { return row.id == bookmark->before->id; });
            if (found == current.bookmarks.end() || found->location != bookmark->before->location) return {};
            auto label = merge_field(bookmark->before->label, bookmark->after->label, found->label);
            if (!label) return {};
            auto merged = *bookmark->after;
            merged.label = std::move(*label);
            if(merged!=*found)rebased.changes.emplace_back(BookmarkChange{*found, std::move(merged)});
        } else if (const auto* assignment = std::get_if<TypeAssignmentChange>(&change)) {
            if (!assignment->before && !assignment->after) return {};
            const auto& identity = assignment->before ? *assignment->before : *assignment->after;
            const auto* address = std::get_if<Address>(&identity.location);
            if (!address || !assignment_ids.insert(identity.id).second ||
                !assignment_locations.emplace(address->space.value, address->offset).second) return {};
            if (assignment->after) {
                // Moves, identity changes, and missing type definitions need
                // an explicit resolution with domain knowledge.
                if (assignment->after->id != identity.id || assignment->after->location != identity.location) return {};
            }
            if (assignment->before) {
                const auto found = std::find_if(current.type_assignments.begin(), current.type_assignments.end(),
                    [&](const TypeAssignment& row) { return row.id == identity.id; });
                if (found == current.type_assignments.end() || *found != *assignment->before) return {};
                if(assignment->after!=std::optional<TypeAssignment>{*found})rebased.changes.emplace_back(*assignment);
            } else {
                if (std::any_of(current.type_assignments.begin(), current.type_assignments.end(),
                        [&](const TypeAssignment& row) { return row.location == identity.location; }) ||
                    next_entity >= UINT64_MAX - 1) return {};
                // Concurrent insertions may have consumed the proposal's ID.
                // Assignment IDs have no inbound references; allocate from the
                // refreshed head and retain the actual ID in normal history.
                auto inserted = *assignment->after;
                inserted.id = next_entity++;
                rebased.changes.emplace_back(TypeAssignmentChange{{}, std::move(inserted)});
            }
        } else if (const auto* type = std::get_if<TypeDefinitionChange>(&change)) {
            if ((!type->before && !type->after) ||
                (type->before && type->after && type->before->id != type->after->id)) return {};
            const auto identity = type->before ? type->before->id : type->after->id;
            if (!type_change_ids.insert(identity).second) return {};
            if (!type->before) {
                if (!type->after->type || type->after->name.empty() ||
                    !inserted_type_ids.insert(identity).second) return {};
                auto inserted = *type->after;
                const auto same = std::find_if(types.begin(), types.end(), [&](const TypeDefinition& row) {
                    return row.name == inserted.name && row.origin == inserted.origin && row.declaration_kind == inserted.declaration_kind &&
                           same_type(row.type, inserted.type);
                });
                if (same != types.end()) {
                    type_id_remap.emplace(inserted.id, same->id);
                    continue;
                }
                if (std::any_of(types.begin(), types.end(), [&](const TypeDefinition& row) {
                        return row.name == inserted.name;
                    })) return {};
                const auto old_id = inserted.id;
                if (!allocate_refreshed_id(next_entity, inserted.id)) return {};
                type_id_remap.emplace(old_id, inserted.id);
                types.push_back(inserted);
                rebased.changes.emplace_back(TypeDefinitionChange{{}, std::move(inserted)});
            } else {
                auto found = std::find_if(types.begin(), types.end(), [&](const TypeDefinition& row) {
                    return row.id == identity;
                });
                if (found == types.end()) return {};
                if (!type->after) {
                    if (!same_definition(*found, *type->before) ||
                        std::any_of(current.type_assignments.begin(), current.type_assignments.end(),
                            [&](const TypeAssignment& row) { return row.type_id == identity; }) ||
                        std::any_of(current.debug_variables.begin(), current.debug_variables.end(),
                            [&](const DebugVariable& row) { return row.type_id == identity; }) ||
                        type_name_is_referenced(types, identity, found->name)) return {};
                    const auto before = *found;
                    types.erase(found);
                    rebased.changes.emplace_back(TypeDefinitionChange{before, {}});
                    continue;
                }
                const auto& proposed = *type->after;
                if (!proposed.type) return {};
                auto name = merge_field(type->before->name, proposed.name, found->name);
                auto origin = merge_field(type->before->origin, proposed.origin, found->origin);
                auto kind = merge_field(type->before->declaration_kind, proposed.declaration_kind, found->declaration_kind);
                auto layout = merge_type(type->before->type, proposed.type, found->type);
                if (!name || !origin || !kind || !layout || name->empty()) return {};
                if (*name != found->name &&
                    (std::any_of(types.begin(), types.end(), [&](const TypeDefinition& row) {
                         return row.id != identity && row.name == *name;
                     }) ||
                     type_name_is_referenced(types, identity, found->name) ||
                     type_name_is_referenced(types, identity, *name) ||
                     type_references_name(*layout, found->name) ||
                     type_references_name(*layout, *name))) return {};
                TypeDefinition merged{identity, std::move(*name), std::move(*layout), std::move(*origin), *kind};
                if (!same_definition(merged, *found)) {
                    const auto before = *found;
                    *found = merged;
                    rebased.changes.emplace_back(TypeDefinitionChange{before, std::move(merged)});
                }
            }
        } else if (const auto* region = std::get_if<RegionChange>(&change)) {
            if ((!region->before && !region->after) ||
                !region_change_ids.insert(region->before ? region->before->id : region->after->id).second) return {};
            if (region->before && region->after && region->before->id != region->after->id) return {};
            if (!region->before) {
                const auto& proposed_row = *region->after;
                const auto same = std::find_if(regions.begin(), regions.end(), [&](const RegionDecision& row) {
                    return region_value_equal(row, proposed_row);
                });
                if (same != regions.end()) continue;
                if (std::any_of(regions.begin(), regions.end(), [&](const RegionDecision& row) {
                        return ranges_overlap(row.begin, row.size, proposed_row.begin, proposed_row.size);
                    })) return {};
                auto inserted = proposed_row;
                if (!allocate_refreshed_id(next_entity, inserted.id)) return {};
                regions.push_back(inserted);
                changed_region_extents.insert(inserted.id);
                rebased.changes.emplace_back(RegionChange{{}, std::move(inserted)});
                continue;
            }
            const auto found = std::find_if(regions.begin(), regions.end(), [&](const RegionDecision& row) {
                return row.id == region->before->id;
            });
            if (found == regions.end()) {
                if (!region->after) {
                    if (std::any_of(regions.begin(), regions.end(), [&](const RegionDecision& row) {
                            return ranges_overlap(row.begin, row.size, region->before->begin, region->before->size);
                        })) return {};
                    continue; // Concurrent deletion already achieved.
                }
                if (std::any_of(regions.begin(), regions.end(), [&](const RegionDecision& row) {
                        return region_value_equal(row, *region->after);
                    })) continue;
                return {};
            }
            if (!region->after) {
                if (*found != *region->before) return {};
                const auto before = *found;
                regions.erase(found);
                rebased.changes.emplace_back(RegionChange{before, {}});
                continue;
            }
            const RegionExtent base_extent{region->before->begin, region->before->size};
            const RegionExtent proposed_extent{region->after->begin, region->after->size};
            const RegionExtent current_extent{found->begin, found->size};
            auto extent = merge_field(base_extent, proposed_extent, current_extent);
            auto kind = merge_field(region->before->kind, region->after->kind, found->kind);
            if (!extent || !kind || extent->size == 0 || !AddressRange::create(extent->begin, extent->size)) return {};
            RegionDecision merged{found->id, extent->begin, extent->size, *kind};
            if (merged == *found) continue;
            const auto before = *found;
            if (extent.value() != current_extent) changed_region_extents.insert(merged.id);
            *found = merged;
            rebased.changes.emplace_back(RegionChange{before, std::move(merged)});
        } else if (const auto* function = std::get_if<FunctionChange>(&change)) {
            if ((!function->before && !function->after) ||
                !function_change_ids.insert(function->before ? function->before->id : function->after->id).second) return {};
            if (function->before && function->after && function->before->id != function->after->id) return {};
            if (!function->before) {
                const auto& proposed_row = *function->after;
                const auto same_entry = std::find_if(functions.begin(), functions.end(), [&](const FunctionDecision& row) {
                    return row.entry == proposed_row.entry;
                });
                if (same_entry != functions.end()) {
                    if (function_value_equal(*same_entry, proposed_row)) continue;
                    return {};
                }
                auto inserted = proposed_row;
                inserted.chunks = canonical_chunks(std::move(inserted.chunks));
                if (!chunks_valid(inserted.chunks) ||
                    (!inserted.chunks.empty() && !function_contains(inserted, inserted.entry))) return {};
                if (!allocate_refreshed_id(next_entity, inserted.id)) return {};
                for (const auto& chunk : inserted.chunks) added_function_chunks.emplace_back(inserted.id, chunk);
                changed_function_entries.emplace_back(inserted.id, inserted.entry);
                functions.push_back(inserted);
                rebased.changes.emplace_back(FunctionChange{{}, std::move(inserted)});
                continue;
            }
            const auto found = std::find_if(functions.begin(), functions.end(), [&](const FunctionDecision& row) {
                return row.id == function->before->id;
            });
            if (found == functions.end()) {
                if (!function->after) {
                    for (const auto& row : functions) {
                        if (row.entry == function->before->entry) return {};
                        for (const auto& old_chunk : function->before->chunks)
                            for (const auto& current_chunk : row.chunks)
                                if (ranges_overlap(old_chunk.begin, old_chunk.size,
                                                   current_chunk.begin, current_chunk.size)) return {};
                    }
                    continue;
                }
                if (std::any_of(functions.begin(), functions.end(), [&](const FunctionDecision& row) {
                        return function_value_equal(row, *function->after);
                    })) continue;
                return {};
            }
            if (!function->after) {
                if (*found != *function->before) return {};
                const auto before = *found;
                functions.erase(found);
                rebased.changes.emplace_back(FunctionChange{before, {}});
                continue;
            }
            auto entry = merge_field(function->before->entry, function->after->entry, found->entry);
            auto suppressed = merge_field(function->before->suppressed, function->after->suppressed, found->suppressed);
            auto chunks = merge_function_chunks(function->before->chunks, function->after->chunks, found->chunks, stop);
            if (stop.stop_requested()) {
                failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"};
                return {};
            }
            if (!entry || !suppressed || !chunks || (!chunks->empty() &&
                std::none_of(chunks->begin(), chunks->end(), [&](const DecisionRange& chunk) {
                    return chunk.begin.space == entry->space && entry->offset >= chunk.begin.offset &&
                           entry->offset - chunk.begin.offset < chunk.size;
                }))) return {};
            FunctionDecision merged{found->id, *entry, *suppressed, std::move(*chunks)};
            if (merged == *found) continue;
            const auto before = *found;
            for (const auto& chunk : merged.chunks)
                if (std::find(before.chunks.begin(), before.chunks.end(), chunk) == before.chunks.end())
                    added_function_chunks.emplace_back(merged.id, chunk);
            if (merged.entry != before.entry) changed_function_entries.emplace_back(merged.id, merged.entry);
            *found = merged;
            rebased.changes.emplace_back(FunctionChange{before, std::move(merged)});
        } else if (const auto* reference = std::get_if<ReferenceChange>(&change)) {
            if ((!reference->before && !reference->after) ||
                !reference_change_ids.insert(reference->before ? reference->before->id : reference->after->id).second) return {};
            if (reference->before && reference->after && reference->before->id != reference->after->id) return {};
            if (!reference->before) {
                const auto& proposed_row = *reference->after;
                const auto same_id = std::find_if(references.begin(), references.end(), [&](const UserReference& row) {
                    return row.id == proposed_row.id;
                });
                // Reference IDs identify a specific edge. Reusing an ID for a
                // different target is ambiguous, unlike a harmless allocation
                // race for a new region or function row.
                if (same_id != references.end()) {
                    if (reference_value_equal(*same_id, proposed_row)) continue;
                    return {};
                }
                if (std::any_of(references.begin(), references.end(), [&](const UserReference& row) {
                        return reference_value_equal(row, proposed_row);
                    })) continue;
                auto inserted = proposed_row;
                if (!allocate_refreshed_id(next_entity, inserted.id)) return {};
                references.push_back(inserted);
                rebased.changes.emplace_back(ReferenceChange{{}, std::move(inserted)});
                continue;
            }
            const auto found = std::find_if(references.begin(), references.end(), [&](const UserReference& row) {
                return row.id == reference->before->id;
            });
            if (found == references.end()) {
                if (!reference->after) {
                    if (std::any_of(references.begin(), references.end(), [&](const UserReference& row) {
                            return reference_value_equal(row, *reference->before);
                        })) return {};
                    continue;
                }
                if (std::any_of(references.begin(), references.end(), [&](const UserReference& row) {
                        return reference_value_equal(row, *reference->after);
                    })) continue;
                return {};
            }
            if (!reference->after) {
                if (*found != *reference->before) return {};
                const auto before = *found;
                references.erase(found);
                rebased.changes.emplace_back(ReferenceChange{before, {}});
                continue;
            }
            auto source = merge_field(reference->before->source, reference->after->source, found->source);
            auto target = merge_field(reference->before->target, reference->after->target, found->target);
            auto kind = merge_field(reference->before->kind, reference->after->kind, found->kind);
            if (!source || !target || !kind) return {};
            UserReference merged{found->id, std::move(*source), std::move(*target), *kind};
            if (merged == *found) continue;
            if (std::any_of(references.begin(), references.end(), [&](const UserReference& row) {
                    return row.id != merged.id && reference_value_equal(row, merged);
                })) return {};
            const auto before = *found;
            *found = merged;
            rebased.changes.emplace_back(ReferenceChange{before, std::move(merged)});
        } else if (const auto* patch=std::get_if<PatchChange>(&change)) {
            if(!original || patch_seen)return {};
            patch_seen=true;
            auto merged=merge_patch_spans(*original,patch->before,patch->after,current.patches,stop);
            if(!merged){failure=merged.error();return {};}
            if(!merged.value())return {};
            if(*merged.value()!=current.patches)
                rebased.changes.emplace_back(PatchChange{current.patches,std::move(*merged.value())});
        } else {
            // Debug-variable and other structural changes still require a
            // caller-authored rebase with domain knowledge.
            return {};
        }
    }

    // A type can be inserted after an assignment in a command's original
    // ordering. Resolve those forward references after every type definition
    // has been projected, while keeping the serialized delta self-contained.
    for (auto& change : rebased.changes) {
        auto* assignment = std::get_if<TypeAssignmentChange>(&change);
        if (!assignment || !assignment->after) continue;
        if (const auto mapped = type_id_remap.find(assignment->after->type_id);
            mapped != type_id_remap.end()) assignment->after->type_id = mapped->second;
        if (std::none_of(types.begin(), types.end(), [&](const TypeDefinition& row) {
                return row.id == assignment->after->type_id;
            })) return {};
    }

    // A region/function ID does not make overlapping ownership independent.
    // Check the complete projected head after all removals and insertions so
    // the result is independent of proposal change ordering.
    // Range queries are indexed by sorted boundaries. Only pathological
    // candidate scans consume the conservative work budget.
    std::size_t validation_work = 0;
    const auto consume_validation_work = [&]() {
        return ++validation_work <= 1'000'000 && !stop.stop_requested();
    };
    auto sorted_regions = regions;
    std::sort(sorted_regions.begin(), sorted_regions.end(), [](const RegionDecision& a, const RegionDecision& b) {
        return std::tie(a.begin.space.value, a.begin.offset, a.size) <
               std::tie(b.begin.space.value, b.begin.offset, b.size);
    });
    std::optional<RegionDecision> furthest;
    std::uint64_t furthest_end = 0;
    for (const auto& region : sorted_regions) {
        if (stop.stop_requested()) { failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"}; return {}; }
        const auto end = region.begin.offset + region.size;
        if (furthest && furthest->begin.space == region.begin.space && region.begin.offset < furthest_end &&
            (changed_region_extents.contains(furthest->id) || changed_region_extents.contains(region.id))) return {};
        if (!furthest || furthest->begin.space != region.begin.space || end > furthest_end) {
            furthest = region;
            furthest_end = end;
        }
    }

    struct OwnedChunk { Address begin; std::uint64_t end; std::uint64_t function_id; };
    std::vector<OwnedChunk> owned_chunks;
    std::vector<std::pair<Address, std::uint64_t>> entries;
    for (const auto& function : functions) {
        if (stop.stop_requested()) { failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"}; return {}; }
        entries.emplace_back(function.entry, function.id);
        for (const auto& chunk : function.chunks)
            owned_chunks.push_back({chunk.begin, chunk.begin.offset + chunk.size, function.id});
    }
    const auto address_less = [](Address a, Address b) {
        return std::tie(a.space.value, a.offset) < std::tie(b.space.value, b.offset);
    };
    std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
        if (address_less(a.first, b.first)) return true;
        if (address_less(b.first, a.first)) return false;
        return a.second < b.second;
    });
    std::sort(owned_chunks.begin(), owned_chunks.end(), [](const OwnedChunk& a, const OwnedChunk& b) {
        return std::tie(a.begin.space.value, a.begin.offset, a.end, a.function_id) <
               std::tie(b.begin.space.value, b.begin.offset, b.end, b.function_id);
    });
    std::vector<std::uint64_t> prefix_max_end(owned_chunks.size());
    std::uint32_t prefix_space = 0;
    std::uint64_t space_max_end = 0;
    for (std::size_t i = 0; i < owned_chunks.size(); ++i) {
        if ((i & 0x3ffu) == 0 && stop.stop_requested()) { failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"}; return {}; }
        if (i == 0 || owned_chunks[i].begin.space.value != prefix_space) {
            prefix_space = owned_chunks[i].begin.space.value;
            space_max_end = owned_chunks[i].end;
        } else space_max_end = std::max(space_max_end, owned_chunks[i].end);
        prefix_max_end[i] = space_max_end;
    }
    const auto budget_exceeded = [&]() -> std::optional<StateDelta> {
        if (stop.stop_requested()) failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"};
        else failure = Error{ErrorCode::resource_limit, "Collaboration decision overlap query exceeded its candidate limit"};
        return {};
    };
    for (const auto& added : added_function_chunks) {
        if (stop.stop_requested()) { failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"}; return {}; }
        const auto end = added.second.begin.offset + added.second.size;
        auto first = std::lower_bound(owned_chunks.begin(), owned_chunks.end(), added.second.begin,
            [](const OwnedChunk& row, Address address) { return std::tie(row.begin.space.value, row.begin.offset) < std::tie(address.space.value, address.offset); });
        auto index = static_cast<std::size_t>(first - owned_chunks.begin());
        for (auto i = index; i > 0;) {
            --i;
            const auto& candidate = owned_chunks[i];
            if (candidate.begin.space != added.second.begin.space || prefix_max_end[i] <= added.second.begin.offset) break;
            if (!consume_validation_work()) return budget_exceeded();
            if (candidate.function_id != added.first && candidate.end > added.second.begin.offset) return {};
        }
        for (auto i = index; i < owned_chunks.size(); ++i) {
            const auto& candidate = owned_chunks[i];
            if (candidate.begin.space != added.second.begin.space || candidate.begin.offset >= end) break;
            if (!consume_validation_work()) return budget_exceeded();
            if (candidate.function_id != added.first) return {};
        }
        auto entry = std::lower_bound(entries.begin(), entries.end(), added.second.begin,
            [&](const auto& row, Address address) { return address_less(row.first, address); });
        for (; entry != entries.end() && entry->first.space == added.second.begin.space && entry->first.offset < end; ++entry) {
            if (!consume_validation_work()) return budget_exceeded();
            if (entry->first.offset >= added.second.begin.offset && entry->second != added.first) return {};
        }
    }
    for (const auto& [function_id, entry] : changed_function_entries) {
        if (stop.stop_requested()) { failure = Error{ErrorCode::canceled, "Collaboration rebase canceled"}; return {}; }
        auto same = std::lower_bound(entries.begin(), entries.end(), entry,
            [&](const auto& row, Address address) { return address_less(row.first, address); });
        for (auto candidate = same; candidate != entries.end() && candidate->first == entry; ++candidate) {
            if (!consume_validation_work()) return budget_exceeded();
            if (candidate->second != function_id) return {};
        }
        auto first = std::lower_bound(owned_chunks.begin(), owned_chunks.end(), entry,
            [](const OwnedChunk& row, Address address) { return std::tie(row.begin.space.value, row.begin.offset) < std::tie(address.space.value, address.offset); });
        auto index = static_cast<std::size_t>(first - owned_chunks.begin());
        for (auto i = index; i > 0;) {
            --i;
            const auto& candidate = owned_chunks[i];
            if (candidate.begin.space != entry.space || prefix_max_end[i] <= entry.offset) break;
            if (!consume_validation_work()) return budget_exceeded();
            if (candidate.function_id != function_id && candidate.end > entry.offset) return {};
        }
        for (auto i = index; i < owned_chunks.size(); ++i) {
            const auto& candidate = owned_chunks[i];
            if (candidate.begin.space != entry.space || candidate.begin.offset > entry.offset) break;
            if (!consume_validation_work()) return budget_exceeded();
            if (candidate.function_id != function_id && candidate.end > entry.offset) return {};
        }
    }
    return rebased;
}
}

ProjectCollaboration::ProjectCollaboration(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Result<std::shared_ptr<ProjectCollaboration>> ProjectCollaboration::open(
    const std::filesystem::path& path, std::stop_token stop) {
    return detail::guarded([&]() -> Result<std::shared_ptr<ProjectCollaboration>> {
        auto impl = std::make_unique<Impl>();
        impl->project = take(ProjectStore::open_collaborative(path, stop));
        impl->connection = take(Connection::open(path, OpenMode::read_write, stop));
        auto result = std::shared_ptr<ProjectCollaboration>(new ProjectCollaboration(std::move(impl)));
        return result;
    });
}

std::shared_ptr<ProjectStore> ProjectCollaboration::project() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->project;
}

Result<std::shared_ptr<const ProjectState>> ProjectCollaboration::refresh(std::stop_token stop) {
    return detail::guarded([&]() -> Result<std::shared_ptr<const ProjectState>> {
        std::lock_guard lock(impl_->mutex);
        auto refreshed = take(ProjectStore::open_collaborative(impl_->project->path(), stop));
        auto state = take(refreshed->snapshot());
        impl_->project = std::move(refreshed);
        return state;
    });
}

Result<CollaborationSubmission> ProjectCollaboration::submit(
    std::uint64_t base_revision, const StateDelta& proposal, std::uint64_t group,
    std::stop_token stop) {
    auto committed = impl_->project->commit(base_revision, proposal, group, stop);
    if (committed) return CollaborationSubmission{committed.value(), {}};
    if (committed.error().code != ErrorCode::conflict) return committed.error();
    // Refresh the head and attempt a safe field-wise rebase. A second
    // revision race falls through to the durable conflict inbox below.
    auto latest = refresh(stop);
    if (!latest) return latest.error();
    if (base_revision > latest.value()->revisions.edit)
        return Error{ErrorCode::invalid_argument,
                     "Collaboration proposal base revision is newer than the project head"};
    std::shared_ptr<const ByteStorage> original;
    if(std::any_of(proposal.changes.begin(),proposal.changes.end(),
                   [](const UserChange& change){return std::holds_alternative<PatchChange>(change);} )){
        auto input=impl_->project->materialize_input(stop);
        if(!input)return input.error();
        original=std::move(input.value());
    }
    std::optional<Error> rebase_failure;
    if (auto rebased = rebase_metadata(proposal, *latest.value(), original.get(), stop, rebase_failure)) {
        if(rebased->changes.empty())
            return CollaborationSubmission{CommitAck{latest.value()->revisions,latest.value()->history_cursor},{}};
        auto merged = impl_->project->commit(latest.value()->revisions.edit, *rebased, group, stop);
        if (merged) return CollaborationSubmission{merged.value(), {}};
        if (merged.error().code != ErrorCode::conflict) return merged.error();
    }
    if(rebase_failure)return *rebase_failure;
    return detail::guarded([&]() -> Result<CollaborationSubmission> {
        const auto encoded = detail::encode_delta(proposal);
        std::lock_guard lock(impl_->mutex);
        detail::Cancellation cancellation(*impl_->connection, stop);
        auto transaction = take(Transaction::begin(*impl_->connection));
        auto current = take(impl_->connection->prepare("SELECT edit_revision FROM project WHERE singleton=1"));
        if (!take(current->step())) throw Failure{{ErrorCode::integrity, "Project header is missing"}};
        const auto observed = take(decode_u64(take(current->blob(0))));
        auto insert = take(impl_->connection->prepare(
            "INSERT INTO collaboration_conflicts(base_revision,observed_revision,proposal) VALUES(?1,?2,?3)"));
        take(insert->bind_blob(1, encode_u64(base_revision)));
        take(insert->bind_blob(2, encode_u64(observed)));
        take(insert->bind_blob(3, encoded));
        take(insert->step());
        auto id_query = take(impl_->connection->prepare("SELECT last_insert_rowid()"));
        if (!take(id_query->step())) throw Failure{{ErrorCode::io, "Conflict record ID was not returned"}};
        CollaborationConflict conflict;
        conflict.id = static_cast<std::uint64_t>(take(id_query->integer(0)));
        conflict.base_revision = base_revision;
        conflict.observed_revision = observed;
        conflict.proposal = proposal;
        take(transaction->commit());
        return CollaborationSubmission{{}, std::move(conflict)};
    });
}

Result<std::vector<CollaborationConflict>> ProjectCollaboration::conflicts(
    bool include_resolved, std::stop_token stop) {
    return detail::guarded([&]() -> Result<std::vector<CollaborationConflict>> {
        std::lock_guard lock(impl_->mutex);
        detail::Cancellation cancellation(*impl_->connection, stop);
        auto query = take(impl_->connection->prepare(
            include_resolved
                ? "SELECT id,base_revision,observed_revision,proposal,resolved,accepted FROM collaboration_conflicts ORDER BY id"
                : "SELECT id,base_revision,observed_revision,proposal,resolved,accepted FROM collaboration_conflicts WHERE resolved=0 ORDER BY id"));
        std::vector<CollaborationConflict> rows;
        while (take(query->step())) {
            if (rows.size() >= project_record_limit) throw Failure{{ErrorCode::resource_limit, "Too many collaboration conflicts"}};
            CollaborationConflict row;
            row.id = static_cast<std::uint64_t>(take(query->integer(0)));
            row.base_revision = take(decode_u64(take(query->blob(1))));
            row.observed_revision = take(decode_u64(take(query->blob(2))));
            row.proposal = detail::decode_delta(take(query->blob(3)));
            row.resolved = take(query->integer(4)) != 0;
            row.accepted = take(query->integer(5)) != 0;
            rows.push_back(std::move(row));
        }
        return rows;
    });
}

Result<std::optional<StateDelta>> ProjectCollaboration::preview_resolution(
    std::uint64_t id, std::uint64_t expected_revision, std::stop_token stop) {
    if (id == 0 || id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        return Error{ErrorCode::invalid_argument, "Invalid collaboration conflict ID"};
    auto latest = refresh(stop);
    if (!latest) return latest.error();
    if (latest.value()->revisions.edit != expected_revision)
        return Error{ErrorCode::conflict, "Project changed before collaboration resolution preview"};
    auto pending = conflicts(false, stop);
    if (!pending) return pending.error();
    const auto found = std::find_if(pending.value().begin(), pending.value().end(),
        [&](const CollaborationConflict& conflict) { return conflict.id == id; });
    if (found == pending.value().end())
        return Error{ErrorCode::conflict, "Collaboration proposal is no longer pending"};

    std::shared_ptr<const ByteStorage> original;
    if (std::any_of(found->proposal.changes.begin(), found->proposal.changes.end(),
            [](const UserChange& change) { return std::holds_alternative<PatchChange>(change); })) {
        auto input = impl_->project->materialize_input(stop);
        if (!input) return input.error();
        original = std::move(input.value());
    }
    std::optional<Error> failure;
    auto resolution = rebase_metadata(found->proposal, *latest.value(), original.get(), stop, failure);
    if (failure) return *failure;
    return resolution;
}

Result<CommitAck> ProjectCollaboration::resolve(
    std::uint64_t id, bool accept_proposal, std::uint64_t expected_revision,
    const StateDelta& rebased_resolution, std::uint64_t group, std::stop_token stop) {
    return detail::guarded([&]() -> Result<CommitAck> {
        if (!accept_proposal) return Error{ErrorCode::invalid_argument, "Use dismiss to keep the current project state"};
        // The project delta and inbox status update now share the ProjectStore
        // writer transaction, so neither can commit without the other.
        return impl_->project->commit_resolving_conflict(id,expected_revision,rebased_resolution,group,stop);
    });
}

Result<bool> ProjectCollaboration::dismiss(std::uint64_t id, std::uint64_t expected_revision,
                                            std::stop_token stop) {
    if (id == 0 || id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        return Error{ErrorCode::invalid_argument, "Invalid collaboration conflict ID"};
    return detail::guarded([&]() -> Result<bool> {
        std::lock_guard lock(impl_->mutex);
        detail::Cancellation cancellation(*impl_->connection, stop);
        auto transaction = take(Transaction::begin(*impl_->connection));
        auto header = take(impl_->connection->prepare("SELECT edit_revision FROM project WHERE singleton=1"));
        if (!take(header->step())) throw Failure{{ErrorCode::integrity, "Project header is missing"}};
        const auto current = take(decode_u64(take(header->blob(0))));
        if (current != expected_revision) return Error{ErrorCode::conflict, "Project changed before conflict dismissal"};
        auto update = take(impl_->connection->prepare(
            "UPDATE collaboration_conflicts SET resolved=1,accepted=0,resolution_revision=?1 WHERE id=?2 AND resolved=0"));
        take(update->bind_blob(1, encode_u64(current)));
        take(update->bind_integer(2, static_cast<std::int64_t>(id)));
        take(update->step());
        auto changed = take(impl_->connection->prepare("SELECT changes()"));
        if (!take(changed->step()) || take(changed->integer(0)) != 1)
            return Error{ErrorCode::conflict, "Unknown or already resolved collaboration conflict"};
        take(transaction->commit());
        return true;
    });
}
}
