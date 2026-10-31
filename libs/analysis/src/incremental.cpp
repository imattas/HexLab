#include "hexlab/analysis/incremental.hpp"
#include "functions_internal.hpp"
#include "instruction_flow.hpp"
#include "strings_internal.hpp"
#include <algorithm>
#include <map>
#include <span>
#include <type_traits>
namespace hexlab {
namespace {
using function_detail::Failure;
using function_detail::require;
using function_detail::take;
void canceled(std::stop_token stop) {
    if (stop.stop_requested())
        throw Failure{{ErrorCode::canceled, "Incremental analysis canceled"}};
}
template <class T>
void copy_cancelable(std::vector<T> &destination, const std::vector<T> &source, std::stop_token stop) {
    canceled(stop);
    destination.reserve(source.size());
    canceled(stop);
    for (const auto &value : source) {
        canceled(stop);
        destination.push_back(value);
    }
}
FunctionStackRecord copy_stack_record_cancelable(const FunctionStackRecord &source, std::stop_token stop) {
    canceled(stop);
    FunctionStackRecord copy;
    copy.function = source.function;
    copy.frame.maximum_stack_allocation_bytes = source.frame.maximum_stack_allocation_bytes;
    copy.frame.complete = source.frame.complete;
    copy.frame.slots.reserve(source.frame.slots.size());
    canceled(stop);
    for (const auto &slot : source.frame.slots) {
        canceled(stop);
        StackSlot cloned;
        cloned.offset_from_entry_sp = slot.offset_from_entry_sp;
        cloned.width = slot.width;
        cloned.read = slot.read;
        cloned.written = slot.written;
        cloned.address_taken = slot.address_taken;
        cloned.incoming_argument = slot.incoming_argument;
        cloned.incoming_argument_abi = slot.incoming_argument_abi;
        copy_cancelable(cloned.accesses, slot.accesses, stop);
        copy_cancelable(cloned.access_details, slot.access_details, stop);
        copy_cancelable(cloned.outgoing_call_arguments, slot.outgoing_call_arguments, stop);
        copy.frame.slots.push_back(std::move(cloned));
    }
    canceled(stop);
    return copy;
}
std::shared_ptr<FunctionSnapshot> clone_snapshot(const FunctionSnapshot &source, std::stop_token stop) {
    auto copy = std::make_shared<FunctionSnapshot>();
    copy_cancelable(copy->functions, source.functions, stop);
    copy_cancelable(copy->blocks, source.blocks, stop);
    copy_cancelable(copy->instructions, source.instructions, stop);
    copy_cancelable(copy->calls, source.calls, stop);
    copy_cancelable(copy->candidates, source.candidates, stop);
    copy_cancelable(copy->conflicts, source.conflicts, stop);
    copy_cancelable(copy->dependencies, source.dependencies, stop);
    copy->key = source.key;
    copy->complete = source.complete;
    copy->omitted_functions = source.omitted_functions;
    copy->omitted_blocks = source.omitted_blocks;
    canceled(stop);
    return copy;
}
template <class F> auto guarded(F f) -> decltype(f()) {
    try {
        return f();
    } catch (const Failure &error) {
        return error.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate incremental analysis"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Incremental analysis exceeds allocation limits"};
    }
}
void validate_basis(const AnalysisBasis &old) {
    require(old.image && old.metadata && old.functions && old.references && old.strings,
            "Incremental analysis requires a complete source basis");
    require(old.functions->key == old.key && old.references->key() == old.key,
            "Derived basis has inconsistent source keys");
    require(old.image->storage()->size() == old.key.input.size,
            "Derived basis input extent does not match source identity");
}
std::vector<FunctionStackRecord> derive_stack_frames(
    const FunctionSnapshot &snapshot, const FunctionSnapshot *prior_snapshot,
    std::span<const FunctionStackRecord> prior, std::stop_token stop,
    std::optional<CallingConvention> image_default_convention, bool abi_unchanged = true) {
    std::map<FunctionId, const FunctionStackRecord *> old;
    for (const auto &record : prior) {
        canceled(stop);
        old.emplace(record.function, &record);
    }
    std::map<FunctionId, std::shared_ptr<const FunctionRecord>> old_functions;
    std::map<BlockId, std::shared_ptr<const BasicBlock>> old_blocks;
    std::map<BlockId, std::shared_ptr<const BasicBlock>> current_blocks;
    for (const auto &block : snapshot.blocks) {
        canceled(stop);
        current_blocks.emplace(block->id, block);
    }
    if (prior_snapshot) {
        for (const auto &function : prior_snapshot->functions) {
            canceled(stop);
            old_functions.emplace(function->id, function);
        }
        for (const auto &block : prior_snapshot->blocks) {
            canceled(stop);
            old_blocks.emplace(block->id, block);
        }
    }
    std::vector<FunctionStackRecord> frames;
    frames.reserve(snapshot.functions.size());
    for (const auto &function : snapshot.functions) {
        canceled(stop);
        auto cached = old.find(function->id);
        bool unchanged = prior_snapshot && cached != old.end() && abi_unchanged;
        if (unchanged) {
            auto old_function = old_functions.find(function->id);
            unchanged = old_function != old_functions.end() && *old_function->second == *function;
            for (auto block_id : function->blocks) {
                canceled(stop);
                if (!unchanged) break;
                auto previous = old_blocks.find(block_id);
                auto current = current_blocks.find(block_id);
                unchanged = previous != old_blocks.end() && current != current_blocks.end() &&
                            *previous->second == *current->second;
            }
        }
        if (unchanged) {
            frames.push_back(copy_stack_record_cancelable(*cached->second, stop));
        } else {
            // Stack transfer only follows blocks owned by this function. Passing
            // the whole recovered image here made a full analysis rescan every
            // block once per function; build a bounded per-function view instead.
            FunctionSnapshot function_view;
            function_view.blocks.reserve(function->blocks.size());
            for (const auto block_id : function->blocks) {
                canceled(stop);
                const auto block = current_blocks.find(block_id);
                if (block != current_blocks.end())
                    function_view.blocks.push_back(block->second);
            }
            frames.push_back({function->id, take(analyze_stack_frame(*function, function_view, stop,
                                                                    image_default_convention))});
        }
    }
    return frames;
}
bool instruction_hit(const InstructionFact &fact, const ReadSet &changes) {
    for (auto range : fact.reads.ranges())
        if (take(changes.intersects(range.begin, range.size)))
            return true;
    return false;
}
bool instruction_bytes_match(const InstructionFact &fact, const Image &image, std::stop_token stop) {
    canceled(stop);
    const auto &instruction = fact.instruction;
    const auto encoded = instruction.encoded_bytes();
    if (!instruction.length || instruction.length != encoded.size())
        return false;
    const auto bytes = image.read(instruction.address, instruction.length);
    canceled(stop);
    return bytes && bytes.value().size() == instruction.length &&
           std::equal(bytes.value().begin(), bytes.value().end(), encoded.begin());
}
bool effective_images_match(const Image &left, const Image &right, std::stop_token stop) {
    const auto &left_storage = *left.storage();
    const auto &right_storage = *right.storage();
    if (&left_storage == &right_storage)
        return true;
    if (left_storage.size() != right_storage.size())
        return false;
    constexpr std::size_t chunk_size = 64 * 1024;
    for (std::uint64_t offset = 0; offset < left_storage.size();) {
        canceled(stop);
        const auto count = static_cast<std::size_t>(
            std::min<std::uint64_t>(chunk_size, left_storage.size() - offset));
        const auto left_bytes = take(left_storage.read_at({offset}, count));
        const auto right_bytes = take(right_storage.read_at({offset}, count));
        canceled(stop);
        if (left_bytes.bytes.size() != count || right_bytes.bytes.size() != count ||
            !std::equal(left_bytes.bytes.begin(), left_bytes.bytes.end(), right_bytes.bytes.begin()))
            return false;
        offset += count;
    }
    return true;
}
// String recognition reads file bytes and uses only the segment-to-file
// address mapping to attach virtual addresses. Processor contexts and code
// policy do not affect its output.
bool same_string_mapping(const Image &left, const Image &right, std::stop_token stop) {
    if (left.storage()->size() != right.storage()->size() ||
        left.layout().space != right.layout().space)
        return false;
    const auto &left_segments = left.layout().segments;
    const auto &right_segments = right.layout().segments;
    if (left_segments.size() != right_segments.size())
        return false;
    for (std::size_t index = 0; index < left_segments.size(); ++index) {
        canceled(stop);
        if (left_segments[index] != right_segments[index])
            return false;
    }
    return true;
}
template <class Values, class Equal>
bool equal_values_cancelable(const Values &left, const Values &right,
                             std::stop_token stop, Equal equal) {
    canceled(stop);
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        canceled(stop);
        if (!equal(left[index], right[index])) return false;
    }
    return true;
}
bool equal_arm_sources_cancelable(const std::vector<ArmContextSource> &left,
                                  const std::vector<ArmContextSource> &right,
                                  std::stop_token stop) {
    return equal_values_cancelable(left, right, stop, [](const auto &a, const auto &b) {
        return a == b;
    });
}
bool equal_layout_cancelable(const ImageLayout &left, const ImageLayout &right,
                             std::stop_token stop) {
    canceled(stop);
    if (left.space != right.space || left.architecture != right.architecture ||
        left.mode != right.mode || left.stack_address_width != right.stack_address_width ||
        left.segmented_memory != right.segmented_memory ||
        !equal_values_cancelable(left.segments, right.segments, stop, [](const auto &a, const auto &b) {
            return a == b;
        }) ||
        !equal_values_cancelable(left.entries, right.entries, stop, [](const auto &a, const auto &b) {
            return a == b;
        }) ||
        !equal_values_cancelable(left.domains, right.domains, stop, [](const auto &a, const auto &b) {
            return a == b;
        }) ||
        !equal_values_cancelable(left.code_exclusions, right.code_exclusions, stop,
            [](const auto &a, const auto &b) { return a == b; }) ||
        !equal_values_cancelable(left.encrypted_ranges, right.encrypted_ranges, stop,
            [](const auto &a, const auto &b) { return a == b; }))
        return false;
    if (left.x86_profile.has_value() != right.x86_profile.has_value() ||
        left.arm_profile.has_value() != right.arm_profile.has_value() ||
        left.execution_profile.has_value() != right.execution_profile.has_value())
        return false;
    if (left.x86_profile) {
        const auto &a = *left.x86_profile;
        const auto &b = *right.x86_profile;
        if (a.environment != b.environment || a.a20 != b.a20 ||
            a.input_load_address != b.input_load_address || a.stack_selector != b.stack_selector ||
            !equal_values_cancelable(a.bindings, b.bindings, stop, [](const auto &x, const auto &y) {
                return x == y;
            }))
            return false;
    }
    if (left.arm_profile) {
        const auto &a = *left.arm_profile;
        const auto &b = *right.arm_profile;
        if (!equal_values_cancelable(a.ranges, b.ranges, stop, [&](const auto &x, const auto &y) {
                return x.begin == y.begin && x.size == y.size && x.kind == y.kind &&
                       equal_arm_sources_cancelable(x.sources, y.sources, stop);
            }) ||
            !equal_values_cancelable(a.roots, b.roots, stop, [&](const auto &x, const auto &y) {
                return x.at == y.at && x.mode == y.mode &&
                       x.known_thumb_it_clear == y.known_thumb_it_clear &&
                       equal_arm_sources_cancelable(x.sources, y.sources, stop);
            }))
            return false;
    }
    if (left.execution_profile &&
        !equal_values_cancelable(left.execution_profile->ranges, right.execution_profile->ranges,
            stop, [](const auto &a, const auto &b) { return a == b; }))
        return false;
    canceled(stop);
    return true;
}
bool same_instruction_mapping(const Image &left, const Image &right, std::stop_token stop) {
    // Recovery rechecks current permission and context at every reused
    // instruction, then rebuilds all edges and ownership from those facts.
    // Keep address-to-file identity fixed so stored byte reads and IDs remain
    // meaningful across a policy or execution-context update.
    return same_string_mapping(left, right, stop);
}
using LocationKey = std::tuple<unsigned, uint32_t, uint64_t>;
LocationKey location_key(Location value) {
    if (auto address = std::get_if<Address>(&value))
        return {0, address->space.value, address->offset};
    return {1, 0, std::get<FileOffset>(value).value};
}
template <class T, class Equal>
bool equal_decision_rows(std::span<const T> left, std::span<const T> right,
                         std::stop_token stop, Equal equal) {
    canceled(stop);
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        canceled(stop);
        if (!equal(left[index], right[index])) return false;
    }
    return true;
}
bool equal_function_decisions(std::span<const FunctionDecision> left,
                              std::span<const FunctionDecision> right,
                              std::stop_token stop) {
    return equal_decision_rows(left, right, stop, [&](const auto &a, const auto &b) {
        return a.id == b.id && a.entry == b.entry && a.suppressed == b.suppressed &&
               equal_decision_rows(std::span<const DecisionRange>{a.chunks},
                                   std::span<const DecisionRange>{b.chunks}, stop,
                                   [](const auto &x, const auto &y) { return x == y; });
    });
}
bool equal_root_decisions(const AnalysisDecisions &left, const AnalysisDecisions &right,
                          std::stop_token stop) {
    return equal_decision_rows(std::span<const RegionDecision>{left.regions},
                               std::span<const RegionDecision>{right.regions}, stop,
                               [](const auto &a, const auto &b) { return a == b; }) &&
           equal_function_decisions(left.functions, right.functions, stop);
}
bool equal_reference_decisions(const AnalysisDecisions &left, const AnalysisDecisions &right,
                               std::stop_token stop) {
    return equal_decision_rows(std::span<const UserReference>{left.references},
                               std::span<const UserReference>{right.references}, stop,
                               [](const auto &a, const auto &b) { return a == b; });
}
bool equal_decisions(const AnalysisDecisions &left, const AnalysisDecisions &right,
                     std::stop_token stop) {
    return equal_root_decisions(left, right, stop) &&
           equal_reference_decisions(left, right, stop);
}
} // namespace
Result<std::shared_ptr<const DependencyIndex>> DependencyIndexCache::get_or_create(
    std::span<const FactDependency> facts, std::shared_ptr<const void> source_identity,
    std::stop_token stop) const {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Dependency index cache access canceled"};
    if (!source_identity)
        return Error{ErrorCode::invalid_argument, "Dependency index cache requires an immutable fact owner"};
    {
        std::lock_guard lock(mutex_);
        if (index_ && source_identity_ == source_identity)
            return index_;
    }
    // Index construction can walk a large dependency table. Do not make a
    // caller with a different (or canceled) request wait behind that work.
    auto created = DependencyIndex::create(facts, stop);
    if (!created)
        return created.error();
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Dependency index cache access canceled"};
    {
        std::lock_guard lock(mutex_);
        if (index_ && source_identity_ == source_identity)
            return index_;
        index_ = created.value();
        source_identity_ = std::move(source_identity);
    }
    return created.value();
}
Result<InvalidationPlan> plan_invalidation(const AnalysisBasis &old, std::span<const FileRange> changes,
                                           const AnalysisDecisions &decisions, const AnalysisKey &key,
                                           std::stop_token stop, bool byte_changes_verified,
                                           bool byte_ranges_verified) {
    return guarded([&]() -> Result<InvalidationPlan> {
        canceled(stop);
        validate_basis(old);
        require(changes.size() <= 1000000, "Too many invalidation ranges");
        InvalidationPlan plan;
        plan.before_key = old.key;
        plan.source_key = key;
        plan.byte_ranges_verified = byte_ranges_verified;
        for (auto range : changes) {
            canceled(stop);
            require(range.begin.value <= old.key.input.size && range.size <= old.key.input.size - range.begin.value,
                    "Invalidation range is outside prior input");
            take(plan.byte_ranges.include(range.begin, range.size));
            if (take(old.metadata_reads.intersects(range.begin, range.size)))
                plan.metadata_invalid = true;
        }
        plan.decisions_changed = !equal_decisions(decisions, old.decisions, stop);
        plan.reference_decisions_changed = !equal_reference_decisions(decisions, old.decisions, stop);
        std::set<std::uint64_t> changed_decision_ids;
        const auto collect_changed_ids = [&](const auto &before, const auto &after) {
            using Decision = typename std::decay_t<decltype(before)>::value_type;
            std::map<std::uint64_t, Decision> old_by_id, new_by_id;
            for (const auto &decision : before) {
                canceled(stop);
                require(decision.id != 0 && old_by_id.emplace(decision.id, decision).second,
                        "Prior analysis decisions have invalid or duplicate identities");
            }
            for (const auto &decision : after) {
                canceled(stop);
                require(decision.id != 0 && new_by_id.emplace(decision.id, decision).second,
                        "Current analysis decisions have invalid or duplicate identities");
            }
            for (const auto &[id, decision] : old_by_id) {
                canceled(stop);
                const auto current = new_by_id.find(id);
                if (current == new_by_id.end() || current->second != decision)
                    changed_decision_ids.insert(id);
            }
            for (const auto &[id, decision] : new_by_id) {
                canceled(stop);
                (void)decision;
                if (!old_by_id.contains(id)) changed_decision_ids.insert(id);
            }
        };
        collect_changed_ids(old.decisions.regions, decisions.regions);
        collect_changed_ids(old.decisions.functions, decisions.functions);
        if (key.input != old.key.input)
            plan.full_reason = "Original input identity changed";
        else if (key.recipe_fingerprint != old.key.recipe_fingerprint)
            plan.full_reason = "Load recipe changed";
        else if (key.external_input_fingerprint != old.key.external_input_fingerprint)
            plan.full_reason = "External analysis-input identity changed";
        else if (key.engine_fingerprint != old.key.engine_fingerprint)
            plan.full_reason = "Analysis engine or options changed";
        else if (!semantic_decoder_read_set_complete(old.options))
            plan.full_reason = "Semantic decoder external reads are not completely declared; full rebuild required";
        else if (semantic_decoder_image_reads_intersect(old.options, {}, old.image->storage()->size()))
            plan.full_reason = "Semantic decoder image-read ranges are invalid; full rebuild required";
        else if (!semantic_decoder_image_read_ranges(old.options).empty() &&
                 key.byte_revision != old.key.byte_revision && !byte_ranges_verified)
            plan.full_reason = "Semantic decoder image reads require a certified complete byte diff";
        else if (plan.metadata_invalid)
            plan.full_reason = "Changed loader metadata requires a freshly parsed mapping";
        else if (!old.metadata_reads_complete && !plan.byte_ranges.ranges().empty())
            plan.full_reason = "Loader metadata read dependencies are uncertified; byte edits require a fresh parse";
        else if (!old.loader_metadata_complete && !plan.byte_ranges.ranges().empty())
            plan.full_reason = "Incomplete loader metadata requires a full rebuild after byte changes";
        else if (key.byte_revision != old.key.byte_revision && plan.byte_ranges.ranges().empty() &&
                 !byte_changes_verified)
            plan.full_reason = "Byte revision changed without invalidation ranges";
        if (key.input == old.key.input && key.recipe_fingerprint == old.key.recipe_fingerprint &&
            key.engine_fingerprint == old.key.engine_fingerprint)
            require(key.byte_revision >= old.key.byte_revision && key.decision_revision >= old.key.decision_revision,
                    "Analysis revisions cannot move backwards");
        require(plan.byte_ranges.ranges().empty() || key.byte_revision != old.key.byte_revision ||
                    key.input != old.key.input,
                "Changed bytes require a new byte revision");
        require(!plan.decisions_changed || key.decision_revision != old.key.decision_revision ||
                    key.input != old.key.input,
                "Changed decisions require a new decision revision");
        std::set<FactKey> facts;
        if (!plan.full_reason.empty()) {
            for (auto &dependency : old.functions->dependencies) {
                canceled(stop);
                facts.insert(dependency.fact);
            }
        } else {
            auto index = old.dependency_index_cache
                ? take(old.dependency_index_cache->get_or_create(old.functions->dependencies,
                                                                 old.functions, stop))
                : take(DependencyIndex::create(old.functions->dependencies, stop));
            for (auto fact : take(index->affected(plan.byte_ranges, stop))) {
                canceled(stop);
                facts.insert(fact);
            }
            if (!changed_decision_ids.empty()) {
                std::vector<std::uint64_t> changed_ids;
                changed_ids.reserve(changed_decision_ids.size());
                for (const auto id : changed_decision_ids) {
                    canceled(stop);
                    changed_ids.push_back(id);
                }
                for (auto fact : take(index->affected_decisions(changed_ids, stop))) {
                    canceled(stop);
                    facts.insert(fact);
                }
            }
            // Definition changes can alter rooted call seeds/shared ownership well beyond
            // an address interval. Rewalk ownership, retaining permitted byte facts.
            if (!equal_root_decisions(decisions, old.decisions, stop))
                for (auto &dependency : old.functions->dependencies) {
                    canceled(stop);
                    if (dependency.fact.kind != FactKind::instruction)
                        facts.insert(dependency.fact);
                }
        }
        plan.facts.reserve(facts.size());
        for (auto fact : facts) {
            canceled(stop);
            plan.facts.push_back(fact);
        }
        for (auto fact : facts) {
            canceled(stop);
            if (fact.kind == FactKind::function)
                plan.functions.push_back({fact.id});
        }
        std::map<LocationKey, Location> sources;
        for (auto &fact : old.functions->instructions) {
            canceled(stop);
            if (!plan.full_reason.empty() || plan.reference_decisions_changed ||
                facts.contains({FactKind::instruction, fact->id}))
                sources.emplace(location_key(fact->instruction.address), fact->instruction.address);
        }
        if (plan.reference_decisions_changed)
            for (auto &reference : old.decisions.references) {
                canceled(stop);
                sources.emplace(location_key(reference.source), reference.source);
            }
        plan.reference_sources.reserve(sources.size());
        for (auto &[location, value] : sources) {
            canceled(stop);
            plan.reference_sources.push_back(value);
        }
        if (!plan.full_reason.empty()) {
            take(plan.string_ranges.include({0}, old.image->storage()->size()));
            plan.string_reason = "Rescan the complete input domain after source or mapping uncertainty";
        } else if (!plan.byte_ranges.ranges().empty()) {
            if (plan.byte_ranges_verified) {
                plan.string_ranges = plan.byte_ranges;
                plan.string_reason = "Rescan every complete string scan domain intersecting changed bytes";
            } else {
                take(plan.string_ranges.include({0}, old.image->storage()->size()));
                plan.string_reason = "Unverified byte ranges require a complete string scan";
            }
        }
        canceled(stop);
        return plan;
    });
}
Result<DerivedProposal> reanalyze(const AnalysisBasis &old, std::shared_ptr<const Image> image,
                                  std::shared_ptr<const ImageMetadata> metadata, const AnalysisDecisions &decisions,
                                  const InvalidationPlan &plan, const AnalysisKey &key, std::stop_token stop) {
    return guarded([&]() -> Result<DerivedProposal> {
        canceled(stop);
        validate_basis(old);
        require(image && metadata, "Reanalysis requires a current image and metadata");
        require(plan.before_key == old.key && plan.source_key == key,
                "Invalidation plan belongs to another source revision");
        require(image->storage()->size() == key.input.size &&
                    key.engine_fingerprint == function_engine_fingerprint(old.options),
                "Reanalysis key does not match the enabled engine/options/input extent");
        require(plan.decisions_changed == !equal_decisions(decisions, old.decisions, stop),
                "Invalidation decisions do not match reanalysis");
        if (!analysis_detail::supports_automatic_flow(*image))
            return Error{ErrorCode::unsupported, "Derived instruction analysis requires a supported processor mode"};
        canceled(stop);
        const bool same_layout = equal_layout_cancelable(image->layout(), old.image->layout(), stop);
        const bool same_metadata = *metadata == *old.metadata;
        if (key == old.key && !same_metadata)
            return Error{ErrorCode::conflict, "Loader metadata changed without advancing the analysis source key"};
        if (key == old.key && !effective_images_match(*old.image, *image, stop))
            return Error{ErrorCode::conflict, "Effective input bytes changed without advancing the analysis source key"};
        const bool callback_reads_complete = semantic_decoder_read_set_complete(old.options);
        // The invalidation plan may have been prepared before a host callback
        // refreshed its manifest. Recheck its current primary-image reads at
        // the reuse boundary so newly declared dependencies cannot leave stale
        // callback-derived instructions in the retained snapshot.
        const bool callback_external_reads_unverified =
            !semantic_decoder_image_read_ranges(old.options).empty() &&
            key.byte_revision != old.key.byte_revision && !plan.byte_ranges_verified;
        const bool callback_read_conflict = !callback_reads_complete || callback_external_reads_unverified ||
            semantic_decoder_image_reads_intersect(old.options, {}, old.image->storage()->size());
        // A loader's dependency ranges are the fast invalidation path, but the
        // freshly parsed result remains authoritative. A changed mapping or
        // metadata snapshot disables all derived-fact reuse even when the
        // loader omitted the corresponding byte range.
        const bool untracked_loader_change = (!same_layout || !same_metadata) &&
                                             !plan.metadata_invalid && plan.full_reason.empty();
        const bool loader_change_requires_full_facts = plan.metadata_invalid || untracked_loader_change ||
            (!old.metadata_reads_complete && !plan.byte_ranges.ranges().empty()) ||
            (!old.loader_metadata_complete && !plan.byte_ranges.ranges().empty()) ||
            callback_read_conflict;
        DerivedProposal output;
        output.source_key = key;
        take(bind_derived_source(output,*image,stop));
        output.full_reason = !plan.full_reason.empty() ? plan.full_reason
            : untracked_loader_change
                ? "Loader mapping or metadata changed without a declared invalidation range; full rebuild"
                : callback_read_conflict
                    ? "Semantic decoder read dependencies changed or could not be certified at reanalysis; full rebuild"
                : "";
        output.string_reason = plan.string_reason;

        // User xref decisions do not participate in code discovery or string
        // recognition. When those are the only changed decisions, avoid
        // rebuilding function ownership/CFG and rescanning the complete input.
        // `byte_ranges_verified` is the caller's proof that an empty change
        // set means the effective bytes did not change; without it we retain
        // the conservative instruction-byte validation/recovery path below.
        const bool reference_decisions_only =
            plan.reference_decisions_changed && plan.decisions_changed &&
            !callback_read_conflict &&
            equal_root_decisions(decisions, old.decisions, stop) &&
            plan.byte_ranges.ranges().empty() && plan.byte_ranges_verified && plan.full_reason.empty() &&
            same_layout && same_metadata;
        if (reference_decisions_only) {
            canceled(stop);
            auto functions = clone_snapshot(*old.functions, stop);
            functions->key = key;
            output.counters.reused_instructions = functions->instructions.size();
            output.counters.reused_blocks = functions->blocks.size();
            output.counters.reused_functions = functions->functions.size();
            output.functions = std::move(functions);
            // Reference decisions do not affect function ownership, block
            // contents, or stack transfer. The branch predicates above prove
            // those inputs are unchanged, so avoid rebuilding lookup maps just
            // to rediscover that every prior frame is reusable.
            output.stack_frames = old.stack_frames;
            output.references = take(derive_references(*image, *output.functions, *metadata, decisions, stop));
            output.strings = old.strings;
            output.complete = output.functions->complete && output.references->complete() && output.strings->complete;
            canceled(stop);
            if (key.engine_fingerprint != function_engine_fingerprint(old.options))
                return Error{ErrorCode::conflict, "Semantic decoder set changed during incremental analysis"};
            return output;
        }
        if (!callback_read_conflict && plan.byte_ranges.ranges().empty() && !plan.decisions_changed && same_layout && same_metadata &&
            plan.full_reason.empty()) {
            // A caller that advances a source revision while certifying an
            // empty dirty set has already compared the complete effective
            // bytes. Do not walk every function again just to republish the
            // same derived facts under the new revision. When the byte
            // revision did not advance, retain the independent byte check so
            // an omitted revision change cannot make this a false no-op.
            const bool unchanged_bytes = key.byte_revision == old.key.byte_revision
                                             ? effective_images_match(*old.image, *image, stop)
                                             : plan.byte_ranges_verified;
            if (unchanged_bytes) {
                if (key == old.key) {
                    output.functions = old.functions;
                    output.references = old.references;
                } else {
                    auto functions = clone_snapshot(*old.functions, stop);
                    functions->key = key;
                    output.functions = std::move(functions);
                    std::vector<Reference> references;
                    references.reserve(old.references->all().size());
                    for (const auto &reference : old.references->all()) {
                        canceled(stop);
                        references.push_back(reference);
                    }
                    output.references = take(ReferenceIndex::create(std::move(references), key,
                                                                     old.references->complete(), stop));
                }
                output.counters.reused_instructions = old.functions->instructions.size();
                output.counters.reused_blocks = old.functions->blocks.size();
                output.counters.reused_functions = old.functions->functions.size();
                output.stack_frames = old.stack_frames;
                output.strings = old.strings;
                output.string_reason = "Reused prior string scan because effective bytes, mapping and metadata are unchanged";
                output.complete = output.functions->complete && output.references->complete() && output.strings->complete;
                if (key.engine_fingerprint != function_engine_fingerprint(old.options))
                    return Error{ErrorCode::conflict, "Semantic decoder set changed during incremental analysis"};
                return output;
            }
        }
        function_detail::Recovery recovery(*image, *metadata, decisions, old.options, stop);
        recovery.output->key = key;
        // A certified byte diff can make a loader-metadata edit safe for
        // instruction reuse even though roots and metadata-derived references
        // must be rebuilt. Reuse is limited to the same input/recipe/engine and
        // only when every effective byte difference is covered by the dirty
        // ranges; the per-instruction dependency check below then excludes
        // facts that consumed any changed byte. Recovery still walks all roots
        // and rebuilds ownership/CFG from the fresh metadata.
        const bool certified_metadata_edit = plan.byte_ranges_verified &&
            !plan.byte_ranges.ranges().empty() &&
            (plan.metadata_invalid || !old.metadata_reads_complete || !old.loader_metadata_complete) &&
            key.input == old.key.input && key.recipe_fingerprint == old.key.recipe_fingerprint &&
            key.external_input_fingerprint == old.key.external_input_fingerprint &&
            key.engine_fingerprint == old.key.engine_fingerprint;
        bool reusable = (!loader_change_requires_full_facts || certified_metadata_edit) &&
                        (plan.full_reason.empty() || certified_metadata_edit) &&
                        !callback_read_conflict &&
                        same_instruction_mapping(*old.image, *image, stop) &&
                        (same_metadata || certified_metadata_edit);
        if (reusable)
            for (auto &fact : old.functions->instructions) {
                canceled(stop);
                if (!instruction_hit(*fact, plan.byte_ranges)) {
                    // Range reuse is safe without per-fact reads only when the
                    // caller compared the complete effective images and proved
                    // that every difference is covered by the dirty ranges.
                    if (plan.byte_ranges_verified) {
                        recovery.reusable_instructions.emplace(fact->instruction.address, fact);
                    } else {
                        ++output.counters.validated_reuse_instructions;
                        if (instruction_bytes_match(*fact, *image, stop))
                            recovery.reusable_instructions.emplace(fact->instruction.address, fact);
                        else
                            ++output.counters.rejected_reuse_instructions;
                    }
                }
            }
        auto recovered = recovery.run();
        auto functions = clone_snapshot(*recovered, stop);
        output.counters.decoded_instructions = recovery.decoded_instructions;
        output.counters.reused_instructions = recovery.reused_instructions;
        if (reusable) {
            std::map<BlockId, std::shared_ptr<const BasicBlock>> blocks;
            std::map<FunctionId, std::shared_ptr<const FunctionRecord>> records;
            for (auto &block : old.functions->blocks) {
                canceled(stop);
                blocks.emplace(block->id, block);
            }
            for (auto &function : old.functions->functions) {
                canceled(stop);
                records.emplace(function->id, function);
            }
            for (auto &block : functions->blocks) {
                canceled(stop);
                auto found = blocks.find(block->id);
                if (found != blocks.end() && *block == *found->second) {
                    block = found->second;
                    ++output.counters.reused_blocks;
                }
            }
            for (auto &function : functions->functions) {
                canceled(stop);
                auto found = records.find(function->id);
                if (found != records.end() && *function == *found->second) {
                    function = found->second;
                    ++output.counters.reused_functions;
                }
            }
        }
        output.functions = std::move(functions);
        output.stack_frames = derive_stack_frames(*output.functions, old.functions.get(), old.stack_frames, stop,
                                                   default_stack_calling_convention(*metadata),
                                                   default_stack_calling_convention(*metadata) ==
                                                       default_stack_calling_convention(*old.metadata));
        output.references = take(derive_references(*image, *output.functions, *metadata, decisions, stop));
        bool loader_strings_reused = false;
        if (loader_change_requires_full_facts && key.input == old.key.input &&
            key.recipe_fingerprint == old.key.recipe_fingerprint && same_string_mapping(*old.image, *image, stop)) {
            std::optional<ReadSet> verified_string_changes;
            if (plan.byte_ranges_verified) {
                verified_string_changes = plan.byte_ranges;
            } else if (effective_images_match(*old.image, *image, stop)) {
                verified_string_changes.emplace();
            }
            if (verified_string_changes) {
                if (verified_string_changes->ranges().empty()) {
                    output.strings = old.strings;
                    output.string_reason = "Loader metadata changed; reused string results because effective bytes and file mapping are unchanged";
                    loader_strings_reused = true;
                } else {
                    output.strings = std::make_shared<const StringScan>(
                        take(refresh_strings(*image, old.options, *old.strings, *verified_string_changes, stop)));
                    output.string_reason = old.strings->complete
                        ? "Loader metadata changed; refreshed only string domains intersecting verified byte changes"
                        : "Loader metadata changed; prior string scan was incomplete, so the string domain was rescanned";
                    loader_strings_reused = true;
                }
            }
        }
        if (!loader_strings_reused) {
            if (plan.string_ranges.ranges().empty() && same_string_mapping(*old.image, *image, stop) &&
                plan.full_reason.empty())
                output.strings = old.strings;
            else if (plan.full_reason.empty() && plan.byte_ranges_verified &&
                     same_string_mapping(*old.image, *image, stop))
                output.strings = std::make_shared<const StringScan>(
                    take(refresh_strings(*image, old.options, *old.strings, plan.string_ranges, stop)));
            else
                output.strings = std::make_shared<const StringScan>(take(find_strings(*image, old.options, stop)));
        }
        output.complete = output.functions->complete && output.references->complete() && output.strings->complete;
        canceled(stop);
        if (key.engine_fingerprint != function_engine_fingerprint(old.options))
            return Error{ErrorCode::conflict, "Semantic decoder set changed during incremental analysis"};
        return output;
    });
}
Result<DerivedProposal> analyze_derived(std::shared_ptr<const Image> image,
                                        std::shared_ptr<const ImageMetadata> metadata,
                                        const AnalysisDecisions &decisions, const AnalysisOptions &options,
                                        const AnalysisKey &key, std::stop_token stop) {
    return guarded([&]() -> Result<DerivedProposal> {
        canceled(stop);
        require(image && metadata, "Derived analysis requires an image and metadata");
        require(image->storage()->size() == key.input.size &&
                    key.engine_fingerprint == function_engine_fingerprint(options),
                "Derived analysis key does not match enabled engine/options/input extent");
        if (!analysis_detail::supports_automatic_flow(*image))
            return Error{ErrorCode::unsupported, "Derived instruction analysis requires a supported processor mode"};
        function_detail::Recovery recovery(*image, *metadata, decisions, options, stop);
        recovery.output->key = key;
        DerivedProposal result;
        result.source_key = key;
        take(bind_derived_source(result,*image,stop));
        result.full_reason = "Full derived analysis requested";
        result.functions = recovery.run();
        if (key.engine_fingerprint != function_engine_fingerprint(options))
            return Error{ErrorCode::conflict, "Semantic decoder set changed during derived analysis"};
        result.stack_frames = derive_stack_frames(*result.functions, nullptr, {}, stop,
                                                  default_stack_calling_convention(*metadata));
        result.counters.decoded_instructions = recovery.decoded_instructions;
        result.references = take(derive_references(*image, *result.functions, *metadata, decisions, stop));
        result.strings = std::make_shared<const StringScan>(take(find_strings(*image, options, stop)));
        result.complete = result.functions->complete && result.references->complete() && result.strings->complete;
        canceled(stop);
        if (key.engine_fingerprint != function_engine_fingerprint(options))
            return Error{ErrorCode::conflict,
                         "Semantic decoder set changed during analysis; refusing to publish a mixed result"};
        return result;
    });
}
} // namespace hexlab
