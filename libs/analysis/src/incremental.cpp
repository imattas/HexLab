#include "hexlab/analysis/incremental.hpp"
#include "functions_internal.hpp"
#include "instruction_flow.hpp"
#include "strings_internal.hpp"
#include <algorithm>
#include <map>
namespace hexlab {
namespace {
using function_detail::Failure;
using function_detail::require;
using function_detail::take;
void canceled(std::stop_token stop) {
    if (stop.stop_requested())
        throw Failure{{ErrorCode::canceled, "Incremental analysis canceled"}};
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
    std::span<const FunctionStackRecord> prior, std::stop_token stop) {
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
        bool unchanged = prior_snapshot && cached != old.end();
        if (unchanged) {
            auto old_function = old_functions.find(function->id);
            unchanged = old_function != old_functions.end() && *old_function->second == *function;
            for (auto block_id : function->blocks) {
                if (!unchanged) break;
                auto previous = old_blocks.find(block_id);
                auto current = current_blocks.find(block_id);
                unchanged = previous != old_blocks.end() && current != current_blocks.end() &&
                            *previous->second == *current->second;
            }
        }
        if (unchanged) {
            frames.push_back(*cached->second);
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
            frames.push_back({function->id, take(analyze_stack_frame(*function, function_view, stop))});
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
bool same_string_mapping(const Image &left, const Image &right) {
    return left.storage()->size() == right.storage()->size() &&
           left.layout().space == right.layout().space &&
           left.layout().segments == right.layout().segments;
}
bool same_instruction_mapping(const Image &left, const Image &right) {
    // Recovery rechecks current permission and context at every reused
    // instruction, then rebuilds all edges and ownership from those facts.
    // Keep address-to-file identity fixed so stored byte reads and IDs remain
    // meaningful across a policy or execution-context update.
    return same_string_mapping(left, right);
}
using LocationKey = std::tuple<unsigned, uint32_t, uint64_t>;
LocationKey location_key(Location value) {
    if (auto address = std::get_if<Address>(&value))
        return {0, address->space.value, address->offset};
    return {1, 0, std::get<FileOffset>(value).value};
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
        plan.decisions_changed = decisions != old.decisions;
        plan.reference_decisions_changed = decisions.references != old.decisions.references;
        if (key.input != old.key.input)
            plan.full_reason = "Original input identity changed";
        else if (key.recipe_fingerprint != old.key.recipe_fingerprint)
            plan.full_reason = "Load recipe changed";
        else if (key.engine_fingerprint != old.key.engine_fingerprint)
            plan.full_reason = "Analysis engine or options changed";
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
            for (auto fact : take(index->affected(plan.byte_ranges, stop)))
                facts.insert(fact);
            // Definition changes can alter rooted call seeds/shared ownership well beyond
            // an address interval. Rewalk ownership, retaining permitted byte facts.
            if (decisions.regions != old.decisions.regions || decisions.functions != old.decisions.functions)
                for (auto &dependency : old.functions->dependencies) {
                    canceled(stop);
                    if (dependency.fact.kind != FactKind::instruction)
                        facts.insert(dependency.fact);
                }
        }
        plan.facts.assign(facts.begin(), facts.end());
        for (auto fact : facts)
            if (fact.kind == FactKind::function)
                plan.functions.push_back({fact.id});
        std::map<LocationKey, Location> sources;
        for (auto &fact : old.functions->instructions) {
            canceled(stop);
            if (!plan.full_reason.empty() || plan.reference_decisions_changed ||
                facts.contains({FactKind::instruction, fact->id}))
                sources.emplace(location_key(fact->instruction.address), fact->instruction.address);
        }
        if (plan.reference_decisions_changed)
            for (auto &reference : old.decisions.references)
                sources.emplace(location_key(reference.source), reference.source);
        for (auto &[location, value] : sources)
            plan.reference_sources.push_back(value);
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
        require(plan.decisions_changed == (decisions != old.decisions),
                "Invalidation decisions do not match reanalysis");
        if (!analysis_detail::supports_automatic_flow(*image))
            return Error{ErrorCode::unsupported, "Derived instruction analysis requires a supported processor mode"};
        const bool same_layout = image->layout() == old.image->layout();
        const bool same_metadata = *metadata == *old.metadata;
        // A loader's dependency ranges are the fast invalidation path, but the
        // freshly parsed result remains authoritative. A changed mapping or
        // metadata snapshot disables all derived-fact reuse even when the
        // loader omitted the corresponding byte range.
        const bool untracked_loader_change = (!same_layout || !same_metadata) &&
                                             !plan.metadata_invalid && plan.full_reason.empty();
        const bool loader_change_requires_full_facts = plan.metadata_invalid || untracked_loader_change ||
            (!old.metadata_reads_complete && !plan.byte_ranges.ranges().empty()) ||
            (!old.loader_metadata_complete && !plan.byte_ranges.ranges().empty());
        DerivedProposal output;
        output.source_key = key;
        take(bind_derived_source(output,*image,stop));
        output.full_reason = !plan.full_reason.empty() ? plan.full_reason
            : untracked_loader_change
                ? "Loader mapping or metadata changed without a declared invalidation range; full rebuild"
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
            decisions.regions == old.decisions.regions && decisions.functions == old.decisions.functions &&
            plan.byte_ranges.ranges().empty() && plan.byte_ranges_verified && plan.full_reason.empty() &&
            same_layout && same_metadata;
        if (reference_decisions_only) {
            canceled(stop);
            auto functions = std::make_shared<FunctionSnapshot>(*old.functions);
            functions->key = key;
            output.counters.reused_instructions = functions->instructions.size();
            output.counters.reused_blocks = functions->blocks.size();
            output.counters.reused_functions = functions->functions.size();
            output.functions = std::move(functions);
            output.stack_frames = derive_stack_frames(*output.functions, old.functions.get(), old.stack_frames, stop);
            output.references = take(derive_references(*image, *output.functions, *metadata, decisions, stop));
            output.strings = old.strings;
            output.complete = output.functions->complete && output.references->complete() && output.strings->complete;
            canceled(stop);
            if (key.engine_fingerprint != function_engine_fingerprint(old.options))
                return Error{ErrorCode::conflict, "Semantic decoder set changed during incremental analysis"};
            return output;
        }
        if (plan.byte_ranges.ranges().empty() && !plan.decisions_changed && same_layout && same_metadata &&
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
                    auto functions = std::make_shared<FunctionSnapshot>(*old.functions);
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
        bool reusable = !loader_change_requires_full_facts && plan.full_reason.empty() &&
                        same_instruction_mapping(*old.image, *image) && same_metadata;
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
        auto functions = std::make_shared<FunctionSnapshot>(*recovered);
        output.counters.decoded_instructions = recovery.decoded_instructions;
        output.counters.reused_instructions = recovery.reused_instructions;
        if (reusable) {
            std::map<BlockId, std::shared_ptr<const BasicBlock>> blocks;
            std::map<FunctionId, std::shared_ptr<const FunctionRecord>> records;
            for (auto &block : old.functions->blocks)
                blocks.emplace(block->id, block);
            for (auto &function : old.functions->functions)
                records.emplace(function->id, function);
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
        output.stack_frames = derive_stack_frames(*output.functions, old.functions.get(), old.stack_frames, stop);
        output.references = take(derive_references(*image, *output.functions, *metadata, decisions, stop));
        bool loader_strings_reused = false;
        if (loader_change_requires_full_facts && key.input == old.key.input &&
            key.recipe_fingerprint == old.key.recipe_fingerprint && same_string_mapping(*old.image, *image)) {
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
            if (plan.string_ranges.ranges().empty() && same_string_mapping(*old.image, *image) &&
                plan.full_reason.empty())
                output.strings = old.strings;
            else if (plan.full_reason.empty() && plan.byte_ranges_verified &&
                     same_string_mapping(*old.image, *image))
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
        result.stack_frames = derive_stack_frames(*result.functions, nullptr, {}, stop);
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
