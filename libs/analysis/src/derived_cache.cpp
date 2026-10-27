#include "derived_cache_internal.hpp"
#include <map>
namespace hexlab::derived_detail {
namespace {
using Facts = std::map<uint64_t, std::shared_ptr<const InstructionFact>>;
constexpr std::array<std::byte, 4> magic{std::byte{'H'}, std::byte{'X'}, std::byte{'D'}, std::byte{'C'}};
Facts collect_facts(const FunctionSnapshot &snapshot, std::stop_token stop) {
    Facts facts;
    const auto add = [&](const std::shared_ptr<const InstructionFact> &fact) {
        canceled(stop);
        require(fact && fact->id, "Invalid instruction fact identity");
        auto [found, inserted] = facts.emplace(fact->id, fact);
        if (!inserted)
            require(instruction_bytes(found->second->instruction, stop) == instruction_bytes(fact->instruction, stop) &&
                        same_reads(found->second->reads, fact->reads),
                    "One instruction ID describes different cached facts");
    };
    for (auto &fact : snapshot.instructions)
        add(fact);
    for (auto &block : snapshot.blocks) {
        require(bool(block), "Null cached block");
        for (auto &fact : block->instructions)
            add(fact);
    }
    for (auto &conflict : snapshot.conflicts) {
        if (conflict.first_fact)
            add(conflict.first_fact);
        if (conflict.second_fact)
            add(conflict.second_fact);
    }
    return facts;
}
template <class T> void ids(Writer &out, const std::vector<T> &values) {
    out.count(values.size());
    for (auto id : values)
        out.number(id.value);
}
std::vector<std::byte> payload(const DerivedProposal &proposal, std::stop_token stop, bool validate_instructions,
                               size_t *validations = nullptr, const AnalysisOptions& options = {}) {
    require(proposal.functions && proposal.references && proposal.strings,
            "Derived cache requires functions/references/strings");
    auto &functions = *proposal.functions;
    require(functions.key == proposal.source_key && proposal.references->key() == proposal.source_key,
            "Derived cache layers have inconsistent source keys");
    require(proposal.complete == (functions.complete && proposal.references->complete() && proposal.strings->complete),
            "Derived cache completeness disagrees with its layers");
    Writer out{{}, stop};
    out.append(magic);
    out.number(derived_cache_version, 2);
    out.key(proposal.source_key);
    out.context(proposal.context);
    require(proposal.mapping_fingerprint.has_value() && !proposal.domain_contexts.empty(),
            "Derived proposal has no source mapping binding");
    require(proposal.domain_contexts.size() <= source_detail::domain_limit &&
                proposal.domain_contexts.size() <= source_detail::domain_memory_limit / sizeof(DomainContext),
            "Derived source domain binding exceeds its memory budget", ErrorCode::resource_limit);
    out.append(*proposal.mapping_fingerprint);
    out.count(proposal.domain_contexts.size(), source_detail::domain_limit);
    bool primary_found = false;
    for (std::size_t n = 0; n < proposal.domain_contexts.size(); ++n) {
        const auto &domain = proposal.domain_contexts[n];
        if (n) {
            const auto &previous = proposal.domain_contexts[n - 1];
            require(previous.space.value < domain.space.value ||
                        (previous.space == domain.space &&
                         ((previous.range_size == 0) != (domain.range_size == 0)
                              ? previous.range_size == 0
                              : previous.range_begin.offset < domain.range_begin.offset)),
                    "Derived domain contexts are not sorted and unique");
        }
        primary_found = primary_found || domain.context == proposal.context;
        out.number(domain.space.value, 4);
        out.number(domain.range_begin.offset);
        out.number(domain.range_size);
        out.context(domain.context, true);
    }
    require(primary_found, "Primary processor context is missing from domain table");
    out.flag(functions.complete);
    out.number(functions.omitted_functions);
    out.number(functions.omitted_blocks);
    auto facts = collect_facts(functions, stop);
    out.count(facts.size());
    for (auto &[id, fact] : facts) {
        canceled(stop);
        out.number(id);
        auto encoded = instruction_bytes(fact->instruction, stop);
        require(fact->instruction.context == context_for(proposal.domain_contexts, fact->instruction.address),
                "Instruction domain context differs from proposal source");
        if (validate_instructions) {
            if (validations)
                ++*validations;
            (void)checked_instruction(encoded, proposal.domain_contexts, nullptr, options, stop);
        }
        out.number(encoded.size(), 4);
        out.append(encoded);
        out.reads(fact->reads);
    }
    out.count(functions.instructions.size());
    for (auto &fact : functions.instructions)
        out.number(fact->id);
    out.count(functions.blocks.size());
    for (auto &block : functions.blocks) {
        canceled(stop);
        out.number(block->id.value);
        out.address(block->begin);
        out.count(block->instructions.size());
        for (auto &fact : block->instructions)
            out.number(fact->id);
        out.count(block->successors.size());
        for (auto &edge : block->successors) {
            out.address(edge.source);
            out.optional_address(edge.target);
            out.flag(edge.block.has_value());
            if (edge.block)
                out.number(edge.block->value);
            out.number(static_cast<unsigned>(edge.kind), 1);
        }
        out.optional_stop(block->stop);
        ids(out, block->owners);
    }
    out.count(functions.functions.size());
    for (auto &function : functions.functions) {
        require(bool(function), "Null cached function");
        canceled(stop);
        out.number(function->id.value);
        out.address(function->entry);
        out.flag(function->complete);
        out.count(function->chunks.size());
        for (auto &chunk : function->chunks) {
            out.address(chunk.begin);
            out.number(chunk.size);
            ids(out, chunk.blocks);
        }
        ids(out, function->blocks);
        out.count(function->seeds.size());
        for (auto &seed : function->seeds) {
            out.number(static_cast<unsigned>(seed.kind), 1);
            out.address(seed.entry);
            out.optional_address(seed.source);
            out.flag(seed.decision.has_value());
            if (seed.decision)
                out.number(*seed.decision);
            out.flag(seed.unwind_evidence.has_value());
            if (seed.unwind_evidence) {
                out.number(seed.unwind_evidence->section, 4);
                out.number(seed.unwind_evidence->file_offset);
                out.number(seed.unwind_evidence->record_size);
            }
            out.flag(seed.initializer_evidence.has_value());
            if (seed.initializer_evidence) {
                const auto &evidence = *seed.initializer_evidence;
                out.number(static_cast<unsigned>(evidence.source), 1);
                out.flag(evidence.section.has_value());
                if (evidence.section) out.number(*evidence.section, 4);
                out.flag(evidence.index.has_value());
                if (evidence.index) out.number(*evidence.index);
                out.flag(evidence.file_offset.has_value());
                if (evidence.file_offset) out.number(*evidence.file_offset);
                out.flag(evidence.dynamic_tag.has_value());
                if (evidence.dynamic_tag) out.number(static_cast<std::uint64_t>(*evidence.dynamic_tag));
                for (const auto *rows : {&evidence.relocation_rows, &evidence.dyld_classic_rows,
                                         &evidence.dyld_chained_rows}) {
                    out.count(rows->size());
                    for (const auto row : *rows) out.number(row);
                }
            }
            out.flag(seed.pogo_evidence.has_value());
            if (seed.pogo_evidence) {
                out.number(seed.pogo_evidence->profile_index, 4);
                out.number(seed.pogo_evidence->entry_index, 4);
                out.number(seed.pogo_evidence->file_offset);
                out.number(seed.pogo_evidence->record_size);
            }
        }
        out.count(function->stops.size());
        for (auto &record : function->stops)
            out.stop_record(record);
    }
    out.count(functions.calls.size());
    for (auto &call : functions.calls) {
        out.number(call.owner.value);
        out.address(call.source);
        out.optional_address(call.target);
        out.flag(call.callee.has_value());
        if (call.callee)
            out.number(call.callee->value);
        out.flag(call.tail_candidate);
    }
    out.count(functions.candidates.size());
    for (auto &candidate : functions.candidates) {
        out.address(candidate.entry);
        out.optional_address(candidate.source);
        out.number(static_cast<unsigned>(candidate.reason), 1);
        out.text(candidate.detail);
    }
    out.count(functions.conflicts.size());
    for (auto &conflict : functions.conflicts) {
        out.number(static_cast<unsigned>(conflict.kind), 1);
        out.address(conflict.first);
        out.address(conflict.second);
        out.text(conflict.detail);
        out.number(conflict.first_fact ? conflict.first_fact->id : 0);
        out.number(conflict.second_fact ? conflict.second_fact->id : 0);
    }
    out.count(functions.dependencies.size());
    for (auto &dependency : functions.dependencies) {
        out.fact_key(dependency.fact);
        out.reads(dependency.reads);
        out.count(dependency.prerequisites.size());
        for (auto key : dependency.prerequisites)
            out.fact_key(key);
        out.count(dependency.decisions.size());
        for (auto id : dependency.decisions)
            out.number(id);
    }
    auto references = take(encode_reference_index(*proposal.references, stop));
    out.number(references.size(), 4);
    out.append(references);
    out.flag(proposal.strings->complete);
    out.count(proposal.strings->records.size());
    for (auto &record : proposal.strings->records) {
        out.number(static_cast<unsigned>(record.encoding), 1);
        out.text(record.preview, 1024);
        out.number(record.characters);
        out.number(record.byte_length);
        out.number(record.file_offset.value);
        out.optional_address(record.address);
        out.flag(record.terminated);
    }
    out.count(proposal.strings->diagnostics.size());
    for (auto &diagnostic : proposal.strings->diagnostics) {
        out.number(static_cast<unsigned>(diagnostic.severity), 1);
        out.text(diagnostic.message);
        out.optional_address(diagnostic.location);
    }
    require(proposal.stack_frames.size() == functions.functions.size(),
            "Derived cache stack table does not cover every function");
    out.count(proposal.stack_frames.size());
    for (std::size_t i = 0; i < proposal.stack_frames.size(); ++i)
        require(proposal.stack_frames[i].function == functions.functions[i]->id,
                "Derived cache stack table differs from function order");
    std::size_t total_stack_access_details = 0;
    for (const auto &record : proposal.stack_frames) {
        canceled(stop);
        out.number(record.function.value);
        out.flag(record.frame.complete);
        out.flag(record.frame.maximum_stack_allocation_bytes.has_value());
        if (record.frame.maximum_stack_allocation_bytes)
            out.number(*record.frame.maximum_stack_allocation_bytes);
        out.count(record.frame.slots.size());
        for (const auto &slot : record.frame.slots) {
            out.signed_number(slot.offset_from_entry_sp);
            out.number(slot.width, 2);
            out.flag(slot.read);
            out.flag(slot.written);
            out.flag(slot.address_taken);
            out.count(slot.accesses.size());
            for (auto access : slot.accesses)
                out.address(access);
            require(slot.access_details.size() <= 4'000'000 - total_stack_access_details,
                    "Derived stack access provenance exceeds budget", ErrorCode::resource_limit);
            total_stack_access_details += slot.access_details.size();
            out.count(slot.access_details.size());
            for (const auto &access : slot.access_details) {
                out.address(access.instruction);
                out.flag(access.read);
                out.flag(access.written);
                out.flag(access.address_taken);
            }
        }
    }
    return std::move(out.bytes);
}
std::shared_ptr<const InstructionFact> fact(const Facts &facts, uint64_t id) {
    auto found = facts.find(id);
    require(found != facts.end(), "Cached model refers to an unknown instruction");
    return found->second;
}
template <class T> std::vector<T> read_ids(Reader &in) {
    std::vector<T> out;
    auto count = in.count(8);
    out.reserve(std::min<size_t>(count, 4096));
    for (size_t i = 0; i < count; ++i) {
        auto id = in.number();
        require(id != 0, "Zero cached association identity");
        out.push_back(T{id});
    }
    return out;
}
struct Decoded {
    DerivedProposal proposal;
    Facts facts;
};
Decoded read_payload(std::span<const std::byte> bytes, const Image &image, const AnalysisOptions &options,
                     const AnalysisKey &key, std::stop_token stop) {
    Reader in{bytes, stop};
    auto marker = in.read(4);
    require(std::equal(marker.begin(), marker.end(), magic.begin()), "Unknown derived cache magic");
    require(in.number(2) == derived_cache_version, "Unknown derived cache version", ErrorCode::unsupported);
    require(in.key() == key, "Derived cache source key differs from the requested revision");
    auto context = in.context();
    require(context == image.decode_context(), "Cached processor context differs from the current loaded image");
    Decoded out;
    out.proposal.source_key = key;
    out.proposal.context = context;
    Sha256Digest mapping_digest{};
    auto digest_bytes = in.read(32);
    std::copy(digest_bytes.begin(), digest_bytes.end(), mapping_digest.begin());
    out.proposal.mapping_fingerprint = mapping_digest;
    const auto domain_count = in.count(25, source_detail::domain_limit);
    require(domain_count <= source_detail::domain_memory_limit / sizeof(DomainContext),
            "Cached source domain binding exceeds its memory budget", ErrorCode::resource_limit);
    require(domain_count != 0, "Cached domain table is empty");
    for (std::size_t n = 0; n < domain_count; ++n) {
        const AddressSpaceId space{static_cast<std::uint32_t>(in.number(4))};
        const Address begin{space, in.number()};
        const auto size = in.number();
        out.proposal.domain_contexts.push_back({space, in.context(true), begin, size});
    }
    take(validate_derived_source(out.proposal, image, stop));
    auto snapshot = std::make_shared<FunctionSnapshot>();
    snapshot->key = key;
    snapshot->complete = in.flag();
    auto omitted_functions = in.number(), omitted_blocks = in.number();
    require(omitted_functions <= SIZE_MAX && omitted_blocks <= SIZE_MAX, "Cached omitted counts exceed host limits");
    snapshot->omitted_functions = static_cast<size_t>(omitted_functions);
    snapshot->omitted_blocks = static_cast<size_t>(omitted_blocks);
    function_detail::Ids identities;
    auto fact_count = in.count(30);
    require(fact_count <= options.instruction_budget, "Cached facts exceed their derivation instruction budget");
    uint64_t previous = 0;
    for (size_t i = 0; i < fact_count; ++i) {
        auto id = in.number();
        require(id > previous, "Cached fact identities are not canonical and unique");
        previous = id;
        auto length = in.number(4);
        require(length <= 16384, "Cached instruction record exceeds its budget");
        auto encoded = in.read(static_cast<size_t>(length));
        auto value = std::make_shared<InstructionFact>();
        value->id = id;
        value->instruction = checked_instruction(encoded, out.proposal.domain_contexts, &image, options, stop);
        ++out.proposal.counters.cache_validation_decodes;
        value->reads = in.reads();
        const auto &instruction = value->instruction;
        require(identities.make(FactKind::instruction, instruction.address,
                                instruction.encoded_bytes()) == id,
                "Cached instruction identity differs from its canonical bytes");
        ReadSet expected;
        for (size_t offset = 0; offset < instruction.length; ++offset) {
            auto at = take(advance(instruction.address, offset));
            auto file = take(image.to_file_offset(at));
            take(expected.include(file, 1));
            auto actual = take(image.storage()->read_at(file, 1));
            require(actual.bytes.size() == 1 && actual.bytes[0] == instruction.encoded_bytes()[offset],
                    "Cached instruction bytes differ from effective input");
        }
        require(same_reads(value->reads, expected), "Cached instruction reads differ from the current mapping");
        out.facts.emplace(id, std::move(value));
    }
    auto trusted = in.count(8);
    require(trusted <= fact_count, "Trusted cached instructions exceed the fact table");
    std::set<uint64_t> trusted_ids;
    for (size_t i = 0; i < trusted; ++i) {
        auto id = in.number();
        require(trusted_ids.insert(id).second, "Duplicate trusted cached instruction");
        snapshot->instructions.push_back(fact(out.facts, id));
    }
    auto block_count = in.count(32);
    require(block_count <= options.block_budget, "Cached blocks exceed their derivation budget");
    std::set<BlockId> block_ids;
    for (size_t i = 0; i < block_count; ++i) {
        auto block = std::make_shared<BasicBlock>();
        block->id = {in.number()};
        block->begin = in.address();
        require(block_ids.insert(block->id).second && identities.make(FactKind::block, block->begin) == block->id.value,
                "Invalid or duplicate cached block identity");
        auto instructions = in.count(8);
        for (size_t j = 0; j < instructions; ++j)
            block->instructions.push_back(fact(out.facts, in.number()));
        auto edges = in.count(15);
        for (size_t j = 0; j < edges; ++j) {
            BlockSuccessor edge{};
            edge.source = in.address();
            edge.target = in.optional_address();
            if (in.flag())
                edge.block = BlockId{in.number()};
            auto kind = in.number(1);
            require(kind <= static_cast<unsigned>(BlockEdgeKind::exception), "Unknown cached block edge kind");
            edge.kind = static_cast<BlockEdgeKind>(kind);
            block->successors.push_back(edge);
        }
        block->stop = in.optional_stop();
        block->owners = read_ids<FunctionId>(in);
        snapshot->blocks.push_back(std::move(block));
    }
    auto function_count = in.count(37);
    require(function_count <= options.function_budget, "Cached functions exceed their derivation budget");
    std::set<FunctionId> function_ids;
    for (size_t i = 0; i < function_count; ++i) {
        auto function = std::make_shared<FunctionRecord>();
        function->id = {in.number()};
        function->entry = in.address();
        require(function_ids.insert(function->id).second &&
                    identities.make(FactKind::function, function->entry) == function->id.value,
                "Invalid or duplicate cached function identity");
        function->complete = in.flag();
        auto chunks = in.count(24);
        for (size_t j = 0; j < chunks; ++j) {
            FunctionChunk chunk{};
            chunk.begin = in.address();
            chunk.size = in.number();
            require(chunk.size && bool(advance(chunk.begin, chunk.size)), "Invalid cached function chunk extent");
            chunk.blocks = read_ids<BlockId>(in);
            function->chunks.push_back(std::move(chunk));
        }
        function->blocks = read_ids<BlockId>(in);
        auto seeds = in.count(16);
        for (size_t j = 0; j < seeds; ++j) {
            auto kind = in.number(1);
            require(kind <= static_cast<unsigned>(FunctionSeedKind::pogo), "Unknown cached function seed kind");
            FunctionSeed seed{static_cast<FunctionSeedKind>(kind), in.address(), in.optional_address(), {}};
            if (in.flag())
                seed.decision = in.number();
            if (in.flag())
                seed.unwind_evidence = FunctionSeedUnwindEvidence{static_cast<std::uint32_t>(in.number(4)),
                                                                  in.number(), in.number()};
            if (in.flag()) {
                FunctionSeedInitializerEvidence evidence;
                const auto source = in.number(1);
                require(source <= static_cast<unsigned>(FunctionInitializerSource::macho_routines),
                        "Unknown cached initializer source kind");
                evidence.source = static_cast<FunctionInitializerSource>(source);
                if (in.flag()) evidence.section = static_cast<std::uint32_t>(in.number(4));
                if (in.flag()) evidence.index = in.number();
                if (in.flag()) evidence.file_offset = in.number();
                if (in.flag()) evidence.dynamic_tag = static_cast<std::int64_t>(in.number());
                auto read_rows = [&](std::vector<std::uint64_t> &rows) {
                    const auto count = in.count(8);
                    rows.reserve(count);
                    for (std::size_t k = 0; k < count; ++k) rows.push_back(in.number());
                };
                read_rows(evidence.relocation_rows);
                read_rows(evidence.dyld_classic_rows);
                read_rows(evidence.dyld_chained_rows);
                seed.initializer_evidence = std::move(evidence);
            }
            if (in.flag())
                seed.pogo_evidence = FunctionSeedPogoEvidence{static_cast<std::uint32_t>(in.number(4)),
                                                               static_cast<std::uint32_t>(in.number(4)),
                                                               in.number(), in.number()};
            require((seed.kind == FunctionSeedKind::unwind) == seed.unwind_evidence.has_value() &&
                        (!seed.unwind_evidence || seed.unwind_evidence->record_size > 0) &&
                        ((seed.kind == FunctionSeedKind::initializer) == seed.initializer_evidence.has_value()) &&
                        ((seed.kind == FunctionSeedKind::pogo) == seed.pogo_evidence.has_value()) &&
                        (!seed.pogo_evidence || seed.pogo_evidence->record_size > 0),
                    "Invalid cached function seed evidence");
            function->seeds.push_back(std::move(seed));
        }
        auto stops = in.count(17);
        for (size_t j = 0; j < stops; ++j)
            function->stops.push_back(in.stop_record());
        snapshot->functions.push_back(std::move(function));
    }
    auto calls = in.count(23);
    for (size_t i = 0; i < calls; ++i) {
        FunctionCall call{};
        call.owner = {in.number()};
        call.source = in.address();
        call.target = in.optional_address();
        if (in.flag())
            call.callee = FunctionId{in.number()};
        call.tail_candidate = in.flag();
        snapshot->calls.push_back(call);
    }
    auto candidates = in.count(18);
    for (size_t i = 0; i < candidates; ++i) {
        auto entry = in.address();
        auto source = in.optional_address();
        auto reason = in.reason();
        snapshot->candidates.push_back({entry, source, reason, in.text()});
    }
    auto conflicts = in.count(45);
    for (size_t i = 0; i < conflicts; ++i) {
        auto kind = in.number(1);
        require(kind <= static_cast<unsigned>(FunctionConflictKind::decision_overlap), "Unknown cached conflict kind");
        FunctionConflict value{static_cast<FunctionConflictKind>(kind), in.address(), in.address(), in.text(), {}, {}};
        auto a = in.number(), b = in.number();
        if (a)
            value.first_fact = fact(out.facts, a);
        if (b)
            value.second_fact = fact(out.facts, b);
        snapshot->conflicts.push_back(std::move(value));
    }
    auto dependencies = in.count(21);
    for (size_t i = 0; i < dependencies; ++i) {
        FactDependency value{};
        value.fact = in.fact_key();
        value.reads = in.reads();
        auto prerequisites = in.count(9);
        for (size_t j = 0; j < prerequisites; ++j)
            value.prerequisites.push_back(in.fact_key());
        auto decisions = in.count(8);
        for (size_t j = 0; j < decisions; ++j) {
            auto id = in.number();
            require(id > 0, "Zero cached decision dependency");
            value.decisions.push_back(id);
        }
        snapshot->dependencies.push_back(std::move(value));
    }
    for (auto &block : snapshot->blocks) {
        canceled(stop);
        for (auto owner : block->owners)
            require(function_ids.contains(owner), "Cached block has an unknown owner");
        for (auto &edge : block->successors)
            if (edge.block)
                require(block_ids.contains(*edge.block), "Cached edge refers to an unknown block");
    }
    for (auto &function : snapshot->functions) {
        for (auto block : function->blocks)
            require(block_ids.contains(block), "Cached function refers to an unknown block");
        for (auto &chunk : function->chunks)
            for (auto block : chunk.blocks)
                require(block_ids.contains(block), "Cached chunk refers to an unknown block");
    }
    for (auto &call : snapshot->calls)
        require(function_ids.contains(call.owner) && (!call.callee || function_ids.contains(*call.callee)),
                "Cached call has an unknown function association");
    (void)take(DependencyIndex::create(snapshot->dependencies, stop));
    auto reference_size = in.number(4);
    require(reference_size <= reference_payload_limit, "Cached references exceed their payload limit");
    out.proposal.references = take(decode_reference_index(in.read(static_cast<size_t>(reference_size)), stop));
    require(out.proposal.references->key() == key, "Nested reference source key differs from derived source");
    out.proposal.functions = std::move(snapshot);
    auto strings = std::make_shared<StringScan>();
    strings->complete = in.flag();
    auto records = in.count(31);
    for (size_t i = 0; i < records; ++i) {
        auto kind = in.number(1);
        require(kind <= static_cast<unsigned>(StringEncoding::iso8859_9), "Unknown cached string encoding");
        StringRecord record{};
        record.encoding = static_cast<StringEncoding>(kind);
        record.preview = in.text(1024);
        record.characters = in.number();
        record.byte_length = in.number();
        record.file_offset = {in.number()};
        record.address = in.optional_address();
        record.terminated = in.flag();
        require(record.characters && record.byte_length && record.file_offset.value <= image.storage()->size() &&
                    record.byte_length <= image.storage()->size() - record.file_offset.value,
                "Cached string exceeds effective input");
        strings->records.push_back(std::move(record));
    }
    auto diagnostics = in.count(6);
    for (size_t i = 0; i < diagnostics; ++i) {
        auto severity = in.number(1);
        require(severity <= static_cast<unsigned>(DiagnosticSeverity::error), "Unknown cached diagnostic severity");
        auto message = in.text();
        strings->diagnostics.push_back(
            {static_cast<DiagnosticSeverity>(severity), std::move(message), in.optional_address()});
    }
    auto stack_count = in.count(14);
    require(stack_count <= snapshot->functions.size(), "Cached stack frame table exceeds function count");
    std::size_t total_stack_access_details = 0;
    for (size_t i = 0; i < stack_count; ++i) {
        FunctionStackRecord record;
        record.function = {in.number()};
        require(record.function.value != 0 &&
                    (i == 0 || out.proposal.stack_frames.back().function.value < record.function.value),
                "Cached stack frame identities are not sorted and unique");
        record.frame.complete = in.flag();
        if (in.flag()) record.frame.maximum_stack_allocation_bytes = in.number();
        auto slots = in.count(17);
        for (size_t n = 0; n < slots; ++n) {
            StackSlot slot;
            auto zigzag = in.number();
            slot.offset_from_entry_sp = (zigzag & 1) ? -1 - static_cast<int64_t>(zigzag >> 1)
                                                       : static_cast<int64_t>(zigzag >> 1);
            slot.width = static_cast<std::uint16_t>(in.number(2));
            slot.read = in.flag();
            slot.written = in.flag();
            slot.address_taken = in.flag();
            auto accesses = in.count(12);
            for (size_t a = 0; a < accesses; ++a) slot.accesses.push_back(in.address());
            auto details = in.count(15);
            require(details <= 4'000'000 - total_stack_access_details,
                    "Cached stack access provenance exceeds budget");
            total_stack_access_details += details;
            for (size_t a = 0; a < details; ++a)
                slot.access_details.push_back({in.address(), in.flag(), in.flag(), in.flag()});
            record.frame.slots.push_back(std::move(slot));
        }
        out.proposal.stack_frames.push_back(std::move(record));
    }
    require(in.cursor == bytes.size(), "Trailing derived cache payload bytes");
    out.proposal.strings = std::move(strings);
    out.proposal.complete =
        out.proposal.functions->complete && out.proposal.references->complete() && out.proposal.strings->complete;
    return out;
}
} // namespace
} // namespace hexlab::derived_detail
namespace hexlab {
Result<std::vector<std::byte>> encode_derived(const DerivedProposal &proposal, std::stop_token stop) {
    size_t ignored = 0;
    return encode_derived(proposal, stop, ignored);
}
Result<std::vector<std::byte>> encode_derived(const DerivedProposal &proposal, std::stop_token stop,
                                              const AnalysisOptions& options) {
    size_t ignored = 0;
    return encode_derived(proposal, stop, ignored, options);
}
Result<std::vector<std::byte>> encode_derived(const DerivedProposal &proposal, std::stop_token stop,
                                              size_t &validations) {
    return encode_derived(proposal, stop, validations, AnalysisOptions{});
}
Result<std::vector<std::byte>> encode_derived(const DerivedProposal &proposal, std::stop_token stop,
                                              size_t &validations, const AnalysisOptions& options) {
    return derived_detail::guarded([&]() -> Result<std::vector<std::byte>> {
        using namespace derived_detail;
        validations = 0;
        canceled(stop);
        auto bytes = payload(proposal, stop, true, &validations, options);
        auto digest = checksum(bytes, stop);
        require(digest.size() <= derived_payload_limit - bytes.size(), "Derived cache checksum exceeds payload budget",
                ErrorCode::resource_limit);
        bytes.insert(bytes.end(), digest.begin(), digest.end());
        return bytes;
    });
}
Result<AnalysisKey> inspect_derived_key(std::span<const std::byte> bytes, std::stop_token stop) {
    return derived_detail::guarded([&]() -> Result<AnalysisKey> {
        using namespace derived_detail;
        canceled(stop);
        require(bytes.size() >= 180 && bytes.size() <= derived_payload_limit, "Invalid derived cache envelope extent");
        auto body = bytes.first(bytes.size() - 32);
        auto digest = checksum(body, stop);
        require(std::equal(digest.begin(), digest.end(), bytes.last(32).begin()),
                "Derived cache envelope checksum mismatch");
        Reader in{body, stop};
        auto marker = in.read(4);
        require(std::equal(marker.begin(), marker.end(), magic.begin()), "Unknown derived cache envelope magic");
        require(in.number(2) == derived_cache_version, "Unknown derived cache envelope version",
                ErrorCode::unsupported);
        auto key = in.key();
        (void)in.context();
        return key;
    });
}
Result<DerivedProposal> decode_derived(std::span<const std::byte> bytes, const Image &image,
                                       const ImageMetadata &metadata, const AnalysisDecisions &decisions,
                                       const AnalysisOptions &options, const AnalysisKey &key, std::stop_token stop) {
    return derived_detail::guarded([&]() -> Result<DerivedProposal> {
        using namespace derived_detail;
        canceled(stop);
        require(bytes.size() >= 180 && bytes.size() <= derived_payload_limit, "Invalid derived cache payload extent");
        require(key.input.size == image.storage()->size() &&
                    key.engine_fingerprint == function_engine_fingerprint(options),
                "Derived cache key is not supported by this input/engine/options");
        const auto body = bytes.first(bytes.size() - 32);
        const auto digest = checksum(body, stop);
        require(std::equal(digest.begin(), digest.end(), bytes.last(32).begin()), "Derived cache checksum mismatch");
        auto decoded = read_payload(body, image, options, key, stop);
        // Re-establish roots, ownership, conflicts and dependencies with validated
        // instruction memo entries. This also detects missing/extra/fabricated facts;
        // a checksum is not evidence that cached derivations are semantically valid.
        function_detail::Recovery recovery(image, metadata, decisions, options, stop);
        recovery.output->key = key;
        for (auto &[id, fact] : decoded.facts)
            require(recovery.reusable_instructions.emplace(fact->instruction.address, fact).second,
                    "Cached fact table has duplicate instruction addresses");
        DerivedProposal expected;
        expected.source_key = key;
        take(bind_derived_source(expected, image, stop));
        expected.functions = recovery.run();
        std::map<BlockId, std::shared_ptr<const BasicBlock>> validated_blocks;
        for (const auto &block : expected.functions->blocks) {
            canceled(stop);
            validated_blocks.emplace(block->id, block);
        }
        for (const auto &function : expected.functions->functions) {
            canceled(stop);
            // The stack solver only needs blocks owned by this function. Keeping
            // cache validation on the same narrow view avoids a functions ×
            // image-blocks scan for large binaries.
            FunctionSnapshot function_view;
            function_view.blocks.reserve(function->blocks.size());
            for (const auto block_id : function->blocks) {
                canceled(stop);
                const auto block = validated_blocks.find(block_id);
                if (block != validated_blocks.end())
                    function_view.blocks.push_back(block->second);
            }
            expected.stack_frames.push_back(
                {function->id, take(analyze_stack_frame(*function, function_view, stop))});
        }
        expected.references = take(derive_references(image, *expected.functions, metadata, decisions, stop));
        expected.strings = std::make_shared<const StringScan>(take(find_strings(image, options, stop)));
        expected.complete =
            expected.functions->complete && expected.references->complete() && expected.strings->complete;
        auto canonical = payload(expected, stop, false);
        require(canonical.size() == body.size() && std::equal(canonical.begin(), canonical.end(), body.begin()),
                "Cached derivation differs from current rooted analysis");
        auto &counters = decoded.proposal.counters;
        counters.cache_validation_decodes += recovery.decoded_instructions;
        counters.cache_validation_recovery_walks = 1;
        counters.cache_validation_string_scans = 1;
        counters.reused_instructions = decoded.proposal.functions->instructions.size();
        counters.reused_blocks = decoded.proposal.functions->blocks.size();
        counters.reused_functions = decoded.proposal.functions->functions.size();
        decoded.proposal.full_reason =
            "Persistent derived cache validated against current bytes, roots, ownership, references and string scan";
        canceled(stop);
        if (key.engine_fingerprint != function_engine_fingerprint(options))
            return Error{ErrorCode::conflict,
                         "Semantic decoder set changed during cache validation; refusing to publish cached facts"};
        return std::move(decoded.proposal);
    });
}
} // namespace hexlab
