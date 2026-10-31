#pragma once
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "hexlab/core/encoding.hpp"
#include <array>
#include <deque>
#include <map>
#include <new>
#include <set>
#include <tuple>
namespace hexlab::function_detail {
struct Failure {
    Error error;
};
template <class T> T take(Result<T> value) {
    if (!value)
        throw Failure{value.error()};
    return std::move(value.value());
}
inline void require(bool value, const char *message) {
    if (!value)
        throw Failure{{ErrorCode::invalid_argument, message}};
}
struct AddressLess {
    bool operator()(Address a, Address b) const {
        return std::tie(a.space.value, a.offset) < std::tie(b.space.value, b.offset);
    }
};
using AddressSet = std::set<Address, AddressLess>;
template <class T> using AddressMap = std::map<Address, T, AddressLess>;
struct PathVisitState { ThumbITState it{}; std::uint16_t flags = 0; };
inline std::uint16_t add_new_path_flags(AddressMap<PathVisitState> &visited, Address at, ThumbITState it,
                                       std::uint16_t incoming, bool &it_conflict) {
    auto found = visited.find(at);
    if (found == visited.end()) {
        visited.emplace(at, PathVisitState{it, incoming});
        return incoming;
    }
    if (found->second.it != it) {
        it_conflict = true;
        return 0;
    }
    const auto fresh = static_cast<std::uint16_t>(incoming & ~found->second.flags);
    found->second.flags = static_cast<std::uint16_t>(found->second.flags | incoming);
    return fresh;
}
struct NodeEdge {
    std::optional<Address> target;
    BlockEdgeKind kind;
    ThumbITState target_it{};
    // NZCV valuations required before this instruction for the edge to execute.
    // The all-ones default denotes an unmodelled or unconditional edge.
    std::uint16_t flags_guard = 0xffff;
    bool flags_unknown_after = false;
};
struct Node {
    Address at;
    std::shared_ptr<const InstructionFact> fact;
    ReadSet window;
    std::vector<NodeEdge> edges;
    std::optional<FunctionStop> stop;
    bool call = false;
    std::optional<Address> call_target;
    std::optional<ExternalIdentity> external_call_target;
    std::optional<FunctionStop> call_issue;
    std::uint16_t call_guard = 0xffff;
    std::uint16_t stop_guard = 0xffff;
    std::vector<std::uint64_t> decisions;
    ThumbITState incoming_it{};
};
class Ids {
    std::map<FactKey, std::vector<std::byte>> assigned_;

  public:
    std::uint64_t make(FactKind, Address, std::span<const std::byte> extra = {});
};
class Recovery {
  public:
    const Image &image;
    const ImageMetadata &metadata;
    const AnalysisDecisions &decisions;
    const AnalysisOptions &options;
    std::vector<FileRange> semantic_decoder_image_ranges;
    std::stop_token stop;
    RelocationResolver relocations;
    std::shared_ptr<FunctionSnapshot> output = std::make_shared<FunctionSnapshot>();
    Ids ids;
    AddressMap<Node> nodes;
    AddressMap<ThumbITState> thumb_states;
    AddressMap<std::uint16_t> reachable_flags;
    // Each possible input A64 NZCV nibble maps to a set of output nibbles.
    AddressMap<std::array<std::uint16_t, 16>> a64_flag_transfers;
    AddressSet discovered_functions, discovered_switches;
    std::size_t discovery_memberships = 0, a64_indirect_passes = 0;
    bool a64_indirect_seeds_added = false;
    AddressMap<std::vector<FunctionSeed>> roots, all_seeds, valid_seeds;
    // Validated object-format function ranges constrain control-flow recovery
    // when no explicit user chunk definition overrides them.
    AddressMap<std::vector<FunctionChunk>> metadata_chunks;
    AddressSet root_entries, omitted_entries;
    AddressSet delayed_slots;
    AddressMap<std::vector<NodeEdge>> delayed_edges;
    AddressMap<const FunctionDecision *> definitions;
    AddressSet suppressed, ambiguous;
    std::vector<const RegionDecision *> regions;
    AddressMap<std::shared_ptr<FunctionRecord>> functions;
    AddressMap<std::vector<FunctionId>> owners;
    std::map<FunctionId, AddressSet> function_nodes;
    AddressMap<BlockId> node_blocks;
    std::vector<std::shared_ptr<BasicBlock>> blocks;
    AddressMap<std::shared_ptr<const InstructionFact>> reusable_instructions;
    // Exact loader-reported import address slots to their symbolic identities.
    // A null value records a collision/invalid row so ambiguous slots fail closed.
    AddressMap<std::optional<ExternalIdentity>> imported_call_slots;
    std::size_t decoded_instructions = 0, reused_instructions = 0;
    std::size_t attempts = 0, owner_steps = 0;
    std::size_t last_progress_attempts = 0;
    bool discovery_exhausted = false;
    Recovery(const Image &i, const ImageMetadata &m, const AnalysisDecisions &d, const AnalysisOptions &o,
             std::stop_token s)
        : image(i), metadata(m), decisions(d), options(o),
          semantic_decoder_image_ranges(semantic_decoder_image_read_ranges(o)), stop(s),
          relocations(take(RelocationResolver::create(i, m, s))) {
        for (const auto &symbol : metadata.imports) {
            if (stop.stop_requested())
                throw Failure{{ErrorCode::canceled, "Function recovery canceled while indexing import slots"}};
            std::optional<ExternalIdentity> identity;
            const bool has_symbol = symbol.name && !symbol.name->empty() && !symbol.ordinal;
            const bool has_ordinal = symbol.ordinal && !symbol.name;
            if (!symbol.library.empty() && symbol.library.size() <= 65536 &&
                symbol.library.find('\0') == std::string::npos && (has_symbol || has_ordinal) &&
                (!symbol.name || (symbol.name->size() <= 65536 && symbol.name->find('\0') == std::string::npos)))
                identity = ExternalIdentity{symbol.library, symbol.name, symbol.ordinal};
            const auto [found, inserted] = imported_call_slots.emplace(symbol.iat, identity);
            if (!inserted && found->second != identity)
                found->second.reset();
        }
    }
    void canceled() const {
        if (stop.stop_requested())
            throw Failure{{ErrorCode::canceled, "Function recovery canceled"}};
    }
    void report_progress(std::string_view stage, std::uint64_t completed, std::uint64_t total) {
        canceled();
        if (options.progress) {
            bool keep_going = false;
            try {
                keep_going = options.progress(stage, completed, total);
            } catch (const std::bad_alloc &) {
                throw Failure{{ErrorCode::resource_limit, "Function progress callback allocation failed"}};
            } catch (...) {
                throw Failure{{ErrorCode::invalid_argument, "Function progress callback threw"}};
            }
            if (!keep_going)
                throw Failure{{ErrorCode::canceled, "Function recovery canceled by progress callback"}};
        }
        canceled();
    }
    std::optional<FunctionStopReason> permission(Address, bool instruction_start = true) const;
    const RegionDecision *region_at(Address) const;
    bool within_chunks(Address entry, Address at, std::uint64_t size = 1) const;
    bool add_seed(AddressMap<std::vector<FunctionSeed>> &, FunctionSeed, bool enforce_budget = true);
    Node &node(Address, ThumbITState = {});
    std::uint16_t edge_flags(const Node &, const NodeEdge &, std::uint16_t) const;
    std::shared_ptr<const FunctionSnapshot> run();

  private:
    void validate_decisions();
    void seed_roots();
    void discover();
    void refine_a64_flow();
    void find_conflicts();
    void trusted_seeds();
    void assign_owners();
    void prune_unowned_seeds();
    void resolve_wasm_indirect_calls();
};
void build_blocks(Recovery &);
void finish_functions(Recovery &);
void build_dependencies(Recovery &);
inline bool terminal_complete(FunctionStopReason reason) {
    return reason == FunctionStopReason::ret || reason == FunctionStopReason::trap ||
           reason == FunctionStopReason::tail_candidate;
}
} // namespace hexlab::function_detail
