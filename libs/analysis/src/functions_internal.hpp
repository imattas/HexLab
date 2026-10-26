#pragma once
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "hexlab/core/encoding.hpp"
#include <deque>
#include <map>
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
    std::stop_token stop;
    RelocationResolver relocations;
    std::shared_ptr<FunctionSnapshot> output = std::make_shared<FunctionSnapshot>();
    Ids ids;
    AddressMap<Node> nodes;
    AddressMap<ThumbITState> thumb_states;
    AddressMap<std::uint16_t> reachable_flags;
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
    std::size_t decoded_instructions = 0, reused_instructions = 0;
    std::size_t attempts = 0, owner_steps = 0;
    bool discovery_exhausted = false;
    Recovery(const Image &i, const ImageMetadata &m, const AnalysisDecisions &d, const AnalysisOptions &o,
             std::stop_token s)
        : image(i), metadata(m), decisions(d), options(o), stop(s),
          relocations(take(RelocationResolver::create(i, m, s))) {}
    void canceled() const {
        if (stop.stop_requested())
            throw Failure{{ErrorCode::canceled, "Function recovery canceled"}};
    }
    std::optional<FunctionStopReason> permission(Address, bool instruction_start = true) const;
    const RegionDecision *region_at(Address) const;
    bool within_chunks(Address entry, Address at, std::uint64_t size = 1) const;
    bool add_seed(AddressMap<std::vector<FunctionSeed>> &, FunctionSeed, bool enforce_budget = true);
    Node &node(Address, ThumbITState = {});
    std::shared_ptr<const FunctionSnapshot> run();

  private:
    void validate_decisions();
    void seed_roots();
    void discover();
    void find_conflicts();
    void trusted_seeds();
    void assign_owners();
    void prune_unowned_seeds();
};
void build_blocks(Recovery &);
void finish_functions(Recovery &);
void build_dependencies(Recovery &);
inline bool terminal_complete(FunctionStopReason reason) {
    return reason == FunctionStopReason::ret || reason == FunctionStopReason::trap ||
           reason == FunctionStopReason::tail_candidate;
}
} // namespace hexlab::function_detail
