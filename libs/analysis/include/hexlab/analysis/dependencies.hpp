#pragma once
#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/image/read_set.hpp"
#include <map>
#include <compare>
#include <optional>
#include <stop_token>
namespace hexlab {
struct InputIdentity {std::uint64_t size=0;Sha256Digest sha256=Sha256{}.digest();bool operator==(const InputIdentity&)const=default;};
struct AnalysisKey {
    InputIdentity input;std::uint64_t byte_revision=0,decision_revision=0;
    Sha256Digest recipe_fingerprint{},engine_fingerprint{};
    std::optional<Sha256Digest> external_input_fingerprint;
    bool operator==(const AnalysisKey&)const=default;
};
enum class FactKind {instruction,block,function,seed};
struct FactKey {FactKind kind;std::uint64_t id;auto operator<=>(const FactKey&)const=default;};
struct FactDependency {FactKey fact;ReadSet reads;std::vector<FactKey> prerequisites;std::vector<std::uint64_t> decisions;};
class DependencyIndex {
public:
    HEXLAB_ANALYSIS_EXPORT static Result<std::shared_ptr<const DependencyIndex>> create(std::span<const FactDependency>,std::stop_token={});
    HEXLAB_ANALYSIS_EXPORT Result<std::vector<FactKey>> affected(FileOffset,std::uint64_t,std::stop_token={})const;
    HEXLAB_ANALYSIS_EXPORT Result<std::vector<FactKey>> affected(const ReadSet&,std::stop_token={})const;
    // Return facts that directly cite any changed decision identity, plus all
    // prerequisite dependents. This supports precise invalidation for edits to
    // an existing region/function decision while additions are handled by the
    // caller's normal root-discovery policy.
    HEXLAB_ANALYSIS_EXPORT Result<std::vector<FactKey>> affected_decisions(
        std::span<const std::uint64_t>, std::stop_token = {}) const;
private:
    struct ReadInterval {std::uint64_t begin,end;FactKey fact;};
    std::map<FactKey,std::vector<FactKey>> dependents_;
    std::map<std::uint64_t,std::vector<FactKey>> decision_facts_;
    // Sorted read intervals plus a prefix maximum end lets invalidation skip
    // unrelated facts while still finding long reads that start earlier.
    std::vector<ReadInterval> read_intervals_;
    std::vector<std::uint64_t> prefix_max_end_;
};
}
