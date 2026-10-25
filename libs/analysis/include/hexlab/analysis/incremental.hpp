#pragma once
#include "hexlab/analysis/references.hpp"
#include "hexlab/analysis/stack.hpp"
#include <mutex>
namespace hexlab {
struct FunctionStackRecord {
    FunctionId function;
    StackFrameAnalysis frame;
    bool operator==(const FunctionStackRecord &) const = default;
};
// A basis is immutable and may be invalidated more than once while work is
// queued, canceled, or retried. Keep the expensive dependency closure index
// with that basis and build it only if a range-based invalidation is needed.
class DependencyIndexCache {
  public:
    HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const DependencyIndex>> get_or_create(
        std::span<const FactDependency>, std::shared_ptr<const void> source_identity, std::stop_token) const;
  private:
    mutable std::mutex mutex_;
    mutable std::shared_ptr<const DependencyIndex> index_;
    mutable std::shared_ptr<const void> source_identity_;
};
struct AnalysisBasis {
    std::shared_ptr<const Image> image;
    std::shared_ptr<const ImageMetadata> metadata;
    ReadSet metadata_reads;
    AnalysisDecisions decisions;AnalysisOptions options;AnalysisKey key;
    std::shared_ptr<const FunctionSnapshot> functions;
    std::shared_ptr<const ReferenceIndex> references;
    std::shared_ptr<const StringScan> strings;
    // False means the loader could not enumerate all metadata facts reliably;
    // byte changes then require fresh mapping/metadata and full derivation.
    bool loader_metadata_complete=true;
    std::vector<FunctionStackRecord> stack_frames;
    std::shared_ptr<DependencyIndexCache> dependency_index_cache;
};
struct InvalidationPlan {
    AnalysisKey before_key,source_key;ReadSet byte_ranges,string_ranges;
    std::vector<FactKey> facts;std::vector<FunctionId> functions;std::vector<Location> reference_sources;
    bool metadata_invalid=false,decisions_changed=false,reference_decisions_changed=false;
    bool byte_ranges_verified=false;
    std::string full_reason,string_reason;
};
struct ReanalysisCounters {
    std::size_t decoded_instructions=0,reused_instructions=0,reused_blocks=0,reused_functions=0;
    // Prior facts outside declared dirty ranges whose encoded bytes no longer
    // match the current effective image. They are decoded again if reachable.
    std::size_t rejected_reuse_instructions=0;
    // Facts checked against source bytes because the caller did not certify
    // that its invalidation ranges cover every effective-byte difference.
    std::size_t validated_reuse_instructions=0;
    std::size_t cache_validation_decodes=0,cache_validation_recovery_walks=0,cache_validation_string_scans=0;
    std::size_t cache_serialization_decodes=0;
};
struct DomainContext {
    AddressSpaceId space;
    DecodeContext context;
    Address range_begin{};
    std::uint64_t range_size=0;
    bool operator==(const DomainContext&) const = default;
};
struct DerivedProposal {
    AnalysisKey source_key;
    DecodeContext context;
    std::shared_ptr<const FunctionSnapshot> functions;
    std::shared_ptr<const ReferenceIndex> references;
    std::shared_ptr<const StringScan> strings;
    std::vector<FunctionStackRecord> stack_frames;
    ReanalysisCounters counters;bool complete=false;std::string full_reason,string_reason;
    std::vector<DomainContext> domain_contexts;
    std::optional<Sha256Digest> mapping_fingerprint;
};
HEXLAB_ANALYSIS_EXPORT Result<bool> bind_derived_source(DerivedProposal&,const Image&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<bool> validate_derived_source(const DerivedProposal&,const Image&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<DerivedProposal> analyze_derived(std::shared_ptr<const Image>,std::shared_ptr<const ImageMetadata>,const AnalysisDecisions&,const AnalysisOptions&,const AnalysisKey&,std::stop_token);
// Missing ranges on a changed byte revision force a full rebuild unless the
// caller has compared the effective source bytes and verified that no bytes
// changed. Set byte_ranges_verified only after comparing the complete effective
// source and proving every difference is covered by changes. Without that
// proof, reanalysis independently verifies encoded instruction bytes before
// allowing decode reuse. Nonempty ranges must cover loader-metadata edits.
HEXLAB_ANALYSIS_EXPORT Result<InvalidationPlan> plan_invalidation(const AnalysisBasis&,std::span<const FileRange>,const AnalysisDecisions&,const AnalysisKey&,std::stop_token,bool byte_changes_verified=false,bool byte_ranges_verified=false);
// Reference-only user-decision edits reuse the prior function/CFG and string
// derivations when byte ranges are verified empty and mapping/metadata match;
// the reference index is rebuilt under the new source key.
HEXLAB_ANALYSIS_EXPORT Result<DerivedProposal> reanalyze(const AnalysisBasis&,std::shared_ptr<const Image>,std::shared_ptr<const ImageMetadata>,const AnalysisDecisions&,const InvalidationPlan&,const AnalysisKey&,std::stop_token);
}
