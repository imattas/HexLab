#pragma once
#include "hexlab/analysis/incremental.hpp"
namespace hexlab {
inline constexpr std::uint32_t derived_cache_version=34;
inline constexpr std::size_t derived_payload_limit=64*1024*1024,derived_record_limit=1000000;
// HXDC(4), u16 version, AnalysisKey(120), primary context(5), mapping SHA256(32),
// counted domain id/context table, completeness and model tables. Every fact is
// validated against the authoritative Image::context_at before adoption.
HEXLAB_ANALYSIS_EXPORT Result<std::vector<std::byte>> encode_derived(const DerivedProposal&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::vector<std::byte>> encode_derived(const DerivedProposal&,std::stop_token,std::size_t& validation_decodes);
HEXLAB_ANALYSIS_EXPORT Result<std::vector<std::byte>> encode_derived(const DerivedProposal&,std::stop_token,const AnalysisOptions&);
HEXLAB_ANALYSIS_EXPORT Result<std::vector<std::byte>> encode_derived(const DerivedProposal&,std::stop_token,std::size_t& validation_decodes,const AnalysisOptions&);
HEXLAB_ANALYSIS_EXPORT Result<AnalysisKey> inspect_derived_key(std::span<const std::byte>,std::stop_token);
// Checks current effective bytes and validates the persisted derivation using
// cached instruction facts. Validation decoder work is separately reported.
HEXLAB_ANALYSIS_EXPORT Result<DerivedProposal> decode_derived(std::span<const std::byte>,const Image&,const ImageMetadata&,const AnalysisDecisions&,const AnalysisOptions&,const AnalysisKey&,std::stop_token);
}
