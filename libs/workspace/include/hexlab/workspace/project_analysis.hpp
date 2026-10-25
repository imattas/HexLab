#pragma once
#include "hexlab/workspace/project.hpp"
namespace hexlab {
struct ProjectAnalysisRequest {
    std::shared_ptr<const ProjectSnapshot> snapshot;AnalysisOptions options;AnalysisKey key;
    database::DerivedCacheBytes cache;bool encode_cache=true,force_full=false;
};
struct ProjectAnalysis {
    AnalysisKey source_key;DerivedProposal derived;bool supported=true;
    database::CacheStatus cache_status=database::CacheStatus::absent;std::string cache_reason,reason;
    std::shared_ptr<const std::vector<std::byte>> encoded_cache;
};
HEXLAB_WORKSPACE_EXPORT Result<AnalysisKey> project_analysis_key(const ProjectSnapshot&,const AnalysisOptions&);
// Pure worker path: requests contain immutable values/leases and no SQL store.
HEXLAB_WORKSPACE_EXPORT Result<ProjectAnalysis> compute_project_analysis(const ProjectAnalysisRequest&,std::stop_token);
}
