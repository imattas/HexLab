#pragma once
#include "hexlab/workspace/document.hpp"
#include "hexlab/analysis/graph.hpp"
#include <functional>
#include <future>
namespace hexlab {
struct SessionKey {DocumentId document{0};std::uint64_t epoch=0;bool operator==(const SessionKey&)const=default;};
struct ProjectAnalysis;struct SearchResults;struct ListingResult;struct ProjectGraph;
using AnalysisPayload=std::variant<std::shared_ptr<const ProjectAnalysis>,std::shared_ptr<const GraphLayout>,std::shared_ptr<const SearchResults>,std::shared_ptr<const ListingResult>,std::shared_ptr<const ProjectGraph>>;
using AnalysisTask=std::function<Result<AnalysisPayload>(std::stop_token)>;
enum class AnalysisPriority {foreground,normal};
enum class AnalysisWorkKind {project_analysis,read_only};
struct AnalysisTicket {
    SessionKey session;std::uint64_t sequence=0;AnalysisKey source;
    std::optional<std::uint64_t> presentation_revision;
};
struct AnalysisSubmission {AnalysisTicket ticket;std::shared_future<Result<AnalysisPayload>> result;};
struct AnalysisCompletion {AnalysisTicket ticket;std::shared_future<Result<AnalysisPayload>> result;};
struct PoolLimits {
    std::size_t max_sessions=128;
    // Number of independent session jobs allowed to run at once. A session
    // still owns at most one active job, regardless of this pool-wide limit.
    std::size_t max_workers=2;
};
struct PoolStatistics {std::size_t workers=0,running=0,pending=0,ready=0,sessions=0;};
// Read-only jobs capture immutable engine inputs, never windows or SQL writers.
// A document has one active job, one replaceable pending job and one unread
// completion. Futures remain terminal even when their mailbox entry is retired.
class AnalysisPool {
public:
    HEXLAB_WORKSPACE_EXPORT explicit AnalysisPool(PoolLimits={});
    HEXLAB_WORKSPACE_EXPORT ~AnalysisPool();
    AnalysisPool(const AnalysisPool&)=delete;AnalysisPool& operator=(const AnalysisPool&)=delete;
    HEXLAB_WORKSPACE_EXPORT Result<bool> activate(SessionKey);
    HEXLAB_WORKSPACE_EXPORT Result<AnalysisSubmission> submit(SessionKey,const AnalysisKey&,AnalysisPriority,AnalysisTask,std::optional<std::uint64_t> presentation_revision={},AnalysisWorkKind=AnalysisWorkKind::project_analysis);
    HEXLAB_WORKSPACE_EXPORT void cancel(SessionKey);
    // Cancel current work and wait until its worker callback has actually exited.
    HEXLAB_WORKSPACE_EXPORT void cancel_and_wait(SessionKey);
    HEXLAB_WORKSPACE_EXPORT void retire(SessionKey);
    HEXLAB_WORKSPACE_EXPORT std::optional<AnalysisCompletion> take_completed(SessionKey);
    HEXLAB_WORKSPACE_EXPORT PoolStatistics statistics()const;
private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
}
