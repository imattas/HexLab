#include "session_controller.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "project_testing.hpp"
namespace hexlab::desktop {
Result<bool> SessionController::request_listing(std::shared_ptr<const DocumentSnapshot> document, Location location) {
    if (!document || !document->project)
        return Error{ErrorCode::invalid_argument, "Manual listing requires a project"};
    auto id = document->id;
    auto actor = manager_->actor(id);
    auto current = manager_->project(id);
    if (!actor || !current)
        return Error{ErrorCode::invalid_argument, "The document is closed"};
    auto key = project_analysis_key(*document->project, document->project->analysis_options);
    if (!key)
        return key.error();
    auto current_key = project_analysis_key(*current, current->analysis_options);
    if (!current_key)
        return current_key.error();
    if (key.value() != current_key.value())
        return Error{ErrorCode::conflict, "The listing source has changed"};
    auto existing = listings_.find(id.value);
    if (existing != listings_.end() && existing->second.key == key.value() && existing->second.begin == location) {
        if(existing->second.suspended)return false;
        if (existing->second.cached) {
            if (listing_ready)
                listing_ready(id, location, existing->second.cached->page);
            return true;
        }
        if (existing->second.pending)
            return true;
    }
    ListingJob request;
    request.key = key.value();
    request.begin = location;
    request.document = std::move(document);
    listings_.insert_or_assign(id.value, std::move(request));
    return true;
}
bool SessionController::listing_busy(DocumentId id) const {
    auto found = listings_.find(id.value);
    return found != listings_.end() && found->second.job &&
           found->second.job->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
}
bool SessionController::poll_listing() {
    bool changed = false;
    for (auto it = listings_.begin(); it != listings_.end();) {
        DocumentId id{it->first};
        auto actor = manager_->actor(id);
        auto project = manager_->project(id);
        if (!actor || !project) {
            it = listings_.erase(it);
            continue;
        }
        auto &request = it->second;
        auto source = project_analysis_key(*project, project->analysis_options);
        if (!source || source.value() != request.key) {
            it = listings_.erase(it);
            continue;
        }
        if (!request.pending) {
            ++it;
            continue;
        }
        if (!request.job) {
            if (project->status == DerivedStatus::pending || project->status == DerivedStatus::stale ||
                search_pending(id) || graph_busy(id)) {
                ++it;
                continue;
            }
            auto document = std::make_shared<DocumentSnapshot>(*request.document);
            document->project = project;
            if (project->loaded)
                document->image = project->loaded->image;
            auto begin = request.begin;
            auto session = actor->view().session;
            auto key = request.key;
            auto submitted = pool_->submit(
                session, key, AnalysisPriority::foreground,
                [document = std::move(document), begin, session, key](std::stop_token stop) -> Result<AnalysisPayload> {
                    workspace_testing::actor_checkpoint(
                        {session, workspace_testing::ActorPhase::listing_started, 0, key});
                    auto page = make_listing_page(*document, begin, 256, ListingOptions{true, stop});
                    if (!page)
                        return page.error();
                    workspace_testing::actor_checkpoint(
                        {session, workspace_testing::ActorPhase::listing_computed, 0, key});
                    return AnalysisPayload{
                        std::make_shared<const ListingResult>(ListingResult{begin, std::move(page.value())})};
                },
                {}, AnalysisWorkKind::read_only);
            if (!submitted) {
                if (submitted.error().code == ErrorCode::busy) {
                    ++it;
                    continue;
                }
                request.pending = false;
                ++it;
                continue;
            }
            request.job = std::move(submitted.value());
        }
        if (request.job->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            ++it;
            continue;
        }
        auto completed = std::move(*request.job);
        request.job.reset();
        request.pending = false;
        changed = true;
        if (completed.ticket.session != actor->view().session || completed.ticket.source != request.key) {
            ++it;
            continue;
        }
        const auto &result = completed.result.get();
        if (!result) {
            ++it;
            continue;
        }
        auto payload = std::get_if<std::shared_ptr<const ListingResult>>(&result.value());
        if (!payload || !*payload || (*payload)->begin != request.begin) {
            ++it;
            continue;
        }
        request.cached = *payload;
        if (listing_ready)
            listing_ready(id, request.begin, request.cached->page);
        ++it;
    }
    return changed;
}
} // namespace hexlab::desktop
