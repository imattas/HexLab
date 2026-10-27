#include "session_controller.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "project_testing.hpp"
namespace hexlab::desktop {
namespace {
Result<AnalysisKey> source_key(const ProjectSnapshot &snapshot) {
    return project_analysis_key(snapshot, snapshot.analysis_options);
}
Location hit_location(const SearchMatch &hit) { return search_match_location(hit); }
} // namespace
Result<bool> SessionController::find(DocumentId id, SearchQuery query, const SearchLimits &limits) {
    auto project = manager_->project(id);
    auto history = manager_->search_history(id);
    if (!project || !history)
        return Error{ErrorCode::invalid_argument, "Open a project first"};
    auto key = source_key(*project);
    if (!key)
        return key.error();
    if (!limits.max_results || limits.max_results > 4096 || !limits.max_candidates ||
        limits.max_candidates > 16777216 || !limits.max_comparisons || limits.max_comparisons > 67108864)
        return Error{ErrorCode::invalid_argument, "Invalid search page limits"};
    auto begun = history->begin(key.value(), query);
    if (!begun)
        return begun.error();
    SearchJob request;
    request.key = key.value();
    request.query = std::move(query);
    request.limits = limits;
    searches_.insert_or_assign(id.value, std::move(request));
    changed_();
    return true;
}
Result<bool> SessionController::find_all(SearchQuery query, const SearchLimits &limits) {
    const auto documents = manager_->documents();
    std::size_t queued = 0;
    Error first_error{ErrorCode::invalid_argument, "No open documents contain a searchable project"};
    all_search_scope_ = true;
    for (const auto &document : documents) {
        if (!manager_->project(document.id))
            continue;
        auto result = find(document.id, query, limits);
        if (result)
            ++queued;
        else
            first_error = result.error();
    }
    changed_();
    return queued ? Result<bool>(true) : Result<bool>(first_error);
}
Result<bool> SessionController::more_results_all() {
    std::size_t queued = 0;
    Error first_error{ErrorCode::out_of_bounds, "No open document has more search results"};
    for (const auto &document : manager_->documents()) {
        auto history = manager_->search_history(document.id);
        if (!history || !history->continuation() || search_pending(document.id))
            continue;
        auto result = more_results(document.id, false);
        if (result)
            ++queued;
        else
            first_error = result.error();
    }
    return queued ? Result<bool>(true) : Result<bool>(first_error);
}
bool SessionController::all_search_pending() const {
    for (const auto &document : manager_->documents())
        if (search_pending(document.id))
            return true;
    return false;
}
Result<bool> SessionController::more_results(DocumentId id, bool follow) {
    auto history = manager_->search_history(id);
    auto project = manager_->project(id);
    if (!history || !project || !history->query() || !history->continuation())
        return Error{ErrorCode::out_of_bounds, "No further search page"};
    if (search_pending(id))
        return Error{ErrorCode::busy, "A search page is already running"};
    auto key = source_key(*project);
    if (!key)
        return key.error();
    auto cursor = *history->continuation();
    if (cursor.source_key != key.value())
        return Error{ErrorCode::conflict, "Search source changed"};
    SearchJob request;
    request.key = key.value();
    request.query = *history->query();
    request.cursor = cursor;
    request.follow = follow;
    if (auto old = searches_.find(id.value); old != searches_.end())
        request.limits = old->second.limits;
    searches_.insert_or_assign(id.value, std::move(request));
    changed_();
    return true;
}
Result<bool> SessionController::find_next(DocumentId id) {
    auto history = manager_->search_history(id);
    if (!history)
        return Error{ErrorCode::invalid_argument, "Document is closed"};
    // Source edits invalidate retained pages, but the last query remains useful.
    // F3 starts it again against the current immutable source instead of leaving
    // the user to reopen Find and reconstruct the query.
    if (!history->query()) {
        auto previous = searches_.find(id.value);
        auto project = manager_->project(id);
        if (previous != searches_.end() && project) {
            auto key = source_key(*project);
            if (!key)
                return key.error();
            if (key.value() != previous->second.key) {
                auto query = previous->second.query;
                auto limits = previous->second.limits;
                return find(id, std::move(query), limits);
            }
        }
    }
    if (auto match = history->next()) {
        auto moved = manager_->navigate(id, hit_location(*match));
        if (!moved)
            return moved.error();
        changed_();
        return true;
    }
    if (history->continuation())
        return more_results(id, true);
    return Error{ErrorCode::out_of_bounds, "No next search result"};
}
Result<bool> SessionController::find_previous(DocumentId id) {
    auto history = manager_->search_history(id);
    if (!history)
        return Error{ErrorCode::invalid_argument, "Document is closed"};
    if (auto match = history->previous()) {
        auto moved = manager_->navigate(id, hit_location(*match));
        if (!moved)
            return moved.error();
        changed_();
        return true;
    }
    return Error{ErrorCode::out_of_bounds, "No previous search result"};
}
Result<bool> SessionController::find_next_all(DocumentId id) {
    auto current = find_next(id);
    if (current || current.error().code != ErrorCode::out_of_bounds)
        return current;
    bool saw_pending = false;
    for (const auto &document : manager_->documents()) {
        if (document.id == id || !manager_->project(document.id))
            continue;
        if (search_pending(document.id)) {
            saw_pending = true;
            continue;
        }
        auto history = manager_->search_history(document.id);
        if (!history || !history->query())
            continue;
        if (auto match = history->next()) {
            auto moved = manager_->navigate(document.id, hit_location(*match));
            if (!moved)
                return moved.error();
            changed_();
            return true;
        }
        if (history->continuation())
            return more_results(document.id, true);
    }
    return saw_pending ? Result<bool>(Error{ErrorCode::busy, "Waiting for another document's search page"})
                       : Result<bool>(Error{ErrorCode::out_of_bounds, "No next search result in open documents"});
}
Result<bool> SessionController::find_previous_all(DocumentId id) {
    auto current = find_previous(id);
    if (current || current.error().code != ErrorCode::out_of_bounds)
        return current;
    const auto documents = manager_->documents();
    for (auto it = documents.rbegin(); it != documents.rend(); ++it) {
        if (it->id == id || !manager_->project(it->id))
            continue;
        auto history = manager_->search_history(it->id);
        if (!history || !history->query())
            continue;
        auto match = history->size() ? (history->selected_index() ? history->previous()
                                                                  : history->select(history->size() - 1))
                                     : std::optional<SearchMatch>{};
        if (match) {
            auto moved = manager_->navigate(it->id, hit_location(*match));
            if (!moved)
                return moved.error();
            changed_();
            return true;
        }
    }
    return Error{ErrorCode::out_of_bounds, "No previous loaded search result in open documents"};
}
bool SessionController::search_pending(DocumentId id) const {
    auto found = searches_.find(id.value);
    return found != searches_.end() && found->second.pending;
}
wxString SessionController::search_reason(DocumentId id) const {
    auto found = searches_.find(id.value);
    return found == searches_.end() ? wxString{} : wxString::FromUTF8(found->second.reason);
}
bool SessionController::poll_search() {
    bool changed = false;
    for (auto it = searches_.begin(); it != searches_.end();) {
        DocumentId id{it->first};
        auto actor = manager_->actor(id);
        auto project = manager_->project(id);
        auto history = manager_->search_history(id);
        if (!actor || !project || !history) {
            it = searches_.erase(it);
            changed = true;
            continue;
        }
        auto &request = it->second;
        auto key = source_key(*project);
        if (!key || key.value() != request.key || !history->query() || *history->query() != request.query) {
            request.job.reset();
            request.pending = false;
            std::string reason = "Input or query changed; find again";
            changed = changed || request.reason != reason;
            request.reason = std::move(reason);
            ++it;
            continue;
        }
        if (!request.pending) {
            ++it;
            continue;
        }
        if (!request.job) {
            if (project->status == DerivedStatus::pending || project->status == DerivedStatus::stale ||
                listing_busy(id) || graph_busy(id)) {
                ++it;
                continue;
            }
            auto query = request.query;
            auto cursor = request.cursor;
            auto limits = request.limits;
            auto session = actor->view().session;
            auto source = request.key;
            auto submitted = pool_->submit(
                session, source, AnalysisPriority::foreground,
                [project, query = std::move(query), cursor, limits, session,
                 source](std::stop_token stop) -> Result<AnalysisPayload> {
                    workspace_testing::actor_checkpoint(
                        {session, workspace_testing::ActorPhase::search_started, 0, source});
                    auto page = search(*project, query, cursor, limits, stop);
                    if (!page)
                        return page.error();
                    workspace_testing::actor_checkpoint(
                        {session, workspace_testing::ActorPhase::search_computed, 0, source});
                    return AnalysisPayload{
                        std::make_shared<const SearchResults>(SearchResults{query, std::move(page.value())})};
                },
                {}, AnalysisWorkKind::read_only);
            if (!submitted) {
                if (submitted.error().code == ErrorCode::busy) {
                    ++it;
                    continue;
                }
                request.pending = false;
                request.reason = submitted.error().message;
                changed = true;
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
        auto session = actor->view().session;
        if (completed.ticket.session != session || completed.ticket.source != request.key) {
            request.reason = "Retired search completion";
            ++it;
            continue;
        }
        const auto &result = completed.result.get();
        if (!result) {
            request.reason = result.error().message;
            ++it;
            continue;
        }
        auto payload = std::get_if<std::shared_ptr<const SearchResults>>(&result.value());
        if (!payload || !*payload || (*payload)->query != request.query || (*payload)->page.source_key != request.key) {
            request.reason = "Search completion belongs to another request";
            ++it;
            continue;
        }
        auto page = std::shared_ptr<const SearchPage>(*payload, &(*payload)->page);
        auto appended = history->append(std::move(page));
        if (!appended) {
            request.reason = appended.error().message;
            ++it;
            continue;
        }
        request.reason = (*payload)->page.reason;
        if (request.follow)
            if (auto hit = history->next()) {
                auto moved = manager_->navigate(id, hit_location(*hit));
                if (!moved)
                    request.reason = moved.error().message;
            }
        ++it;
    }
    return changed;
}
} // namespace hexlab::desktop
