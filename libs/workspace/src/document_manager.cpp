#include "hexlab/workspace/document_manager.hpp"
#include "project_internal.hpp"
#include <atomic>
#include <chrono>
namespace hexlab {
namespace {
using project_detail::require;
using project_detail::take;
std::atomic<uint64_t> document_sequence = 0;
DocumentId next_id() {
    auto current = document_sequence.load();
    for (;;) {
        require(current < UINT64_MAX, "Document identifiers exhausted", ErrorCode::resource_limit);
        if (document_sequence.compare_exchange_weak(current, current + 1))
            return {current + 1};
    }
}
bool valid(const DocumentSnapshot &document, Location location) {
    if (auto address = std::get_if<Address>(&location))
        return document.image->segment_at(*address) != nullptr;
    return std::get<FileOffset>(location).value < document.file_storage().size();
}
bool same_project_file(const std::filesystem::path& left,const std::filesystem::path& right) {
    if(left.empty() || right.empty())return false;
    std::error_code error;
    const bool same=std::filesystem::equivalent(left,right,error);
    return !error && same;
}
std::shared_ptr<const DocumentSnapshot> projection(SessionKey key, std::shared_ptr<const ProjectSnapshot> project) {
    auto document = std::make_shared<DocumentSnapshot>();
    document->id = key.document;
    document->revision = project->state->revisions.edit;
    document->project = std::move(project);
    auto &snapshot = *document->project;
    document->analysis_requested = snapshot.derived_key.has_value() || snapshot.status == DerivedStatus::pending ||
                                   snapshot.status == DerivedStatus::stale;
    if (snapshot.loaded) {
        document->image = snapshot.loaded->image;
        document->metadata_complete = snapshot.loaded->metadata_complete;
    } else {
        ImageLayout layout{{{0}, 64, 1, ByteOrder::little}, Architecture::unknown, ExecutionMode::unknown, {}, {}};
        document->image = take(Image::create(snapshot.effective, std::move(layout)));
        document->metadata_complete = false;
    }
    return document;
}
} // namespace
struct DocumentManager::Impl {
    struct Entry {
        DocumentId id;
        std::shared_ptr<ProjectActor> actor;
        Workspace navigation;
        SearchHistory search;
        ActorView view;
        std::shared_ptr<const ProjectSnapshot> project;
        ProjectSubmission opening;
        std::vector<ProjectSubmission> operations;
        std::optional<ProjectOperationId> external_check;
        std::chrono::steady_clock::time_point next_external_check{};
        std::optional<Error> error;
        bool opened = false;
    };
    std::shared_ptr<AnalysisPool> pool;
    std::size_t limit;
    std::vector<std::unique_ptr<Entry>> entries;
    std::vector<std::pair<std::shared_ptr<ProjectActor>, ProjectSubmission>> retiring;
    Workspace empty;
    std::optional<DocumentId> active, pending;
    bool dirty = false;
    Impl(std::shared_ptr<AnalysisPool> p, std::size_t maximum) : pool(std::move(p)), limit(maximum) {}
    Entry *find(DocumentId id) {
        for (auto &entry : entries)
            if (entry->id == id)
                return entry.get();
        return nullptr;
    }
    const Entry *find(DocumentId id) const {
        for (auto &entry : entries)
            if (entry->id == id)
                return entry.get();
        return nullptr;
    }
    Workspace &workspace() {
        if (active)
            if (auto entry = find(*active))
                return entry->navigation;
        return empty;
    }
    void retire(std::shared_ptr<ProjectActor> actor) {
        auto closing = take(actor->close());
        retiring.emplace_back(std::move(actor), std::move(closing));
    }
};
DocumentManager::DocumentManager(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Result<std::unique_ptr<DocumentManager>> DocumentManager::create(std::shared_ptr<AnalysisPool> pool,
                                                                 std::size_t maximum) {
    return project_detail::guarded([&]() -> Result<std::unique_ptr<DocumentManager>> {
        require(pool && maximum > 0 && maximum <= 128, "Invalid document manager pool/capacity");
        auto impl = std::make_unique<Impl>(std::move(pool), maximum);
        impl->entries.reserve(maximum);
        impl->retiring.reserve(maximum * 2);
        return std::unique_ptr<DocumentManager>(new DocumentManager(std::move(impl)));
    });
}
DocumentManager::~DocumentManager() {
    close_all();
    for (auto &[actor, closing] : impl_->retiring)
        closing.result.wait();
    impl_->retiring.clear();
}
Result<DocumentId> DocumentManager::import_binary(OpenRequest request) {
    return project_detail::guarded([&]() -> Result<DocumentId> {
        require(impl_->entries.size() + impl_->retiring.size() < impl_->limit, "Document capacity reached",
                ErrorCode::resource_limit);
        auto id = next_id();
        auto actor = take(ProjectActor::create({id, 1}, impl_->pool));
        auto opening = take(actor->import_binary(std::move(request)));
        auto entry = std::make_unique<Impl::Entry>();
        entry->id = id;
        entry->actor = std::move(actor);
        entry->opening = std::move(opening);
        entry->operations.reserve(128);
        impl_->entries.push_back(std::move(entry));
        impl_->pending = id;
        impl_->workspace().pending_ = OpenTicket{id, 1};
        impl_->workspace().error_.reset();
        return id;
    });
}
Result<DocumentId> DocumentManager::open_project(std::filesystem::path path, database::ProjectMode mode,
                                                 const AnalysisOptions &options) {
    return project_detail::guarded([&]() -> Result<DocumentId> {
        require(impl_->entries.size() + impl_->retiring.size() < impl_->limit, "Document capacity reached",
                ErrorCode::resource_limit);
        auto id = next_id();
        auto actor = take(ProjectActor::create({id, 1}, impl_->pool));
        auto opening = take(actor->open_project(std::move(path), mode, options));
        auto entry = std::make_unique<Impl::Entry>();
        entry->id = id;
        entry->actor = std::move(actor);
        entry->opening = std::move(opening);
        entry->operations.reserve(128);
        impl_->entries.push_back(std::move(entry));
        impl_->pending = id;
        impl_->workspace().pending_ = OpenTicket{id, 1};
        impl_->workspace().error_.reset();
        return id;
    });
}
Result<bool> DocumentManager::poll() {
    return project_detail::guarded([&]() -> Result<bool> {
        bool changed = impl_->dirty;
        impl_->dirty = false;
        for (auto it = impl_->retiring.begin(); it != impl_->retiring.end();)
            if (it->second.result.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                it = impl_->retiring.erase(it);
                changed = true;
            } else
                ++it;
        for (std::size_t index = 0; index < impl_->entries.size();) {
            auto &entry = *impl_->entries[index];
            bool remove = false;
            std::optional<Error> open_error;
            if (!entry.opened &&
                entry.opening.result.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                const auto &opened = entry.opening.result.get();
                if (!opened) {
                    if (impl_->pending == entry.id || impl_->active == entry.id)
                        open_error = opened.error();
                    if (impl_->pending == entry.id) {
                        impl_->pending.reset();
                        impl_->workspace().pending_.reset();
                    }
                    remove = true;
                } else {
                    std::optional<DocumentId> duplicate;
                    for (auto &candidate : impl_->entries)
                        if (candidate->id != entry.id && candidate->project &&
                            candidate->project->state->uuid == opened.value().snapshot->state->uuid) {
                            duplicate = candidate->id;
                            break;
                        }
                    if (duplicate) {
                        if (impl_->pending == entry.id || impl_->active == entry.id) {
                            impl_->workspace().pending_.reset();
                            if (impl_->pending == entry.id)
                                impl_->pending.reset();
                            impl_->active = duplicate;
                        }
                        remove = true;
                    } else {
                        entry.opened = true;
                        if (impl_->pending == entry.id) {
                            impl_->workspace().pending_.reset();
                            impl_->pending.reset();
                            impl_->active = entry.id;
                        }
                        entry.opening = {};
                    }
                }
                changed = true;
            }
            if (remove) {
                auto id = entry.id;
                impl_->retire(entry.actor);
                impl_->entries.erase(impl_->entries.begin() + std::ptrdiff_t(index));
                if (impl_->active == id) {
                    impl_->active.reset();
                    for (auto it = impl_->entries.rbegin(); it != impl_->entries.rend(); ++it)
                        if ((*it)->opened) {
                            impl_->active = (*it)->id;
                            break;
                        }
                }
                if (open_error)
                    impl_->workspace().error_ = std::move(open_error);
                continue;
            }
            for (auto it = entry.operations.begin(); it != entry.operations.end();) {
                if (it->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
                    ++it;
                    continue;
                }
                const auto &result = it->result.get();
                if (entry.external_check == it->id)
                    entry.external_check.reset();
                if (!result) {
                    entry.error = result.error();
                    entry.navigation.error_ = result.error();
                } else {
                    entry.error.reset();
                    entry.navigation.error_.reset();
                }
                it = entry.operations.erase(it);
                changed = true;
            }
            if (entry.opened) {
                auto view = entry.actor->view();
                if (view.generation != entry.view.generation) {
                    if (view.snapshot && view.snapshot != entry.project) {
                        auto previous = entry.navigation.current_;
                        auto next = projection(view.session, view.snapshot);
                        entry.project = view.snapshot;
                        entry.navigation.current_ = std::move(next);
                        auto &nav = entry.navigation;
                        if (previous && previous->project &&
                            (previous->project->state->input != entry.project->state->input ||
                             previous->project->state->revisions.bytes != entry.project->state->revisions.bytes ||
                             previous->project->state->revisions.decisions !=
                                 entry.project->state->revisions.decisions))
                            entry.search.clear();
                        if (previous && previous->image != nav.current_->image) {
                            std::vector<Location> kept;
                            kept.reserve(nav.history_.size());
                            std::size_t position = 0;
                            for (std::size_t n = 0; n < nav.history_.size(); ++n)
                                if (valid(*nav.current_, nav.history_[n])) {
                                    if (n <= nav.history_position_)
                                        position = kept.size();
                                    kept.push_back(nav.history_[n]);
                                }
                            nav.history_ = std::move(kept);
                            nav.history_position_ = position;
                        }
                        if (nav.selection_ && !valid(*nav.current_, *nav.selection_)) {
                            std::optional<Location> fallback;
                            if (previous && previous->image->storage().get() == &previous->file_storage() &&
                                std::holds_alternative<Address>(*nav.selection_)) {
                                auto file = previous->image->to_file_offset(std::get<Address>(*nav.selection_));
                                if (file && valid(*nav.current_, file.value()))
                                    fallback = file.value();
                            }
                            nav.selection_ = fallback;
                            nav.history_.clear();
                            nav.history_position_ = 0;
                        }
                        if (!nav.selection_) {
                            if (!nav.current_->image->layout().entries.empty())
                                nav.selection_ = nav.current_->image->layout().entries.front();
                            else if (nav.current_->file_storage().size())
                                nav.selection_ = FileOffset{0};
                        }
                        if (nav.selection_ && nav.history_.empty())
                            nav.history_.push_back(*nav.selection_);
                    }
                    entry.view = std::move(view);
                    changed = true;
                }
                if (entry.view.analysis_pending)
                    entry.navigation.pending_ = OpenTicket{entry.id, entry.view.session.epoch};
                else if (!impl_->pending || impl_->active != entry.id)
                    entry.navigation.pending_.reset();

                // Probe at most once per second and only when this actor has
                // no queued user work. The SQLite header check is cheap; a
                // full refresh is serialized by the actor only after a
                // different process advances the persisted project revision.
                const auto now = std::chrono::steady_clock::now();
                if (entry.view.project_path && !entry.external_check && now >= entry.next_external_check) {
                    if (entry.actor->view().pending_operations == 0) {
                        auto submitted = entry.actor->refresh_if_external();
                        if (submitted) {
                            entry.external_check = submitted.value().id;
                            entry.operations.push_back(std::move(submitted.value()));
                            entry.next_external_check = now + std::chrono::seconds(1);
                        } else {
                            entry.error = submitted.error();
                            entry.next_external_check = now + std::chrono::seconds(1);
                            changed = true;
                        }
                    } else {
                        entry.next_external_check = now + std::chrono::milliseconds(250);
                    }
                }
            }
            ++index;
        }
        if (impl_->pending)
            impl_->workspace().pending_ = OpenTicket{*impl_->pending, 1};
        return changed;
    });
}
void DocumentManager::report_error(Error error) {
    impl_->workspace().error_ = std::move(error);
    impl_->dirty = true;
}
void DocumentManager::report_error(DocumentId id, Error error) {
    if (auto entry = impl_->find(id)) {
        entry->error = error;
        entry->navigation.error_ = std::move(error);
        impl_->dirty = true;
    }
}
Result<bool> DocumentManager::activate(DocumentId id) {
    return project_detail::guarded([&]() -> Result<bool> {
        require(impl_->find(id) != nullptr, "Document is closed");
        impl_->workspace().pending_.reset();
        impl_->active = id;
        return true;
    });
}
Result<Location> DocumentManager::navigate(DocumentId id, Location location) {
    auto entry = impl_->find(id);
    if (!entry)
        return Error{ErrorCode::invalid_argument, "Document is closed"};
    return entry->navigation.navigate(location);
}
Result<bool> DocumentManager::close(DocumentId id) {
    return project_detail::guarded([&]() -> Result<bool> {
        auto entry = impl_->find(id);
        require(entry != nullptr, "Document is closed");
        impl_->retire(entry->actor);
        if (impl_->pending == id) {
            impl_->pending.reset();
            impl_->workspace().pending_.reset();
        }
        impl_->entries.erase(std::find_if(impl_->entries.begin(), impl_->entries.end(),
                                          [&](auto &candidate) { return candidate->id == id; }));
        if (impl_->active == id) {
            impl_->active.reset();
            for (auto it = impl_->entries.rbegin(); it != impl_->entries.rend(); ++it)
                if ((*it)->opened) {
                    impl_->active = (*it)->id;
                    break;
                }
        }
        return true;
    });
}
Result<bool> DocumentManager::synchronize_external(const std::filesystem::path& path,
                                                   const database::ProjectUuid& uuid) {
    return project_detail::guarded([&]() -> Result<bool> {
        std::vector<Impl::Entry*> matches;
        for (auto& entry : impl_->entries)
            if (entry->opened && entry->project && entry->view.project_path &&
                entry->project->state->uuid == uuid && same_project_file(path, *entry->view.project_path))
                matches.push_back(entry.get());
        require(!matches.empty(), "No open document matches this project file and identity", ErrorCode::invalid_argument);

        std::vector<std::pair<DocumentId, ProjectSubmission>> pending;
        pending.reserve(matches.size());
        std::optional<Error> first_error;
        for (auto* entry : matches) {
            auto submitted = entry->actor->refresh_external();
            if (!submitted) {
                if (!first_error) first_error = submitted.error();
                report_error(entry->id, submitted.error());
                continue;
            }
            pending.emplace_back(entry->id, std::move(submitted.value()));
        }
        for (auto& [id, operation] : pending) {
            try {
                const auto& completed = operation.result.get();
                if (!completed) {
                    if (!first_error) first_error = completed.error();
                    report_error(id, completed.error());
                }
            } catch (const std::exception& error) {
                Error failure{ErrorCode::io, error.what()};
                if (!first_error) first_error = failure;
                report_error(id, std::move(failure));
            }
        }
        impl_->dirty = true;
        if (first_error) return *first_error;
        return true;
    });
}
Result<bool> DocumentManager::refresh_external(const std::filesystem::path& path,
                                               const database::ProjectUuid& uuid) {
    return project_detail::guarded([&]() -> Result<bool> {
        std::vector<Impl::Entry*> matches;
        for (auto& entry : impl_->entries)
            if (entry->opened && entry->project && entry->view.project_path &&
                entry->project->state->uuid == uuid && same_project_file(path, *entry->view.project_path))
                matches.push_back(entry.get());
        require(!matches.empty(), "No open document matches this project file and identity", ErrorCode::invalid_argument);

        std::optional<Error> first_error;
        for (auto* entry : matches) {
            auto submitted = entry->actor->refresh_external();
            if (!submitted) {
                if (!first_error) first_error = submitted.error();
                report_error(entry->id, submitted.error());
                continue;
            }
            auto watched = watch(entry->id, std::move(submitted));
            if (!watched) {
                if (!first_error) first_error = watched.error();
                report_error(entry->id, watched.error());
            }
        }
        if (first_error) return *first_error;
        return true;
    });
}
void DocumentManager::cancel_open() {
    if (impl_->pending) {
        auto id = *impl_->pending;
        auto result = close(id);
        (void)result;
    } else if (impl_->active) {
        auto actor = impl_->find(*impl_->active)->actor;
        actor->cancel_analysis();
        impl_->workspace().pending_.reset();
    }
}
void DocumentManager::close_all() {
    while (!impl_->entries.empty()) {
        auto result = close(impl_->entries.back()->id);
        if (!result)
            break;
    }
    impl_->active.reset();
    impl_->pending.reset();
    impl_->empty.close_document();
}
Workspace &DocumentManager::active_workspace() { return impl_->workspace(); }
const Workspace &DocumentManager::active_workspace() const { return impl_->workspace(); }
std::optional<DocumentId> DocumentManager::active_document() const { return impl_->active; }
std::vector<DocumentInfo> DocumentManager::documents() const {
    std::vector<DocumentInfo> result;
    result.reserve(impl_->entries.size());
    for (auto &entry : impl_->entries) {
        DocumentInfo info{entry->id, entry->actor->view().session};
        info.error = entry->error;
        info.path = entry->view.project_path;
        info.analysis_pending = entry->view.analysis_pending;
        if (entry->project) {
            info.uuid = entry->project->state->uuid;
            info.readonly = entry->project->mode == database::ProjectMode::read_only;
            info.save_state = entry->error           ? DocumentSaveState::error
                              : entry->view.untitled ? DocumentSaveState::untitled
                                                     : DocumentSaveState::saved;
        }
        if (!entry->operations.empty() && entry->project)
            info.save_state = DocumentSaveState::saving;
        result.push_back(std::move(info));
    }
    return result;
}
std::shared_ptr<const ProjectSnapshot> DocumentManager::project(DocumentId id) const {
    auto entry = impl_->find(id);
    return entry ? entry->project : nullptr;
}
std::optional<Location> DocumentManager::selection(DocumentId id) const {
    auto entry = impl_->find(id);
    return entry ? entry->navigation.selection() : std::nullopt;
}
std::shared_ptr<ProjectActor> DocumentManager::actor(DocumentId id) const {
    auto entry = impl_->find(id);
    return entry ? entry->actor : nullptr;
}
Result<ProjectOperationId> DocumentManager::watch(DocumentId id, Result<ProjectSubmission> submitted) {
    return project_detail::guarded([&]() -> Result<ProjectOperationId> {
        auto entry = impl_->find(id);
        require(entry != nullptr, "Document is closed");
        auto operation = take(std::move(submitted));
        require(operation.session.document == id && operation.session == entry->actor->view().session,
                "Operation belongs to another document session", ErrorCode::conflict);
        require(entry->operations.size() < 128, "Too many observed document operations", ErrorCode::resource_limit);
        auto result = operation.id;
        entry->operations.push_back(std::move(operation));
        return result;
    });
}
SearchHistory *DocumentManager::search_history(DocumentId id) {
    auto entry = impl_->find(id);
    return entry ? &entry->search : nullptr;
}
} // namespace hexlab
