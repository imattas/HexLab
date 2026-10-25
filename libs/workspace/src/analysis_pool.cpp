#include "hexlab/workspace/analysis_pool.hpp"
#include <condition_variable>
#include <map>
#include <thread>
namespace hexlab {
struct AnalysisPool::Impl {
    struct Work {
        AnalysisTicket ticket;
        AnalysisPriority priority = AnalysisPriority::normal;
        AnalysisWorkKind kind = AnalysisWorkKind::project_analysis;
        AnalysisTask task;
        std::stop_source stop;
        std::promise<Result<AnalysisPayload>> promise;
        std::shared_future<Result<AnalysisPayload>> future = promise.get_future().share();
        bool finished = false, stop_marked = false;
    };
    struct Slot {
        SessionKey session;
        bool registered = true;
        std::uint64_t latest = 0;
        std::optional<AnalysisKey> source;
        std::shared_ptr<Work> active, pending;
        std::optional<AnalysisCompletion> ready;
    };
    PoolLimits limits;
    mutable std::mutex mutex;
    std::condition_variable_any changed;
    std::map<uint64_t, Slot> slots;
    uint64_t sequence = 0;
    bool closing = false;
    std::vector<std::jthread> workers;
    explicit Impl(PoolLimits value) : limits(value) {
        if (!limits.max_sessions || limits.max_sessions > 4096)
            throw std::invalid_argument("Analysis pool capacity must be between 1 and 4096 sessions");
        workers.reserve(2);
        for (unsigned i = 0; i < 2; ++i)
            workers.emplace_back([this](std::stop_token stop) { run(stop); });
    }
    static void finish(Work &work, Result<AnalysisPayload> result) {
        if (work.finished)
            return;
        work.promise.set_value(std::move(result));
        work.finished = true;
    }
    ~Impl() {
        {
            std::lock_guard lock(mutex);
            closing = true;
        }
        for (auto &worker : workers)
            worker.request_stop();
        changed.notify_all();
        // Retire one captured job at a time, requesting stop outside the mutex.
        // This path needs no allocation proportional to the number of sessions.
        for (;;) {
            std::shared_ptr<Work> stopped;
            {
                std::lock_guard lock(mutex);
                for (auto &[id, slot] : slots) {
                    if (slot.pending) {
                        stopped = std::move(slot.pending);
                        finish(*stopped, Error{ErrorCode::canceled, "Pool closed"});
                        stopped->stop_marked = true;
                        break;
                    }
                    if (slot.active && !slot.active->stop_marked) {
                        stopped = slot.active;
                        finish(*stopped, Error{ErrorCode::canceled, "Pool closed"});
                        stopped->stop_marked = true;
                        break;
                    }
                }
            }
            if (!stopped)
                break;
            stopped->stop.request_stop();
        }
        changed.notify_all();
        for (auto &worker : workers)
            if (worker.joinable())
                worker.join();
    }
    bool runnable() const {
        for (auto &[id, slot] : slots)
            if (slot.registered && slot.pending && !slot.active)
                return true;
        return false;
    }
    std::shared_ptr<Work> select() {
        Slot *selected = nullptr;
        for (auto &[id, slot] : slots)
            if (slot.registered && slot.pending && !slot.active) {
                if (!selected || slot.pending->priority < selected->pending->priority ||
                    (slot.pending->priority == selected->pending->priority &&
                     slot.pending->ticket.sequence < selected->pending->ticket.sequence))
                    selected = &slot;
            }
        if (!selected)
            return {};
        selected->active = std::move(selected->pending);
        return selected->active;
    }
    void run(std::stop_token stop) {
        for (;;) {
            std::shared_ptr<Work> work;
            {
                std::unique_lock lock(mutex);
                if (!changed.wait(lock, stop, [&] { return closing || runnable(); }) || closing ||
                    stop.stop_requested())
                    return;
                work = select();
            }
            if (!work)
                continue;
            auto result = [&]() -> Result<AnalysisPayload> {
                try {
                    if (work->stop.stop_requested())
                        return Error{ErrorCode::canceled, "Canceled"};
                    return work->task(work->stop.get_token());
                } catch (const std::bad_alloc &) {
                    return Error{ErrorCode::resource_limit, "Worker allocation failed"};
                } catch (const std::exception &error) {
                    return Error{ErrorCode::io, std::string("Analysis worker failed: ") + error.what()};
                } catch (...) {
                    return Error{ErrorCode::io, "Analysis worker failed with an unknown exception"};
                }
            }();
            std::optional<AnalysisCompletion> discarded;
            {
                std::lock_guard lock(mutex);
                auto found = slots.find(work->ticket.session.document.value);
                if (found != slots.end()) {
                    auto &slot = found->second;
                    const bool current = slot.registered && slot.session == work->ticket.session &&
                                         slot.latest == work->ticket.sequence && !closing;
                    if (!work->finished) {
                        if (work->stop.stop_requested() || !current)
                            finish(*work, Error{ErrorCode::canceled, "Superseded"});
                        else
                            finish(*work, std::move(result));
                        if (current) {
                            discarded = std::move(slot.ready);
                            slot.ready = AnalysisCompletion{work->ticket, work->future};
                        }
                    }
                    if (slot.active == work)
                        slot.active.reset();
                    if (!slot.registered && !slot.active && !slot.pending)
                        slots.erase(found);
                } else
                    finish(*work, Error{ErrorCode::canceled, "Session closed"});
            }
            changed.notify_all();
            // Work and discarded immutable payloads are released outside locks.
        }
    }
};
AnalysisPool::AnalysisPool(PoolLimits limits) : impl_(std::make_unique<Impl>(limits)) {}
AnalysisPool::~AnalysisPool() = default;
Result<bool> AnalysisPool::activate(SessionKey key) {
    if (!key.document.value || !key.epoch)
        return Error{ErrorCode::invalid_argument, "Analysis session needs a document and epoch"};
    try {
        std::shared_ptr<Impl::Work> active, pending;
        std::optional<AnalysisCompletion> discarded;
        {
            std::lock_guard lock(impl_->mutex);
            if (impl_->closing)
                return Error{ErrorCode::canceled, "Analysis pool is closing"};
            auto found = impl_->slots.find(key.document.value);
            if (found == impl_->slots.end()) {
                if (impl_->slots.size() >= impl_->limits.max_sessions)
                    return Error{ErrorCode::resource_limit, "Analysis pool session capacity reached"};
                Impl::Slot slot;
                slot.session = key;
                impl_->slots.emplace(key.document.value, std::move(slot));
                return true;
            }
            auto &slot = found->second;
            if (key.epoch < slot.session.epoch || (key.epoch == slot.session.epoch && !slot.registered))
                return Error{ErrorCode::conflict, "Analysis session epoch was already retired"};
            if (slot.session == key && slot.registered)
                return true;
            active = slot.active;
            pending = std::move(slot.pending);
            discarded = std::move(slot.ready);
            slot.session = key;
            slot.registered = true;
            slot.latest = 0;
            slot.source.reset();
            if (active) {
                Impl::finish(*active, Error{ErrorCode::canceled, "Superseded"});
                active->stop_marked = true;
            }
            if (pending) {
                Impl::finish(*pending, Error{ErrorCode::canceled, "Superseded"});
                pending->stop_marked = true;
            }
        }
        if (active)
            active->stop.request_stop();
        if (pending)
            pending->stop.request_stop();
        impl_->changed.notify_all();
        return true;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot register analysis session"};
    }
}
Result<AnalysisSubmission> AnalysisPool::submit(SessionKey key, const AnalysisKey &source, AnalysisPriority priority,
                                                AnalysisTask task, std::optional<uint64_t> presentation,
                                                AnalysisWorkKind kind) {
    if (!task || (priority != AnalysisPriority::foreground && priority != AnalysisPriority::normal) ||
        (kind != AnalysisWorkKind::project_analysis && kind != AnalysisWorkKind::read_only))
        return Error{ErrorCode::invalid_argument, "Analysis submission needs a task, known priority and work kind"};
    try {
        auto work = std::make_shared<Impl::Work>();
        work->task = std::move(task);
        work->priority = priority;
        work->kind = kind;
        work->ticket.session = key;
        work->ticket.source = source;
        work->ticket.presentation_revision = presentation;
        std::shared_ptr<Impl::Work> active, pending;
        std::optional<AnalysisCompletion> discarded;
        {
            std::lock_guard lock(impl_->mutex);
            if (impl_->closing)
                return Error{ErrorCode::canceled, "Analysis pool is closing"};
            auto found = impl_->slots.find(key.document.value);
            if (found == impl_->slots.end() || !found->second.registered || found->second.session != key)
                return Error{ErrorCode::conflict, "Analysis session is not active"};
            if (impl_->sequence == UINT64_MAX)
                return Error{ErrorCode::resource_limit, "Analysis sequence space exhausted"};
            auto &slot = found->second;
            if (slot.source) {
                auto &before = *slot.source;
                if (source.input != before.input || source.recipe_fingerprint != before.recipe_fingerprint ||
                    source.byte_revision < before.byte_revision || source.decision_revision < before.decision_revision)
                    return Error{ErrorCode::conflict,
                                 "Analysis source belongs to an earlier or different session revision"};
            }
            if (kind == AnalysisWorkKind::read_only &&
                ((slot.active && !slot.active->finished && slot.active->kind == AnalysisWorkKind::project_analysis) ||
                 (slot.pending && slot.pending->kind == AnalysisWorkKind::project_analysis)))
                return Error{ErrorCode::busy, "Project analysis owns this session; retry the read after completion"};
            slot.source = source;
            work->ticket.sequence = ++impl_->sequence;
            slot.latest = work->ticket.sequence;
            active = slot.active;
            pending = std::move(slot.pending);
            discarded = std::move(slot.ready);
            slot.pending = work;
            if (active) {
                Impl::finish(*active, Error{ErrorCode::canceled, "Superseded"});
                active->stop_marked = true;
            }
            if (pending) {
                Impl::finish(*pending, Error{ErrorCode::canceled, "Superseded"});
                pending->stop_marked = true;
            }
        }
        if (active)
            active->stop.request_stop();
        if (pending)
            pending->stop.request_stop();
        impl_->changed.notify_all();
        return AnalysisSubmission{work->ticket, work->future};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate analysis request"};
    }
}
void AnalysisPool::cancel(SessionKey key) {
    std::shared_ptr<Impl::Work> active, pending;
    std::optional<AnalysisCompletion> discarded;
    {
        std::lock_guard lock(impl_->mutex);
        auto found = impl_->slots.find(key.document.value);
        if (found == impl_->slots.end() || !found->second.registered || found->second.session != key)
            return;
        auto &slot = found->second;
        active = slot.active;
        pending = std::move(slot.pending);
        discarded = std::move(slot.ready);
        if (active) {
            Impl::finish(*active, Error{ErrorCode::canceled, "Canceled"});
            active->stop_marked = true;
        }
        if (pending) {
            Impl::finish(*pending, Error{ErrorCode::canceled, "Canceled"});
            pending->stop_marked = true;
        }
        auto latest = pending ? pending : active;
        if (latest && latest->ticket.sequence == slot.latest)
            slot.ready = AnalysisCompletion{latest->ticket, latest->future};
    }
    if (active)
        active->stop.request_stop();
    if (pending)
        pending->stop.request_stop();
    impl_->changed.notify_all();
}
void AnalysisPool::cancel_and_wait(SessionKey key) {
    cancel(key);
    std::unique_lock lock(impl_->mutex);
    impl_->changed.wait(lock, [&] {
        auto found = impl_->slots.find(key.document.value);
        return found == impl_->slots.end() || !found->second.registered ||
               found->second.session != key || !found->second.active;
    });
}
void AnalysisPool::retire(SessionKey key) {
    std::shared_ptr<Impl::Work> active, pending;
    std::optional<AnalysisCompletion> discarded;
    {
        std::lock_guard lock(impl_->mutex);
        auto found = impl_->slots.find(key.document.value);
        if (found == impl_->slots.end() || found->second.session != key)
            return;
        auto &slot = found->second;
        slot.registered = false;
        active = slot.active;
        pending = std::move(slot.pending);
        discarded = std::move(slot.ready);
        if (active) {
            Impl::finish(*active, Error{ErrorCode::canceled, "Session closed"});
            active->stop_marked = true;
        }
        if (pending) {
            Impl::finish(*pending, Error{ErrorCode::canceled, "Session closed"});
            pending->stop_marked = true;
        }
        if (!active)
            impl_->slots.erase(found);
    }
    if (active)
        active->stop.request_stop();
    if (pending)
        pending->stop.request_stop();
    impl_->changed.notify_all();
}
std::optional<AnalysisCompletion> AnalysisPool::take_completed(SessionKey key) {
    std::lock_guard lock(impl_->mutex);
    auto found = impl_->slots.find(key.document.value);
    if (found == impl_->slots.end() || !found->second.registered || found->second.session != key)
        return {};
    auto ready = std::move(found->second.ready);
    found->second.ready.reset();
    return ready;
}
PoolStatistics AnalysisPool::statistics() const {
    std::lock_guard lock(impl_->mutex);
    PoolStatistics out;
    out.workers = impl_->workers.size();
    for (auto &[id, slot] : impl_->slots) {
        out.sessions += slot.registered;
        out.running += bool(slot.active);
        out.pending += bool(slot.pending);
        out.ready += slot.ready.has_value();
    }
    return out;
}
} // namespace hexlab
