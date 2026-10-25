#include "hexlab/workspace/analysis_pool.hpp"
#include "support/checks.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <semaphore>
#include <thread>
using namespace hexlab;
using namespace hexlab_test;
using namespace std::chrono_literals;
namespace {
struct GateState {
    std::promise<bool> entered;
    std::binary_semaphore released{0};
    std::atomic<bool> opened = false;
};
struct Gate {
    std::shared_ptr<GateState> state = std::make_shared<GateState>();
    std::future<bool> entered = state->entered.get_future();
    ~Gate() { release(); }
    void release() {
        if (!state->opened.exchange(true))
            state->released.release();
    }
    void wait() {
        if (entered.wait_for(3s) != std::future_status::ready)
            throw std::runtime_error("Worker did not reach deterministic barrier");
        entered.get();
    }
};
AnalysisPayload payload(unsigned value) {
    auto layout = std::make_shared<GraphLayout>();
    layout->key[0] = std::byte(value);
    return std::shared_ptr<const GraphLayout>(std::move(layout));
}
AnalysisTask blocked(Gate &gate, unsigned value) {
    auto state = gate.state;
    return [state, value](std::stop_token) -> Result<AnalysisPayload> {
        state->entered.set_value(true);
        state->released.acquire();
        return payload(value);
    };
}
Result<AnalysisPayload> await(const AnalysisSubmission &submission) {
    if (submission.result.wait_for(3s) != std::future_status::ready)
        throw std::runtime_error("Analysis submission has no terminal result");
    return submission.result.get();
}
unsigned marker(const Result<AnalysisPayload> &result) {
    return std::to_integer<unsigned>(std::get<std::shared_ptr<const GraphLayout>>(result.value())->key[0]);
}
void replacement_tests() {
    AnalysisPool pool;
    Gate old_gate;
    const SessionKey first{{1}, 1};
    check(bool(pool.activate(first)), "first pool session activates");
    AnalysisKey key;
    auto old = pool.submit(first, key, AnalysisPriority::normal, blocked(old_gate, 1)).value();
    old_gate.wait();
    ++key.byte_revision;
    auto replaced = pool.submit(first, key, AnalysisPriority::normal,
                                [](std::stop_token) -> Result<AnalysisPayload> { return payload(2); })
                        .value();
    ++key.byte_revision;
    auto newest = pool.submit(first, key, AnalysisPriority::foreground,
                              [](std::stop_token) -> Result<AnalysisPayload> { return payload(3); })
                      .value();
    check(!await(replaced) && !await(old), "replaced queued/running submissions reach explicit cancellation terminals");
    auto stats = pool.statistics();
    check(stats.workers == 2 && stats.running == 1 && stats.pending == 1,
          "document has one running and one replaceable pending analysis");
    check(!pool.take_completed(SessionKey{{2}, 1}), "another document cannot consume a completion");
    old_gate.release();
    check(marker(await(newest)) == 3, "newest queued request completes after retired running task releases");
    auto ready = pool.take_completed(first);
    check(ready && ready->ticket.sequence == newest.ticket.sequence && ready->ticket.source == key &&
              marker(ready->result.get()) == 3,
          "only newest unread result and its exact source key are published");
    check(!pool.take_completed(first), "completion is consumed once");
    pool.retire(first);
}
void epoch_and_priority_tests() {
    AnalysisPool pool;
    Gate left, right;
    SessionKey a{{1}, 1}, b{{2}, 1}, c{{3}, 1}, d{{4}, 1};
    for (auto key : {a, b, c, d})
        check(bool(pool.activate(key)), "priority fixture session activates");
    AnalysisKey source;
    auto first = pool.submit(a, source, AnalysisPriority::normal, blocked(left, 1)).value();
    auto second = pool.submit(b, source, AnalysisPriority::normal, blocked(right, 2)).value();
    left.wait();
    right.wait();
    std::mutex order_mutex;
    std::vector<unsigned> order;
    auto task = [&](unsigned id) {
        return [&, id](std::stop_token) -> Result<AnalysisPayload> {
            std::lock_guard lock(order_mutex);
            order.push_back(id);
            return payload(id);
        };
    };
    auto background = pool.submit(c, source, AnalysisPriority::normal, task(3)).value();
    auto foreground = pool.submit(d, source, AnalysisPriority::foreground, task(4)).value();
    left.release();
    check(marker(await(foreground)) == 4 && marker(await(background)) == 3,
          "foreground pending work is selected before background work");
    {
        std::lock_guard lock(order_mutex);
        check(order == std::vector<unsigned>{4, 3},
              "priority selection is proven by barrier-controlled execution order");
    }
    right.release();
    check(bool(await(first)) && bool(await(second)), "independent running documents complete normally");
    Gate stale;
    auto old = pool.submit(a, source, AnalysisPriority::normal, blocked(stale, 5)).value();
    stale.wait();
    SessionKey reopened{{1}, 2};
    check(bool(pool.activate(reopened)), "same document activates a new immutable epoch");
    auto fresh = pool.submit(reopened, source, AnalysisPriority::normal,
                             [](std::stop_token) -> Result<AnalysisPayload> { return payload(6); })
                     .value();
    check(!await(old) && !pool.take_completed(a), "old epoch is terminally canceled and cannot read new epoch mailbox");
    stale.release();
    check(marker(await(fresh)) == 6, "reopened epoch receives its own result");
    auto completion = pool.take_completed(reopened);
    check(completion && completion->ticket.session == reopened, "late old completion cannot restore a closed session");
}
void capacity_and_shutdown_tests() {
    AnalysisPool pool(PoolLimits{2});
    check(bool(pool.activate({{1}, 1})) && bool(pool.activate({{2}, 1})) && !pool.activate({{3}, 1}),
          "registered sessions have an explicit bounded capacity");
    Gate gate;
    auto active = pool.submit({{1}, 1}, {}, AnalysisPriority::normal, blocked(gate, 1)).value();
    gate.wait();
    pool.cancel({{1}, 1});
    check(!await(active), "explicit running cancellation has a terminal future");
    gate.release();
    pool.retire({{1}, 1});
    pool.retire({{2}, 1});
    std::atomic<unsigned> stopped = 0;
    auto owned = std::make_unique<AnalysisPool>();
    check(bool(owned->activate({{9}, 1})), "shutdown fixture session activates");
    std::promise<bool> entered;
    auto started = entered.get_future();
    auto running = owned
                       ->submit({{9}, 1}, {}, AnalysisPriority::normal,
                                [&](std::stop_token stop) -> Result<AnalysisPayload> {
                                    entered.set_value(true);
                                    std::mutex mutex;
                                    std::condition_variable_any changed;
                                    std::unique_lock lock(mutex);
                                    changed.wait(lock, stop, [] { return false; });
                                    ++stopped;
                                    return Error{ErrorCode::canceled, "Stopped by pool destruction"};
                                })
                       .value();
    check(started.wait_for(3s) == std::future_status::ready, "shutdown worker is running before destruction");
    owned.reset();
    check(stopped == 1 && !await(running), "pool destruction stops and joins workers without holding their mutex");
}
void writer_ownership_tests() {
    AnalysisPool pool;
    SessionKey session{{30}, 1};
    check(bool(pool.activate(session)), "writer ownership fixture activates");
    AnalysisKey key;
    key.byte_revision = 1;
    Gate first;
    auto writer = pool.submit(session, key, AnalysisPriority::normal, blocked(first, 1)).value();
    first.wait();
    auto reader = pool.submit(
        session, key, AnalysisPriority::foreground,
        [](std::stop_token) -> Result<AnalysisPayload> { return payload(2); }, {}, AnalysisWorkKind::read_only);
    check(!reader && reader.error().code == ErrorCode::busy && writer.result.wait_for(0ms) != std::future_status::ready,
          "same-key foreground read cannot cancel a writer-owned analysis");
    first.release();
    check(marker(await(writer)) == 1, "writer analysis still reaches its successful terminal");
    auto read =
        pool.submit(
                session, key, AnalysisPriority::foreground,
                [](std::stop_token) -> Result<AnalysisPayload> { return payload(3); }, {}, AnalysisWorkKind::read_only)
            .value();
    check(marker(await(read)) == 3, "read request can run after writer completion");
    Gate next;
    auto current = key;
    ++current.byte_revision;
    auto fresh = pool.submit(session, current, AnalysisPriority::foreground, blocked(next, 4)).value();
    next.wait();
    auto late = pool.submit(
        session, key, AnalysisPriority::foreground,
        [](std::stop_token) -> Result<AnalysisPayload> { return payload(5); }, {}, AnalysisWorkKind::read_only);
    check(!late && late.error().code == ErrorCode::conflict && fresh.result.wait_for(0ms) != std::future_status::ready,
          "older source arriving after writer scheduling cannot cancel current work");
    next.release();
    check(marker(await(fresh)) == 4, "current source remains publishable after obsolete reader refusal");
    auto other = current;
    other.recipe_fingerprint[0] = std::byte{1};
    check(!pool.submit(session, other, AnalysisPriority::normal,
                       [](std::stop_token) -> Result<AnalysisPayload> { return payload(6); }),
          "same session refuses a different input recipe");
    check(bool(pool.activate({session.document, 2})), "new epoch resets source gate");
    check(bool(await(pool.submit({session.document, 2}, {}, AnalysisPriority::normal,
                                 [](std::stop_token) -> Result<AnalysisPayload> { return payload(7); })
                         .value())),
          "new epoch accepts its independent initial source");
}
} // namespace
int main() {
    return run([] {
        replacement_tests();
        epoch_and_priority_tests();
        capacity_and_shutdown_tests();
        writer_ownership_tests();
    });
}
