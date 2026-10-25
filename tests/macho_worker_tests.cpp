#include "hexlab/workspace/project_actor.hpp"
#include "project_testing.hpp"
#include "support/macho_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
#include <chrono>
#include <semaphore>
#include <thread>
using namespace hexlab;
using namespace hexlab_test;
using namespace std::chrono_literals;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
struct GateState {
    std::promise<bool> entered;
    std::binary_semaphore released{0};
    std::atomic<bool> claimed = false, opened = false;
};
struct Gate {
    std::shared_ptr<GateState> state = std::make_shared<GateState>();
    std::future<bool> entered = state->entered.get_future();
    ~Gate() { release(); }
    void release() {
        if (!state->opened.exchange(true))
            state->released.release();
    }
    bool wait() {
        if (entered.wait_for(3s) != std::future_status::ready)
            throw std::runtime_error("Mach-O worker barrier was not reached");
        return entered.get();
    }
};
struct HookGuard {
    SessionKey key;
    ~HookGuard() { workspace_testing::clear_actor_hook(key); }
};
Result<ProjectReply> await(const ProjectSubmission &submission) {
    if (submission.result.wait_for(5s) != std::future_status::ready)
        throw std::runtime_error("Mach-O worker operation did not terminate");
    return submission.result.get();
}
ProjectReply reply(Result<ProjectSubmission> submission) { return take(await(take(std::move(submission)))); }
void cancellation_and_selection() {
    FixtureFile input(macho_fixture::mapped_fat());
    const SessionKey key{{991}, 1};
    HookGuard hooks{key};
    auto pool = std::make_shared<AnalysisPool>();
    auto actor = take(ProjectActor::create(key, pool));
    Gate gate;
    const auto state = gate.state;
    const auto caller = std::this_thread::get_id();
    workspace_testing::set_actor_hook(key, [state, caller](const auto &point) {
        if (point.phase == workspace_testing::ActorPhase::before_open && !state->claimed.exchange(true)) {
            state->entered.set_value(std::this_thread::get_id() != caller);
            state->released.acquire();
        }
    });
    OpenRequest request;
    request.path = input.path;
    request.macho = MachOOptions{0};
    request.run_analysis = false;
    auto canceled = take(actor->import_binary(request));
    check(gate.wait(), "Mach-O opening and selection run on the worker rather than the submitting thread");
    check(actor->cancel_operation(canceled.id), "held Mach-O import accepts cancellation");
    gate.release();
    const auto terminal = await(canceled);
    check(!terminal && terminal.error().code == ErrorCode::canceled && !actor->view().snapshot,
          "canceled slice opening cannot publish a partial project");
    workspace_testing::clear_actor_hook(key);
    const auto imported = reply(actor->import_binary(request));
    request.macho = MachOOptions{1};
    check(imported.snapshot->loaded->metadata.macho->selected_slice == 0 &&
              imported.snapshot->state->recipe.macho->slice_index == 0 && !imported.snapshot->functions,
          "actor import persists explicit nondefault slice and honors metadata-only opening");
    check(std::filesystem::remove(input.path), "owned universal input removed after worker embedding");
    const auto ready = reply(actor->ready(true));
    check(ready.snapshot->loaded->metadata.macho->selected_slice == 0 && ready.snapshot->functions &&
              ready.snapshot->loaded->image->decode_context().mode == ExecutionMode::x86_32,
          "worker reanalysis uses the embedded selected slice after external source removal");
    check(reply(actor->close()).closed, "Mach-O import actor retires its SQL owner");
}
void stale_kind_completion() {
    auto bytes = macho_fixture::mapped_fat();
    const auto thin = macho_fixture::mapped(true);
    std::copy(thin.begin(), thin.end(), bytes.begin());
    FixtureFile input(bytes);
    const SessionKey key{{992}, 1};
    HookGuard hooks{key};
    auto pool = std::make_shared<AnalysisPool>();
    auto actor = take(ProjectActor::create(key, pool));
    Gate gate;
    const auto state = gate.state;
    workspace_testing::set_actor_hook(key, [state](const auto &point) {
        if (point.phase == workspace_testing::ActorPhase::analysis_computed && point.source &&
            point.source->byte_revision == 0 && !state->claimed.exchange(true)) {
            state->entered.set_value(true);
            state->released.acquire();
        }
    });
    OpenRequest request;
    request.path = input.path;
    const auto imported = reply(actor->import_binary(request));
    check(gate.wait(), "initial Mach-O analysis is held after computation");
    const auto old_ready = take(actor->ready());
    auto header = macho_fixture::mapped_fat();
    header.resize(48);
    const auto changed = reply(actor->execute(PatchBytes{FileOffset{0}, header}));
    check(!changed.snapshot->loaded && changed.snapshot->status == DerivedStatus::file_only,
          "worker source-kind patch removes the mapping before old analysis can publish");
    gate.release();
    const auto obsolete = await(old_ready);
    check(!obsolete && obsolete.error().code == ErrorCode::canceled,
          "obsolete Mach-O readiness reaches a canceled terminal state");
    const auto current = reply(actor->ready());
    check(current.snapshot->status == DerivedStatus::file_only && !current.snapshot->loaded &&
              !current.snapshot->state->recipe.macho && current.snapshot->state->uuid == imported.snapshot->state->uuid,
          "late completion cannot restore an invalid container or change the saved selection/UUID");
    const auto restored = reply(actor->undo());
    const auto ready = reply(actor->ready());
    check(restored.snapshot->loaded && ready.snapshot->loaded &&
              !ready.snapshot->loaded->metadata.macho->container.universal,
          "undo after rejected stale completion rebuilds the original thin source");
    check(reply(actor->close()).closed, "stale-completion actor closes without a live SQL owner");
}
} // namespace
int main() {
    return run([] {
        cancellation_and_selection();
        stale_kind_completion();
    });
}
