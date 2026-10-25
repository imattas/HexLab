#include "hexlab/workspace/document_manager.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include "support/pe_fixture.hpp"
#include "project_testing.hpp"
#include <chrono>
#include <semaphore>
#include <thread>
using namespace hexlab;
using namespace hexlab_test;
using namespace std::chrono_literals;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
template <class F> void until(DocumentManager &manager, F condition) {
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!condition()) {
        take(manager.poll());
        if (std::chrono::steady_clock::now() > deadline)
            throw std::runtime_error("Document manager did not reach expected state");
        std::this_thread::sleep_for(2ms);
    }
}
OpenRequest raw(const std::filesystem::path &path, uint64_t base) {
    OpenRequest request;
    request.path = path;
    request.format = Format::raw;
    request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, base}, true, false, true, {}};
    return request;
}
void isolation_tests() {
    FixtureFile first(bytes({0x90, 0xc3})), second(bytes({0xcc, 0xc3}));
    auto pool = std::make_shared<AnalysisPool>();
    auto manager = take(DocumentManager::create(pool));
    auto a = take(manager->import_binary(raw(first.path, 0x1000)));
    until(*manager, [&] { return manager->project(a) && !manager->active_workspace().opening(); });
    check(manager->active_document() == a && manager->active_workspace().selection() == Location{Address{{0}, 0x1000}},
          "first project owns initial navigation");
    take(manager->active_workspace().navigate(Address{{0}, 0x1001}));
    auto b = take(manager->import_binary(raw(second.path, 0x2000)));
    until(*manager, [&] { return manager->active_document() == b && !manager->active_workspace().opening(); });
    check(manager->documents().size() == 2 && manager->active_workspace().selection() == Location{Address{{0}, 0x2000}},
          "second project gets isolated active selection");
    take(manager->active_workspace().navigate(FileOffset{1}));
    take(manager->activate(a));
    check(manager->active_workspace().selection() == Location{Address{{0}, 0x1001}},
          "tab switch restores first project selection");
    take(manager->active_workspace().back());
    check(manager->active_workspace().selection() == Location{Address{{0}, 0x1000}},
          "first project navigation history survives another tab");
    take(manager->activate(b));
    check(manager->active_workspace().selection() == Location{FileOffset{1}}, "second project retains its own history");
    auto actor = manager->actor(a);
    auto operation = take(manager->watch(a, actor->execute(Comment{FileOffset{0}, "background edit"})));
    (void)operation;
    until(*manager, [&] { return manager->project(a)->state->revisions.edit == 1; });
    check(manager->project(b)->state->revisions.edit == 0 && manager->active_document() == b &&
              manager->active_workspace().selection() == Location{FileOffset{1}},
          "inactive project completion cannot mutate active document or selection");
    take(manager->close(a));
    check(manager->documents().size() == 1 && manager->active_document() == b && !manager->project(a),
          "closing inactive project preserves active tab");
    auto c = take(manager->import_binary(raw(first.path, 0x3000)));
    until(*manager, [&] { return manager->active_document() == c && bool(manager->project(c)); });
    take(manager->active_workspace().navigate(FileOffset{1}));
    take(manager->close(c));
    check(manager->active_document() == b && manager->active_workspace().selection() == Location{FileOffset{1}},
          "closing active project restores the remaining tab and its navigation state");
    take(manager->close(b));
    check(!manager->active_document() && !manager->active_workspace().current(),
          "closing final document clears active projection");
}
void identity_tests() {
    using namespace hexlab::database;
    FixtureFile marker(std::span<const std::byte>{});
    auto path = marker.path.wstring() + L".manager.hxproj";
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ignored;
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto file = path;
                file += suffix;
                std::filesystem::remove(file, ignored);
            }
        }
    } cleanup{path};
    {
        auto store = take(ProjectStore::create(path, {}));
        MemoryStorage data(bytes({0x90, 0xc3}));
        take(store->import_input(
            data,
            {Format::raw,
             RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}}},
            {}, {}));
    }
    auto pool = std::make_shared<AnalysisPool>();
    auto manager = take(DocumentManager::create(pool));
    auto first = take(manager->open_project(path, ProjectMode::read_write));
    until(*manager, [&] { return manager->project(first) && !manager->active_workspace().opening(); });
    auto duplicate = take(manager->open_project(path, ProjectMode::read_only));
    until(*manager, [&] { return !manager->actor(duplicate); });
    check(manager->documents().size() == 1 && manager->active_document() == first,
          "duplicate project UUID activates existing document");
    auto external = take(DocumentManager::create(pool));
    auto other = take(external->open_project(path, ProjectMode::read_write));
    until(*external, [&] { return bool(external->project(other)); });
    check(external->project(other)->mode == ProjectMode::read_only,
          "external editable ownership opens visibly read-only");
    take(external->close(other));
    auto missing = take(manager->open_project(path + L".missing", ProjectMode::read_write));
    take(manager->activate(missing));
    until(*manager, [&] { return !manager->actor(missing); });
    check(manager->active_document() == first && manager->active_workspace().current() &&
              manager->active_workspace().last_error(),
          "failed selected opening tab restores existing project and diagnostic");
}
struct GateState {
    std::promise<bool> entered;
    std::binary_semaphore release{0};
    std::atomic<bool> opened = false, claimed = false;
};
struct Gate {
    std::shared_ptr<GateState> state = std::make_shared<GateState>();
    std::future<bool> entered = state->entered.get_future();
    void open() {
        if (!state->opened.exchange(true))
            state->release.release();
    }
    void wait() {
        if (entered.wait_for(3s) != std::future_status::ready)
            throw std::runtime_error("Manager barrier not reached");
        entered.get();
    }
    ~Gate() { open(); }
};
void lifetime_tests() {
    auto pool = std::make_shared<AnalysisPool>();
    Gate first, second, late;
    for (auto pair : {std::pair{SessionKey{{UINT64_MAX - 1}, 1}, first.state},
                      std::pair{SessionKey{{UINT64_MAX - 2}, 1}, second.state}}) {
        take(pool->activate(pair.first));
        take(pool->submit(pair.first, {}, AnalysisPriority::foreground,
                          [state = pair.second](std::stop_token) -> Result<AnalysisPayload> {
                              state->entered.set_value(true);
                              state->release.acquire();
                              return Error{ErrorCode::canceled, "Fixture worker released"};
                          }));
    }
    first.wait();
    second.wait();
    FixtureFile input(bytes({0x90, 0xc3}));
    auto manager = take(DocumentManager::create(pool));
    auto a = take(manager->import_binary(raw(input.path, 0x1000)));
    until(*manager, [&] { return bool(manager->project(a)); });
    auto key = manager->actor(a)->view().session;
    struct Clear {
        SessionKey key;
        ~Clear() { workspace_testing::clear_actor_hook(key); }
    } clear{key};
    auto state = late.state;
    workspace_testing::set_actor_hook(key, [state](const workspace_testing::ActorCheckpoint &point) {
        if (point.phase == workspace_testing::ActorPhase::analysis_computed && !state->claimed.exchange(true)) {
            state->entered.set_value(true);
            state->release.acquire();
        }
    });
    first.open();
    late.wait();
    take(manager->close(a));
    check(!manager->active_document() && !manager->active_workspace().current(),
          "closing tab drops projection while old job still holds its input");
    auto b = take(manager->import_binary(raw(input.path, 0x2000)));
    until(*manager, [&] { return manager->active_document() == b && bool(manager->project(b)); });
    late.open();
    second.open();
    until(*manager, [&] { return !manager->active_workspace().opening(); });
    check(manager->documents().size() == 1 && manager->active_document() == b &&
              manager->active_workspace().selection() == Location{Address{{0}, 0x2000}},
          "late closed-document completion cannot replace reopened active tab");
    auto failed = take(manager->import_binary(raw(L"missing-manager-binary.bin", 0x3000)));
    manager->cancel_open();
    check(!manager->actor(failed) && manager->active_document() == b && !manager->active_workspace().opening(),
          "canceling queued import retains current tab immediately");
}
void mapping_history_tests() {
    FixtureFile file(pe_fixture());
    auto pool = std::make_shared<AnalysisPool>();
    auto manager = take(DocumentManager::create(pool));
    OpenRequest request;
    request.path = file.path;
    auto id = take(manager->import_binary(request));
    until(*manager, [&] { return manager->project(id) && !manager->active_workspace().opening(); });
    take(manager->active_workspace().navigate(FileOffset{0x200}));
    take(manager->watch(id, manager->actor(id)->execute(PatchBytes{FileOffset{0}, bytes({0})})));
    until(*manager, [&] { return manager->project(id)->status == DerivedStatus::file_only; });
    check(!manager->active_workspace().back() && manager->active_workspace().selection() == Location{FileOffset{0x200}},
          "mapping invalidation removes unbacked address history while preserving selected file bytes");
}
} // namespace
int main() {
    return run([] {
        isolation_tests();
        identity_tests();
        lifetime_tests();
        mapping_history_tests();
    });
}
