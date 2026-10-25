#include "hexlab/workspace/open_recipe.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/loaders/x86_raw_profile.hpp"
#include "project_testing.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <chrono>
#include <fstream>
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
const std::string profile_text = "hexlab-x86-profile 1\nenvironment real386\na20 enabled\nload 0x10000\n"
                                 "entry 7 0\nstack none\ndomains 1\ndomain 7 0x1000 code \"code\" real\n";
void contracts() {
    FixtureFile input(bytes({0x90, 0xc3})), profile(std::as_bytes(std::span(profile_text)));
    OpenRequest request;
    request.path = input.path;
    request.format = Format::raw;
    request.x86_profile_path = profile.path;
    auto recipe = take(resolve_open_recipe(request, {}));
    check(recipe.raw && recipe.raw->x86_profile && recipe.raw->mode == ExecutionMode::x86_16 &&
              recipe.raw->entry == Address{{7}, 0},
          "worker recipe resolution reads a bounded explicit profile");
    auto doc = take(load_document(request, {{1}, 1}, {}));
    check(doc->analysis && doc->analysis->instructions.size() == 2 &&
              doc->image->decode_context().mode == ExecutionMode::x86_16,
          "inspection document worker shares profile resolution and original16 decoding");
    auto changed = request;
    changed.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0}, true, false, true, {}};
    check(!resolve_open_recipe(changed, {}), "flat options and external profile cannot conflict silently");
    changed = request;
    changed.format = Format::pe;
    check(!resolve_open_recipe(changed, {}), "profile option is valid only for explicit raw input");
    changed.format = Format::automatic;
    check(!resolve_open_recipe(changed, {}), "automatic detection cannot consume a raw profile");
    changed = request;
    changed.x86_profile_path.reset();
    check(!resolve_open_recipe(changed, {}), "raw input still requires explicit mapping intent");
    changed.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}};
    check(take(encode_recipe(take(resolve_open_recipe(changed, {})))) ==
              take(encode_recipe({Format::raw, changed.raw})),
          "old flat recipe bytes survive shared resolution");
    changed = request;
    changed.x86_profile_path = std::filesystem::path{};
    check(!resolve_open_recipe(changed, {}), "empty external profile path is rejected");
    changed.x86_profile_path = std::filesystem::path(std::wstring(L"bad\0profile", 11));
    check(!resolve_open_recipe(changed, {}), "embedded NUL cannot truncate an external profile path");
    std::stop_source stop;
    stop.request_stop();
    changed = request;
    changed.x86_profile_path = profile.path.wstring() + L".missing";
    auto canceled = resolve_open_recipe(changed, stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled,
          "canceled profile resolution stops before any file opening");
}
struct Gate {
    std::promise<bool> entered;
    std::binary_semaphore released{0};
    std::atomic<bool> claimed = false, opened = false;
    void release() {
        if (!opened.exchange(true))
            released.release();
    }
};
struct HookGuard {
    SessionKey key;
    ~HookGuard() { workspace_testing::clear_actor_hook(key); }
};
Result<ProjectReply> await(const ProjectSubmission &work) {
    if (work.result.wait_for(5s) != std::future_status::ready)
        throw std::runtime_error("Profile import operation did not terminate");
    return work.result.get();
}
void worker_import() {
    FixtureFile input(bytes({0x90, 0xc3})), profile(bytes({0}));
    OpenRequest request;
    request.path = input.path;
    request.format = Format::raw;
    request.x86_profile_path = profile.path;
    auto gate = std::make_shared<Gate>();
    auto entered = gate->entered.get_future();
    const auto caller = std::this_thread::get_id();
    SessionKey key{{91}, 1};
    HookGuard hook{key};
    workspace_testing::set_actor_hook(key, [gate, caller](const auto &checkpoint) {
        if (checkpoint.phase == workspace_testing::ActorPhase::before_open && !gate->claimed.exchange(true)) {
            gate->entered.set_value(std::this_thread::get_id() != caller);
            gate->released.acquire();
        }
    });
    auto pool = std::make_shared<AnalysisPool>();
    auto actor = take(ProjectActor::create(key, pool));
    struct Release {
        std::shared_ptr<Gate> gate;
        ~Release() { gate->release(); }
    } release{gate};
    auto imported = take(actor->import_binary(request));
    if (entered.wait_for(3s) != std::future_status::ready)
        throw std::runtime_error("Profile import barrier was not reached");
    check(entered.get(), "profile import executes on the actor rather than the requesting thread");
    // Submission happened while this file was invalid. Only the worker reads
    // its contents, after this barrier, and then embeds the complete profile.
    {
        std::ofstream file(profile.path, std::ios::binary | std::ios::trunc);
        file << profile_text;
        if (!file)
            throw std::runtime_error("Cannot write owned profile fixture");
    }
    gate->release();
    auto accepted = take(await(imported));
    check(accepted.snapshot && accepted.snapshot->state->recipe.raw->x86_profile,
          "deferred worker parsing embeds the profile instead of retaining a live external mapping");
    check(std::filesystem::remove(profile.path) && std::filesystem::remove(input.path),
          "external input and profile can disappear after actor import");
    auto ready = take(await(take(actor->ready()))).snapshot;
    check(ready->functions && ready->functions->instructions.size() == 2 &&
              ready->loaded->image->decode_context().mode == ExecutionMode::x86_16,
          "analysis continues from embedded16 profile after both external files disappear");
    check(take(await(take(actor->close()))).closed, "profile import actor closes its SQL owner cleanly");
}
void cancel_and_retry() {
    const std::string bad_text = "hexlab-x86-profile 99\n";
    FixtureFile input(bytes({0x90, 0xc3})), bad(std::as_bytes(std::span(bad_text))),
        profile(std::as_bytes(std::span(profile_text)));
    auto pool = std::make_shared<AnalysisPool>();
    SessionKey key{{92}, 1};
    HookGuard hook{key};
    auto actor = take(ProjectActor::create(key, pool));
    OpenRequest request;
    request.path = input.path;
    request.format = Format::raw;
    request.x86_profile_path = bad.path;
    auto rejected = await(take(actor->import_binary(request)));
    check(!rejected && rejected.error().code == ErrorCode::unsupported && !actor->view().snapshot,
          "malformed profile import leaves no partially adopted project");
    auto gate = std::make_shared<Gate>();
    auto entered = gate->entered.get_future();
    struct Release {
        std::shared_ptr<Gate> gate;
        ~Release() { gate->release(); }
    } release{gate};
    workspace_testing::set_actor_hook(key, [gate](const auto &checkpoint) {
        if (checkpoint.phase == workspace_testing::ActorPhase::before_open && !gate->claimed.exchange(true)) {
            gate->entered.set_value(true);
            gate->released.acquire();
        }
    });
    request.x86_profile_path = profile.path;
    auto canceled = take(actor->import_binary(request));
    if (entered.wait_for(3s) != std::future_status::ready)
        throw std::runtime_error("Cancelable profile import did not reach its barrier");
    check(entered.get() && actor->cancel_operation(canceled.id), "live profile import accepts explicit cancellation");
    gate->release();
    auto terminal = await(canceled);
    check(!terminal && terminal.error().code == ErrorCode::canceled && !actor->view().snapshot,
          "canceled profile import terminates without publishing stale mappings");
    workspace_testing::clear_actor_hook(key);
    auto retry = take(await(take(actor->import_binary(request))));
    auto ready = take(await(take(actor->ready()))).snapshot;
    check(retry.snapshot && ready->functions && ready->functions->instructions.size() == 2 &&
              ready->loaded->image->decode_context().mode == ExecutionMode::x86_16,
          "same actor can import valid profile after rejected and canceled attempts");
    check(take(await(take(actor->close()))).closed, "retried profile actor closes cleanly");
}
void pe_pdb_discovery() {
    FixtureFile input(pe_codeview_fixture());
    const auto directory = input.path.parent_path() / (input.path.filename().string() + ".pdb-search");
    std::filesystem::create_directory(directory);
    const auto sidecar = directory / "sample.pdb";
    { std::ofstream output(sidecar, std::ios::binary); output.put('\0'); }
    OpenRequest request; request.path = input.path; request.format = Format::pe;
    request.pdb_search_paths.push_back(directory);
    auto recipe = take(resolve_open_recipe(request, {}));
    check(recipe.pdb_path == std::filesystem::absolute(sidecar).lexically_normal(),
          "PE opener discovers RSDS basename from an explicitly configured local directory");
    const auto encoded = take(encode_recipe(recipe));
    check(take(decode_recipe(encoded)).pdb_path == recipe.pdb_path,
          "discovered PDB path is durable in the project recipe");
    std::error_code ignored; std::filesystem::remove(sidecar, ignored); std::filesystem::remove(directory, ignored);
}
} // namespace
int main() {
    return run([] {
        contracts();
        worker_import();
        cancel_and_retry();
        pe_pdb_discovery();
    });
}
