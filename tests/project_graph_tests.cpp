#include "hexlab/workspace/project_graph.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
struct Fixture {
    FixtureFile file{std::span<const std::byte>{}};
    std::filesystem::path path = file.path.wstring() + L".graph-view.hxproj";
    std::shared_ptr<ProjectStore> store;
    std::shared_ptr<ProjectSession> session;
    Fixture(std::vector<std::byte> bytes, bool executable = true) {
        store = take(ProjectStore::create(path, {}));
        MemoryStorage input(std::move(bytes));
        take(store->import_input(
            input,
            {Format::raw,
             RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, executable, {}}},
            {}, {}));
        session = take(ProjectSession::attach(store, {}, {}));
    }
    ~Fixture() {
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto item = path;
            item += suffix;
            std::filesystem::remove(item, ignored);
        }
    }

};

void graph_tests() {
    Fixture f(bytes({0x74, 3, 0x90, 0xeb, 1, 0x90, 0xc3}));
    auto initial = f.session->snapshot();
    auto graph = take(make_project_graph(*initial, GraphKind::function_cfg, Location{Address{{0}, 0x1005}}, {}, {}));
    check(graph.model->nodes.size() == 4 && graph.model->edges.size() == 4,
          "literal four-block diamond is the actual project graph");
    check(graph.model->source_key == initial->derived_key && graph.layout->model_key == graph.model->key,
          "graph and geometry share the exact source and model identity");
    Fixture calls(bytes({0xe8,3,0,0,0,0xc3,0x90,0x90,0xc3}));
    auto neighborhood=take(make_project_graph(*calls.session->snapshot(),GraphKind::function_calls,
                                              Location{Address{{0},0x1000}},{},{}));
    check(neighborhood.model->function && neighborhood.model->nodes.size()==2 && neighborhood.model->edges.size()==1 &&
              neighborhood.model->kind==GraphKind::function_calls,
          "project graph resolves the current selection to a function-centered caller/callee neighborhood");
    auto function = graph.model->function;
    take(f.session->execute(Rename{Address{{0}, 0x1005}, "chosen_block"}, 0, {}));
    take(f.session->execute(Comment{Address{{0}, 0x1005}, "line one\nline two"}, 0, {}));
    auto renamed = f.session->snapshot();
    auto labeled = take(make_project_graph(*renamed, GraphKind::function_cfg, Location{Address{{0}, 0x1005}}, {}, {}));
    bool found = false;
    for (auto &node : labeled.model->nodes)
        if (node.selection == Location{Address{{0}, 0x1005}})
            found = node.label == "chosen_block" && node.comment == "line one\nline two";
    check(found && labeled.model->function == function && labeled.model->presentation_revision == 2,
          "committed annotations reach the selected block without changing its owning function");
    check(labeled.model->source_key == graph.model->source_key && labeled.layout->model_key != graph.layout->model_key,
          "annotation-only reflow changes geometry identity while preserving analysis source");
    check(project_graph_current(*renamed, labeled) && !project_graph_current(*renamed, graph),
          "presentation revision rejects an old layout even when its analysis key matches");
    take(f.session->execute(PatchBytes{FileOffset{0}, bytes({0xeb})}, 0, {}));
    check(!make_project_graph(*f.session->snapshot(), GraphKind::function_cfg, Location{Address{{0}, 0x1005}}, {}, {}),
          "stale project facts cannot be relabeled as current graphs");
    take(f.session->refresh_analysis({}));
    auto patched = f.session->snapshot();
    auto changed = take(make_project_graph(*patched, GraphKind::function_cfg, Location{Address{{0}, 0x1005}}, {}, {}));
    check(changed.model->nodes.size() == 2 && changed.model->edges.size() == 1 &&
              !project_graph_current(*patched, labeled),
          "literal unconditional patch removes unreachable diamond branch and retires prior geometry");
    GraphOptions small;
    small.node_budget = 1;
    auto partial =
        take(make_project_graph(*initial, GraphKind::function_cfg, Location{Address{{0}, 0x1000}}, small, {}));
    check(!partial.model->complete && partial.model->omitted_nodes > 0,
          "budget-limited graph reports partial topology");
    std::stop_source cancel;
    cancel.request_stop();
    auto stopped = make_project_graph(*initial, GraphKind::image_calls, {}, {}, cancel.get_token());
    check(!stopped && stopped.error().code == ErrorCode::canceled,
          "project graph observes cancellation before presentation construction");
    check(!make_project_graph(*initial, GraphKind::function_cfg, Location{FileOffset{0}}, {}, {}),
          "file offsets are not silently invented as virtual graph selections");
}
} // namespace
int main() {
    return run([] { graph_tests(); });
}
