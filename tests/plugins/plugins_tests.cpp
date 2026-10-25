#include "hexlab/plugins/plugins.hpp"
#include "support/checks.hpp"

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace hexlab::plugins;

namespace {
struct FakePlugin {
    static inline int starts = 0;
    static inline int stops = 0;
    static inline bool wrong_abi = false;
    static inline bool legacy_layout = false;
    static inline bool fail_start = false;
    static inline bool leave_instance_null = false;
    static inline bool start_received_null = false;
    static inline int action_calls = 0;
    static inline void* last_stopped_instance = nullptr;
    static void invoke(void*) { ++action_calls; }
    static int32_t start(const HexLabHostApi* host, void** instance) {
        ++starts;
        start_received_null = instance && *instance == nullptr;
        *instance = leave_instance_null ? nullptr : reinterpret_cast<void*>(std::uintptr_t{0x1234});
        if (host->log) host->log(host->host_context, HEXLAB_LOG_INFO, "started");
        if (fail_start) return -1;
        if (host->register_action && host->register_action(host->host_context, "test.run", "Run test", nullptr, invoke) != 0)
            return -1;
        return 0;
    }
    static void stop(void* instance) { ++stops; last_stopped_instance = instance; }
    static int32_t query(uint32_t requested, const HexLabHostApi*, HexLabPluginApi* api) {
        api->struct_size = sizeof(*api);
        api->abi_major = wrong_abi ? requested + 1 : requested;
        api->abi_minor = 0;
        api->plugin_id = "test.plugin";
        api->name = "Test Plugin";
        api->version = "1.2.3";
        static const char* caps[] = {"analysis.action", "ui.panel"};
        static const HexLabCapability versioned_caps[] = {
            {sizeof(HexLabCapability), 1, 2, 0, "analysis.project"}
        };
        api->capabilities = caps;
        api->capability_count = 2;
        api->start = start;
        api->stop = stop;
        api->declared_capabilities = versioned_caps;
        api->declared_capability_count = 1;
        if (legacy_layout) api->struct_size = static_cast<std::uint32_t>(offsetof(HexLabPluginApi, declared_capabilities));
        return 0;
    }
};

class FakeModules final : public ModuleProvider {
public:
    bool fail_load = false;
    int opens = 0;
    int closes = 0;
    hexlab::Result<Module> open(const std::string&) override {
        ++opens;
        if (fail_load) return hexlab::Error{hexlab::ErrorCode::io, "open failed"};
        return Module{this, &lookup, &close};
    }
private:
    static void* lookup(void*, const char* name) {
        if (std::strcmp(name, "hexlab_plugin_query") == 0)
            return reinterpret_cast<void*>(&FakePlugin::query);
        return nullptr;
    }
    static void close(void* handle) { ++static_cast<FakeModules*>(handle)->closes; }
};

void run_tests() {
    FakePlugin::starts = FakePlugin::stops = FakePlugin::action_calls = 0;
    FakePlugin::wrong_abi = false;
    FakePlugin::fail_start = false;
    FakePlugin::leave_instance_null = false;
    FakePlugin::start_received_null = false;
    FakePlugin::last_stopped_instance = nullptr;
    auto modules = std::make_shared<FakeModules>();
    PluginManager manager(modules);
    auto loaded = manager.load("test-plugin.dll");
    hexlab_test::check(loaded && loaded.value().id == "test.plugin", "loads and copies plugin metadata");
    hexlab_test::check(loaded && loaded.value().capabilities.size() == 2, "copies capability declarations");
    hexlab_test::check(loaded && loaded.value().declared_capabilities.size() == 1 &&
                           loaded.value().declared_capabilities[0].id == "analysis.project" &&
                           loaded.value().declared_capabilities[0].major_version == 1 &&
                           loaded.value().declared_capabilities[0].minor_version == 2,
                       "copies independently versioned capability declarations");
    hexlab_test::check(manager.supports_capability("test.plugin", "analysis.project", 1, 1) &&
                           !manager.supports_capability("test.plugin", "analysis.project", 2, 0) &&
                           !manager.supports_capability("test.plugin", "analysis.project", 1, 3),
                       "matches declared capability major and minimum minor versions at runtime");
    hexlab_test::check(FakePlugin::starts == 1, "starts plugin with host API");
    const auto actions = manager.actions();
    hexlab_test::check(actions.size() == 1 && actions[0].plugin_id == "test.plugin" &&
                           actions[0].id == "test.run" && actions[0].label == "Run test",
                       "retains registered plugin action metadata");
    hexlab_test::check(static_cast<bool>(manager.invoke_action("test.plugin", "test.run")) &&
                           FakePlugin::action_calls == 1,
                       "invokes a registered plugin action");
    hexlab_test::check(!manager.invoke_action("test.plugin", "missing") &&
                           !manager.invoke_action("missing", "test.run"),
                       "rejects unknown plugin or action IDs");
    hexlab_test::check(!manager.load("test-plugin.dll"), "rejects duplicate plugin IDs");
    hexlab_test::check(static_cast<bool>(manager.unload("test.plugin")), "unloads plugin by ID");
    hexlab_test::check(manager.actions().empty() && !manager.invoke_action("test.plugin", "test.run"),
                       "removes actions before unloading their module");
    hexlab_test::check(FakePlugin::stops == 1 && modules->closes == 2, "stops before closing module and closes duplicate candidate");

    FakePlugin::legacy_layout = true;
    auto legacy = manager.load("abi-1.3-plugin.dll");
    hexlab_test::check(legacy && legacy.value().declared_capabilities.empty(),
                       "loads an older descriptor layout without reading appended capability fields");
    hexlab_test::check(!manager.supports_capability("test.plugin", "analysis.project", 1),
                       "does not infer versioned support from legacy string capabilities");
    if (legacy) manager.unload("test.plugin");
    FakePlugin::legacy_layout = false;

    FakePlugin::fail_start = true;
    const auto stop_count = FakePlugin::stops;
    const auto close_count = modules->closes;
    hexlab_test::check(!manager.load("failed-start.dll"), "reports plugin initialization failure");
    hexlab_test::check(FakePlugin::stops == stop_count + 1 &&
                           FakePlugin::last_stopped_instance == reinterpret_cast<void*>(std::uintptr_t{0x1234}) &&
                           modules->closes == close_count + 1 && FakePlugin::start_received_null,
                       "calls stop with the partially initialized instance and closes failed module");
    FakePlugin::leave_instance_null = true;
    const auto null_cleanup_stop_count = FakePlugin::stops;
    hexlab_test::check(!manager.load("failed-start-null.dll") &&
                           FakePlugin::stops == null_cleanup_stop_count + 1 &&
                           FakePlugin::last_stopped_instance == nullptr,
                       "calls stop with null when failed start leaves the initialized output untouched");
    FakePlugin::leave_instance_null = false;
    FakePlugin::fail_start = false;

    FakePlugin::wrong_abi = true;
    const auto start_count = FakePlugin::starts;
    const auto invalid_abi_close_count = modules->closes;
    hexlab_test::check(!manager.load("bad-abi.dll"), "rejects incompatible ABI");
    hexlab_test::check(FakePlugin::starts == start_count && modules->closes == invalid_abi_close_count + 1,
                       "invalid plugin is never started and module closes");
    FakePlugin::wrong_abi = false;
    modules->fail_load = true;
    hexlab_test::check(!manager.load("missing.dll"), "reports module open failure");
    hexlab_test::check(manager.plugins().empty(), "failed loads leave no registered plugin");
}
}

int main() {
    return hexlab_test::run(run_tests);
}
