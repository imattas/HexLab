#include <hexlab/plugins/sdk.hpp>

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>

namespace {
struct State { const HexLabHostApi* host; };
constexpr HexLabCapability requirements[] = {
    {sizeof(HexLabCapability), 1, 8, 0, "debugger.api"}
};

/* Reusable after this session has a launched or attached target. The process
   inventory action below intentionally does not start or attach to one. */
[[maybe_unused]] int32_t wait_for_next_event(hexlab::plugins::sdk::DebuggerClient& debugger,
                                             std::uint32_t timeout_ms,
                                             HexLabDebugEventText& event) {
    if (!debugger.supports_event_text()) return -1;
    return debugger.wait_event_text(timeout_ms, event);
}

void inspect_processes(void* context) {
    const auto* state = static_cast<const State*>(context);
    if (!state || !state->host) return;
    hexlab::plugins::sdk::DebuggerClient debugger(state->host);
    if (!debugger.available() || debugger.create() != 0) {
        if (state->host->log) state->host->log(state->host->host_context, HEXLAB_LOG_WARNING,
                                               "Debugger process inventory is unavailable.");
        return;
    }
    std::array<HexLabDebugProcess, 32> processes{};
    std::uint32_t written = 0;
    if (debugger.processes(0, static_cast<std::uint32_t>(processes.size()),
                           processes.data(), written) != 0 || written > processes.size()) {
        if (state->host->log) state->host->log(state->host->host_context, HEXLAB_LOG_ERROR,
                                               "Could not query debugger processes.");
        return;
    }
    char message[128]{};
    std::snprintf(message, sizeof(message), "Debugger backend reports %u processes in this page.", written);
    if (state->host->log) state->host->log(state->host->host_context, HEXLAB_LOG_INFO, message);
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    if (!host || !instance ||
        !HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, register_action) || !host->register_action)
        return -1;
    auto* state = new State{host};
    *instance = state;
    if (host->register_action(host->host_context, "debugger-process-inventory",
                              "List Debugger Processes", state, inspect_processes) != 0) {
        delete state;
        *instance = nullptr;
        return -1;
    }
    return 0;
}
void stop(void* instance) { delete static_cast<State*>(instance); }
} // namespace

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    std::uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* plugin_api) {
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) + sizeof(HexLabPluginApi::stop))
        return -1;
    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.debugger-processes-cpp", "Debugger Process Inventory C++ Example",
        "1.0.0", nullptr, 0, start, stop, nullptr, 0, requirements, 1);
    if (available_size < offsetof(HexLabPluginApi, declared_capability_count) +
                         sizeof(HexLabPluginApi::declared_capability_count)) {
        api.declared_capabilities = nullptr;
        api.declared_capability_count = 0;
        api.required_capabilities = nullptr;
        api.required_capability_count = 0;
    }
    if (available_size < offsetof(HexLabPluginApi, required_capability_count) +
                         sizeof(HexLabPluginApi::required_capability_count)) {
        api.required_capabilities = nullptr;
        api.required_capability_count = 0;
    }
    api.struct_size = available_size < sizeof(api) ? available_size : sizeof(api);
    std::memcpy(plugin_api, &api, api.struct_size);
    return 0;
}
