#include <hexlab/plugins/sdk.hpp>

#include <cstddef>
#include <cstring>

namespace {
struct PluginState {
    const HexLabHostApi* host;
};

void hello(void* context) {
    const auto* state = static_cast<const PluginState*>(context);
    if (state && state->host && state->host->log)
        state->host->log(state->host->host_context, 1, "Hello from a native C++ plugin.");
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    constexpr auto required = offsetof(HexLabHostApi, register_action) +
                              sizeof(HexLabHostApi::register_action);
    if (!host || !instance || host->struct_size < required || !host->register_action)
        return -1;

    auto* state = new PluginState{host};
    *instance = state;
    if (host->register_action(host->host_context, "hello-cpp", "Hello C++ Plugin",
                              state, hello) != 0) {
        delete state;
        *instance = nullptr;
        return -1;
    }
    if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, register_menu_action) &&
        host->register_menu_action &&
        host->register_menu_action(host->host_context, "Examples/Native SDK",
                                   "hello-cpp-menu", "Hello from menu", state, hello) != 0) {
        delete state;
        *instance = nullptr;
        return -1;
    }
    return 0;
}

void stop(void* instance) {
    delete static_cast<PluginState*>(instance);
}
} // namespace

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    uint32_t host_abi_major, const HexLabHostApi* host, HexLabPluginApi* plugin_api) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) +
                                  sizeof(HexLabPluginApi::stop))
        return -1;

    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.hello-cpp", "Hello C++ Plugin", "1.0.0",
        nullptr, 0, start, stop);
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
