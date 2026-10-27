#include <hexlab/plugins/sdk.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

namespace {
struct PluginState {
    const HexLabHostApi* host;
};

void report(const PluginState* state, int32_t level, const std::string& message) {
    if (!state || !state->host) return;
    constexpr auto required = offsetof(HexLabHostApi, log) + sizeof(HexLabHostApi::log);
    if (state->host->struct_size >= required && state->host->log)
        state->host->log(state->host->host_context, level, message.c_str());
}

void inspect_active_document(void* context) {
    const auto* state = static_cast<const PluginState*>(context);
    if (!state) return;

    hexlab::plugins::sdk::ActiveDocumentClient client(state->host);
    if (!client.available()) {
        report(state, 2, "The host does not provide the active-document API.");
        return;
    }

    HexLabActiveDocumentInfo info{};
    const auto query_status = client.query(info);
    if (query_status != HEXLAB_ACTIVE_DOCUMENT_OK) {
        report(state, 2, "No active document is available (or its snapshot changed).");
        return;
    }

    const auto count = static_cast<std::uint32_t>(std::min<std::uint64_t>(info.file_size, 16));
    if (!count) {
        report(state, 1, "The active document has an empty file view.");
        return;
    }

    HexLabProjectLocation location{};
    location.struct_size = sizeof(location);
    location.kind = HEXLAB_PROJECT_LOCATION_FILE;
    location.offset = 0;
    std::array<std::uint8_t, 16> bytes{};
    const auto read_status = client.read(info.token, location, count, bytes.data());
    if (read_status != HEXLAB_ACTIVE_DOCUMENT_OK) {
        report(state, 2, read_status == HEXLAB_ACTIVE_DOCUMENT_STALE
            ? "The active document changed during the read; invoke the action again."
            : "The active document prefix could not be read.");
        return;
    }

    std::ostringstream message;
    message << "Effective file prefix (" << count << " bytes):";
    for (std::uint32_t i = 0; i < count; ++i)
        message << ' ' << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(bytes[i]);
    report(state, 1, message.str());
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    constexpr auto required = offsetof(HexLabHostApi, register_action) +
                              sizeof(HexLabHostApi::register_action);
    if (!host || !instance || host->struct_size < required || !host->register_action)
        return -1;

    auto* state = new PluginState{host};
    *instance = state;
    if (host->register_action(host->host_context, "inspect-active-file-prefix",
                              "Inspect Active File Prefix", state,
                              inspect_active_document) != 0) {
        delete state;
        *instance = nullptr;
        return -1;
    }
    return 0;
}

void stop(void* instance) { delete static_cast<PluginState*>(instance); }
} // namespace

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* plugin_api) {
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) +
                                  sizeof(HexLabPluginApi::stop))
        return -1;

    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.active-document-cpp", "Active Document C++ Example",
        "1.0.0", nullptr, 0, start, stop);
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
