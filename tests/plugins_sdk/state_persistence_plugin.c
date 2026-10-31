#include "hexlab/plugins/sdk.h"

#include <stdlib.h>
#include <string.h>

static const char *const capabilities[] = {"test.plugin-state"};
static const uint8_t initial_value[] = {'s', 'e', 'e', 'd'};
static const uint8_t replacement_value[] = {'r', 'e', 's', 't', 'a', 'r', 't'};

static int state_api_available(const HexLabHostApi *host) {
    return host && HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, plugin_state_api) &&
           host->plugin_state_api &&
           host->plugin_state_api->struct_size >= sizeof(HexLabPluginStateApi) &&
           host->plugin_state_api->api_version == HEXLAB_PLUGIN_STATE_API_VERSION &&
           host->plugin_state_api->get && host->plugin_state_api->set &&
           host->plugin_state_api->erase;
}

static int32_t start_plugin(const HexLabHostApi *host, void **instance) {
    if (!instance || !state_api_available(host)) return -1;
    *instance = 0;
    const char *phase = getenv("HEXLAB_PLUGIN_STATE_TEST_PHASE");
    if (!phase) return -1;

    const HexLabPluginStateApi *state = host->plugin_state_api;
    uint32_t required = 0;
    uint64_t revision = 0;
    uint64_t next_revision = 0;
    int32_t status = state->get(state->host_context, "restart.value", 0, 0,
                                &required, &revision);
    if (strcmp(phase, "seed") == 0) {
        if (status != HEXLAB_PLUGIN_STATE_NOT_FOUND || revision != 0 || required != 0)
            return -1;
        return state->set(state->host_context, "restart.value", 0, initial_value,
                          (uint32_t)sizeof(initial_value), &next_revision) ==
                       HEXLAB_PLUGIN_STATE_OK && next_revision == 1
                   ? 0
                   : -1;
    }

    if (strcmp(phase, "resume") == 0) {
        uint8_t value[sizeof(initial_value)] = {0};
        if (status != HEXLAB_PLUGIN_STATE_BUFFER_TOO_SMALL ||
            required != sizeof(initial_value) || revision != 1)
            return -1;
        status = state->get(state->host_context, "restart.value", sizeof(value), value,
                            &required, &revision);
        if (status != HEXLAB_PLUGIN_STATE_OK || required != sizeof(initial_value) ||
            memcmp(value, initial_value, sizeof(initial_value)) != 0)
            return -1;
        if (state->erase(state->host_context, "restart.value", 1, &next_revision) !=
                HEXLAB_PLUGIN_STATE_OK || next_revision != 2)
            return -1;
        required = 0;
        revision = 0;
        if (state->get(state->host_context, "restart.value", 0, 0, &required,
                       &revision) != HEXLAB_PLUGIN_STATE_NOT_FOUND || revision != 2)
            return -1;
        if (state->set(state->host_context, "restart.value", 1, replacement_value,
                       (uint32_t)sizeof(replacement_value), &next_revision) !=
                HEXLAB_PLUGIN_STATE_CONFLICT || next_revision != 2)
            return -1;
        return state->set(state->host_context, "restart.value", 2, replacement_value,
                          (uint32_t)sizeof(replacement_value), &next_revision) ==
                       HEXLAB_PLUGIN_STATE_OK && next_revision == 3
                   ? 0
                   : -1;
    }

    if (strcmp(phase, "verify") == 0) {
        uint8_t value[sizeof(replacement_value)] = {0};
        if (status != HEXLAB_PLUGIN_STATE_BUFFER_TOO_SMALL ||
            required != sizeof(replacement_value) || revision != 3)
            return -1;
        status = state->get(state->host_context, "restart.value", sizeof(value), value,
                            &required, &revision);
        if (status != HEXLAB_PLUGIN_STATE_OK || required != sizeof(replacement_value) ||
            revision != 3 || memcmp(value, replacement_value, sizeof(replacement_value)) != 0)
            return -1;
        return 0;
    }
    return -1;
}

static void stop_plugin(void *instance) { (void)instance; }
static const HexLabCapability declared_capabilities[] = {
    HEXLAB_CAPABILITY_INITIALIZER("plugin.state", 1, 0, 0)};
static const HexLabPluginApi api = HEXLAB_PLUGIN_API_INITIALIZER_V15(
    "org.hexlab.state-test", "HexLab persistent state test", "1.0.0", capabilities, 1,
    start_plugin, stop_plugin, declared_capabilities, 1);

HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                const HexLabHostApi *host,
                                                HexLabPluginApi *plugin_api) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < sizeof(HexLabPluginApi))
        return -1;
    *plugin_api = api;
    return 0;
}
