#include "hexlab/plugins/sdk.h"

#include <stddef.h>

static void legacy_action(void *context) { (void)context; }
static int32_t legacy_start(const HexLabHostApi *host, void **instance) {
    if (!host || !host->register_action || !instance) return -1;
    *instance = 0;
    return host->register_action(host->host_context, "legacy.ping", "Legacy ping", 0, legacy_action);
}
static void legacy_stop(void *instance) { (void)instance; }

HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                const HexLabHostApi *host,
                                                HexLabPluginApi *api) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !api) return -1;
    api->struct_size = (uint32_t)offsetof(HexLabPluginApi, declared_capabilities);
    api->abi_major = 1;
    api->abi_minor = 0;
    api->plugin_id = "org.hexlab.legacy";
    api->name = "Legacy ABI 1.0";
    api->version = "1.0.0";
    api->capabilities = 0;
    api->capability_count = 0;
    api->start = legacy_start;
    api->stop = legacy_stop;
    return 0;
}
