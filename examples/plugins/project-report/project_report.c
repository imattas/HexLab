#include "hexlab/plugins/sdk.h"

#include <stddef.h>
#include <stdio.h>

static int32_t report_project(void *context, const HexLabProjectApi *api,
                              const char *path, char *output, uint32_t capacity) {
    (void)context;
    if (!api || !path || !output || capacity == 0 ||
        api->struct_size < offsetof(HexLabProjectApi, summary) + sizeof(api->summary) ||
        !api->open || !api->close || !api->summary) return -1;
    void *project = NULL;
    if (api->open(api->host_context, path, 1, &project) != 0) return -1;
    HexLabProjectSummary summary = {0};
    summary.struct_size = sizeof(summary);
    const int32_t status = api->summary(api->host_context, project, &summary);
    api->close(api->host_context, project);
    if (status != 0) return -1;
    const int written = snprintf(output, capacity,
        "Project analysis summary\nInput bytes: %llu\nFunctions: %llu\nInstructions: %llu",
        (unsigned long long)summary.input_size,
        (unsigned long long)summary.function_count,
        (unsigned long long)summary.instruction_count);
    return written >= 0 && (uint32_t)written < capacity ? 0 : -1;
}

static int32_t start(const HexLabHostApi *host, void **instance) {
    if (instance) *instance = NULL;
    if (!host || !instance ||
        host->struct_size < offsetof(HexLabHostApi, register_analysis_provider) +
                            sizeof(host->register_analysis_provider) ||
        !host->register_analysis_provider) return -1;
    const HexLabAnalysisProvider provider = {
        sizeof(HexLabAnalysisProvider), HEXLAB_ANALYSIS_PROVIDER_API_VERSION,
        "project-summary", "Project Summary", NULL, report_project
    };
    return host->register_analysis_provider(host->host_context, &provider);
}

static void stop(void *instance) { (void)instance; }

HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                 const HexLabHostApi *host,
                                                 HexLabPluginApi *plugin_api) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) + sizeof(plugin_api->stop)) return -1;
    plugin_api->abi_major = HEXLAB_PLUGIN_ABI_MAJOR;
    plugin_api->abi_minor = HEXLAB_PLUGIN_ABI_MINOR;
    plugin_api->plugin_id = "org.hexlab.example.project-report";
    plugin_api->name = "Project Report Example";
    plugin_api->version = "1.0.0";
    plugin_api->capabilities = NULL;
    plugin_api->capability_count = 0;
    plugin_api->start = start;
    plugin_api->stop = stop;
    plugin_api->declared_capabilities = NULL;
    plugin_api->declared_capability_count = 0;
    return 0;
}
