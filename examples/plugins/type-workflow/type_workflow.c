#include "hexlab/plugins/sdk.h"

#include <stddef.h>
#include <stdio.h>

static int32_t import_project_types(void *context, const HexLabProjectApi *api,
                                    const char *path, char *output, uint32_t capacity) {
    (void)context;
    if (!api || !path || !output || capacity == 0 ||
        api->struct_size < offsetof(HexLabProjectApi, enum_values) + sizeof(api->enum_values) ||
        !api->open || !api->close || !api->import_header || !api->declarations || !api->enum_values) return -1;
    void *project = NULL;
    if (api->open(api->host_context, path, 0, &project) != 0) return -1;
    static const char declarations[] =
        "typedef struct Vec2 { float x; float y; } Vec2;\n"
        "typedef struct Node { struct Node *next; int value; } Node;\n"
        "enum ImportStatus { ImportError = -7, ImportReady = 4, ImportNext };\n"
        "extern int imported_counter;\n"
        "int imported_visit(Node *node, enum ImportStatus status);\n";
    HexLabHeaderImportSummary summary = {0};
    summary.struct_size = sizeof(summary);
    const int32_t imported = api->import_header(api->host_context, project, declarations, NULL, &summary);
    if (imported != 0) {
        api->close(api->host_context, project);
        return -1;
    }
    HexLabDeclarationRecord records[16] = {{0}};
    for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); ++i)
        records[i].struct_size = sizeof(records[i]);
    uint32_t written = 0;
    const int32_t listed = api->declarations(api->host_context, project, 0,
        (uint32_t)(sizeof(records) / sizeof(records[0])), records, &written);
    if (listed != 0) { api->close(api->host_context, project); return -1; }
    int used = snprintf(output, capacity,
        "Imported %u types (%u typedefs, %u tags; %u enum constants)\n",
        summary.imported_types, summary.typedefs, summary.tags, summary.enum_constants);
    if (used < 0 || (uint32_t)used >= capacity) { api->close(api->host_context, project); return -1; }
    for (uint32_t i = 0; i < written; ++i) {
        const int added = snprintf(output + used, capacity - (uint32_t)used,
                                   "%s [%u]: %s\n", records[i].name, records[i].kind, records[i].formatted);
        if (added < 0 || (uint32_t)added >= capacity - (uint32_t)used) { api->close(api->host_context, project); return -1; }
        used += added;
        if (records[i].enum_constant_count) {
            HexLabEnumConstantRecord values[16] = {{0}};
            for (size_t j = 0; j < sizeof(values) / sizeof(values[0]); ++j)
                values[j].struct_size = sizeof(values[j]);
            uint32_t value_count = 0;
            if (api->enum_values(api->host_context, project, records[i].id, 0, 16, values, &value_count) != 0) {
                api->close(api->host_context, project); return -1;
            }
            for (uint32_t j = 0; j < value_count; ++j) {
                const uint8_t negative = values[j].is_signed && (values[j].value >> 63);
                const uint64_t magnitude = negative ? (uint64_t)0 - values[j].value : values[j].value;
                const int count = snprintf(output + used, capacity - (uint32_t)used,
                    "  %s = %s%llu\n", values[j].name, negative ? "-" : "", (unsigned long long)magnitude);
                if (count < 0 || (uint32_t)count >= capacity - (uint32_t)used) {
                    api->close(api->host_context, project); return -1;
                }
                used += count;
            }
        }
    }
    api->close(api->host_context, project);
    return 0;
}

static int32_t start(const HexLabHostApi *host, void **instance) {
    if (instance) *instance = NULL;
    if (!host || !instance ||
        host->struct_size < offsetof(HexLabHostApi, register_analysis_provider) +
                            sizeof(host->register_analysis_provider) ||
        !host->register_analysis_provider) return -1;
    const HexLabAnalysisProvider provider = {
        sizeof(HexLabAnalysisProvider), HEXLAB_ANALYSIS_PROVIDER_API_VERSION,
        "import-c-types", "Import C Types", NULL, import_project_types
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
    plugin_api->plugin_id = "org.hexlab.example.type-workflow";
    plugin_api->name = "C Type Workflow Example";
    plugin_api->version = "1.0.0";
    plugin_api->capabilities = NULL;
    plugin_api->capability_count = 0;
    plugin_api->start = start;
    plugin_api->stop = stop;
    plugin_api->declared_capabilities = NULL;
    plugin_api->declared_capability_count = 0;
    return 0;
}
