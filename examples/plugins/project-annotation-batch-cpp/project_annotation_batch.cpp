#include <hexlab/plugins/sdk.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
const HexLabCapability requirements[] = {
    {sizeof(HexLabCapability), 1, 0, 0, "project.api"},
    {sizeof(HexLabCapability), 1, 6, 0, "project.edits"}
};

int32_t annotate_entry(void*, const HexLabProjectApi* project_api, const char* path,
                       char* output, std::uint32_t capacity) {
    if (!project_api || !path || !output || !capacity) return -1;
    HexLabHostApi host{};
    host.struct_size = sizeof(host);
    host.abi_major = HEXLAB_PLUGIN_ABI_MAJOR;
    host.abi_minor = HEXLAB_PLUGIN_ABI_MINOR;
    host.project_api = project_api;
    hexlab::plugins::sdk::ProjectClient project(&host);
    if (!project.available() || !project.supports_annotation_batch() ||
        project.open(path, false) != 0) return -1;

    HexLabProjectSummary summary{};
    if (project.summary(summary) != 0 || !summary.function_count) return -1;
    HexLabFunction entry{};
    std::uint32_t written = 0;
    if (project.functions(0, 1, &entry, written) != 0 || written != 1) return -1;

    HexLabProjectAnnotationEdit edits[2]{};
    for (auto& edit : edits) {
        edit.struct_size = sizeof(edit);
        edit.location.struct_size = sizeof(edit.location);
        edit.location.kind = HEXLAB_PROJECT_LOCATION_ADDRESS;
        edit.location.address_space = entry.address_space;
        edit.location.offset = entry.entry;
    }
    edits[0].kind = HEXLAB_PROJECT_EDIT_RENAME;
    edits[0].value = "sdk_batch_entry";
    edits[1].kind = HEXLAB_PROJECT_EDIT_BOOKMARK;
    edits[1].value = "annotated by native SDK batch example";
    constexpr std::uint64_t undo_group = 0x53444b4241544348ull;
    if (project.annotation_batch(summary.edit_revision, undo_group, edits, 2) != 0)
        return -1;

    const int length = std::snprintf(output, capacity,
        "Applied one revision-pinned annotation batch to function at 0x%llx.",
        static_cast<unsigned long long>(entry.entry));
    return length >= 0 && static_cast<std::uint32_t>(length) < capacity ? 0 : -1;
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    if (!host || !instance ||
        !HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, register_analysis_provider) ||
        !host->register_analysis_provider) return -1;
    const HexLabAnalysisProvider provider{
        sizeof(HexLabAnalysisProvider), HEXLAB_ANALYSIS_PROVIDER_API_VERSION,
        "project-annotation-batch", "Project Annotation Batch", nullptr, annotate_entry
    };
    return host->register_analysis_provider(host->host_context, &provider);
}
void stop(void*) {}
}

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    std::uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* plugin_api) {
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) + sizeof(HexLabPluginApi::stop))
        return -1;
    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.project-annotation-batch-cpp", "Project Annotation Batch C++ Example",
        "1.0.0", nullptr, 0, start, stop, nullptr, 0, requirements, 2);
    if (available_size < offsetof(HexLabPluginApi, declared_capability_count) +
                         sizeof(HexLabPluginApi::declared_capability_count)) {
        api.declared_capabilities = nullptr; api.declared_capability_count = 0;
        api.required_capabilities = nullptr; api.required_capability_count = 0;
    }
    if (available_size < offsetof(HexLabPluginApi, required_capability_count) +
                         sizeof(HexLabPluginApi::required_capability_count)) {
        api.required_capabilities = nullptr; api.required_capability_count = 0;
    }
    api.struct_size = available_size < sizeof(api) ? available_size : sizeof(api);
    std::memcpy(plugin_api, &api, api.struct_size);
    return 0;
}
