#include <hexlab/plugins/sdk.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {
constexpr std::uint8_t magic[] = {'H', 'L', 'F', '1'};
constexpr std::uint64_t image_base = 0x1000;

int32_t probe(void*, const std::uint8_t* prefix, std::uint32_t prefix_size,
              std::uint64_t total_size, std::uint32_t* confidence) {
    if (!confidence) return -1;
    *confidence = 0;
    if (total_size < sizeof(magic) || prefix_size < sizeof(magic) || !prefix) return 0;
    if (std::memcmp(prefix, magic, sizeof(magic)) != 0) return 0;
    *confidence = 1000;
    return 1;
}

int32_t load_image(void*, const HexLabImageInput* input, HexLabImageMapping* mapping) {
    if (!input || !mapping || input->total_size <= sizeof(magic)) return -1;
    if (input->struct_size < offsetof(HexLabImageInput, is_canceled) + sizeof(input->is_canceled) ||
        input->api_version != HEXLAB_IMAGE_PROVIDER_API_VERSION || !input->read)
        return -1;
    std::uint8_t header[sizeof(magic)]{};
    if (input->read(input->input_context, 0, header, sizeof(header)) != 0 ||
        std::memcmp(header, magic, sizeof(magic)) != 0)
        return -1;
    if (input->is_canceled && input->is_canceled(input->input_context)) return -1;

    mapping->api_version = HEXLAB_IMAGE_PROVIDER_API_VERSION;
    mapping->address_space = 0;
    mapping->address_width = 32;
    mapping->byte_order = 0;
    std::memcpy(mapping->architecture_id, "x86", sizeof("x86"));
    std::memcpy(mapping->mode_id, "x86_32", sizeof("x86_32"));
    mapping->segment_count = 1;
    mapping->entry_count = 1;
    auto& segment = mapping->segments[0];
    segment.struct_size = sizeof(segment);
    segment.permissions = 1u | 4u;
    segment.address = image_base;
    segment.memory_size = input->total_size - sizeof(magic);
    segment.file_offset = sizeof(magic);
    segment.file_size = segment.memory_size;
    std::memcpy(segment.name, "flat-code", sizeof("flat-code"));
    mapping->entries[0] = image_base;
    return 0;
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    if (!host || !instance ||
        !HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, register_loader_extension) ||
        !host->register_loader_extension)
        return -1;
    const HexLabLoaderExtension extension{
        sizeof(HexLabLoaderExtension), HEXLAB_EXTENSION_API_VERSION,
        "org.hexlab.example.flat-image", "example-flat", nullptr,
        probe, HEXLAB_IMAGE_PROVIDER_API_VERSION, load_image
    };
    return host->register_loader_extension(host->host_context, &extension);
}

void stop(void*) {}
} // namespace

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    std::uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* plugin_api) {
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) + sizeof(HexLabPluginApi::stop))
        return -1;
    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.flat-image-loader-cpp", "Flat Image Loader C++ Example",
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
