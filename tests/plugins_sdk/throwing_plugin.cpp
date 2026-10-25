#include "hexlab/plugins/sdk.h"

#include <cstdlib>
#include <fstream>
#include <stdexcept>

#ifndef HEXLAB_THROW_STAGE
#define HEXLAB_THROW_STAGE 3
#endif

namespace {
struct State { int marker = 0x51; };

void write_stop_marker() {
    const char* path = std::getenv("HEXLAB_PLUGIN_STOP_MARKER");
    if (path && *path) {
        std::ofstream marker(path, std::ios::binary | std::ios::app);
        marker << 's';
    }
}

void throwing_action(void*) { throw std::runtime_error("action exception"); }
int32_t throwing_probe(void*, const uint8_t*, uint32_t, uint64_t, uint32_t*) {
    throw std::runtime_error("loader exception");
}
int32_t throwing_decode(void*, uint64_t, const uint8_t*, uint32_t, HexLabDecodedInstruction*) {
    throw std::runtime_error("processor exception");
}

int32_t start(const HexLabHostApi* host, void** instance) {
    *instance = new State;
#if HEXLAB_THROW_STAGE == 2
    throw std::runtime_error("start exception");
#else
    if (!host || !host->register_action) return -1;
    if (host->register_action(host->host_context, "throw.action", "Throw action", nullptr,
                              throwing_action) != 0) return -1;
    if (host->struct_size < offsetof(HexLabHostApi, register_processor_extension) +
                                sizeof(host->register_processor_extension) ||
        !host->register_loader_extension || !host->register_processor_extension) return -1;
    HexLabLoaderExtension loader{};
    loader.struct_size = sizeof(loader);
    loader.api_version = HEXLAB_EXTENSION_API_VERSION;
    loader.extension_id = "throw.loader";
    loader.format_id = "throw-format";
    loader.probe = throwing_probe;
    HexLabProcessorExtension processor{};
    processor.struct_size = sizeof(processor);
    processor.api_version = HEXLAB_EXTENSION_API_VERSION;
    processor.extension_id = "throw.processor";
    processor.architecture_id = "x86_64";
    processor.mode_id = "x86_64";
    processor.decode = throwing_decode;
    if (host->register_loader_extension(host->host_context, &loader) != 0 ||
        host->register_processor_extension(host->host_context, &processor) != 0) return -1;
    return 0;
#endif
}

void stop(void* instance) {
    delete static_cast<State*>(instance);
    write_stop_marker();
    throw std::runtime_error("stop exception");
}

int32_t query(uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* api) {
#if HEXLAB_THROW_STAGE == 1
    throw std::runtime_error("query exception");
#else
    if (!api || host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR) return -1;
    api->struct_size = sizeof(*api);
    api->abi_major = HEXLAB_PLUGIN_ABI_MAJOR;
    api->abi_minor = HEXLAB_PLUGIN_ABI_MINOR;
#if HEXLAB_THROW_STAGE == 2
    api->plugin_id = "test.throw-start";
#else
    api->plugin_id = "test.throw-callback";
#endif
    api->name = "Throwing Plugin Test";
    api->version = "1";
    api->start = start;
    api->stop = stop;
    return 0;
#endif
}
}

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                            const HexLabHostApi* host,
                                                            HexLabPluginApi* api) {
    return query(host_abi_major, host, api);
}
