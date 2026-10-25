#include "hexlab/plugins/sdk.h"

static int32_t decode(void *context, uint64_t address, const uint8_t *data,
                      uint32_t size, HexLabDecodedInstruction *out) {
    (void)context;
    (void)address;
    if (!data || !size || !out) return -1;
    if (data[0] != 0x90) return 0;
    out->length = 1;
    out->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    out->mnemonic[0] = 'p'; out->mnemonic[1] = 'l'; out->mnemonic[2] = 'u';
    out->mnemonic[3] = 'g'; out->mnemonic[4] = 'i'; out->mnemonic[5] = 'n';
    out->mnemonic[6] = '_'; out->mnemonic[7] = 'n'; out->mnemonic[8] = 'o';
    out->mnemonic[9] = 'p'; out->mnemonic[10] = '\0';
    return 1;
}

static int32_t start(const HexLabHostApi *host, void **instance) {
    if (!host || !instance || !host->register_processor_extension) return -1;
    *instance = 0;
    HexLabProcessorExtension extension = {
        (uint32_t)sizeof(HexLabProcessorExtension), HEXLAB_EXTENSION_API_VERSION,
        "cli.analysis.display", "x86_64", "x86_64", 0, decode};
    return host->register_processor_extension(host->host_context, &extension);
}
static void stop(void *instance) { (void)instance; }

static const HexLabPluginApi api = {
    (uint32_t)sizeof(HexLabPluginApi), HEXLAB_PLUGIN_ABI_MAJOR, HEXLAB_PLUGIN_ABI_MINOR,
    "org.hexlab.cli-analysis-test", "CLI Analysis Test", "1.0", 0, 0, start, stop, 0, 0};

HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                const HexLabHostApi *host,
                                                HexLabPluginApi *plugin_api) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < sizeof(HexLabPluginApi)) return -1;
    *plugin_api = api;
    return 0;
}
