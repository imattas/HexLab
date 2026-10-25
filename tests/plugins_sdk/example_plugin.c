#include "hexlab/plugins/sdk.h"
#include <stdlib.h>
#include <string.h>

typedef struct SampleContext {
    uint32_t marker;
    void *host_context;
    void (*log)(void *host_context, uint32_t level, const char *message);
} SampleContext;
#define SAMPLE_CONTEXT_MARKER UINT32_C(0x48584c42)

static void sample_action(void *context) {
    SampleContext *state = (SampleContext *)context;
    if (state && state->marker == SAMPLE_CONTEXT_MARKER && state->log)
        state->log(state->host_context, HEXLAB_LOG_INFO, "Sample inspect action invoked");
}
static int32_t sample_loader_probe(void *context, const uint8_t *prefix, uint32_t prefix_size,
                                   uint64_t total_size, uint32_t *confidence) {
    const SampleContext *state = (const SampleContext *)context;
    if (!state || state->marker != SAMPLE_CONTEXT_MARKER) return -1;
    if (prefix_size > HEXLAB_PLUGIN_MAX_LOADER_PROBE_BYTES || total_size < prefix_size) return -1;
    if (!prefix || !confidence || total_size < 2 || prefix_size < 2 || prefix[0] != 'H' || prefix[1] != 'X') return 0;
    *confidence = 900;
    return 1;
}
static int32_t secondary_loader_probe(void *context, const uint8_t *prefix, uint32_t prefix_size,
                                      uint64_t total_size, uint32_t *confidence) {
    const int32_t claimed = sample_loader_probe(context, prefix, prefix_size, total_size, confidence);
    if (claimed == 1) *confidence = 300;
    return claimed;
}
static int32_t sample_processor_decode(void *context, uint64_t address, const uint8_t *data,
                                       uint32_t size, HexLabDecodedInstruction *output) {
    const SampleContext *state = (const SampleContext *)context;
    (void)address;
    if (!state || state->marker != SAMPLE_CONTEXT_MARKER) return -1;
    if (!data || !size || size > HEXLAB_PLUGIN_MAX_EXTENSION_INPUT || !output) return -1;
    if (data[0] == 0xff) return -1;
    if (data[0] != 0x90) return 0;
    output->length = 1;
    output->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    memcpy(output->mnemonic, "nop", 4);
    return 1;
}
static int32_t sample_processor_semantic(void *context, uint64_t address, const uint8_t *data,
                                         uint32_t size, HexLabSemanticInstruction *output) {
    const SampleContext *state = (const SampleContext *)context;
    (void)address;
    if (!state || state->marker != SAMPLE_CONTEXT_MARKER) return -1;
    if (!data || !size || size > HEXLAB_PLUGIN_MAX_EXTENSION_INPUT || !output) return -1;
    if (data[0] != 0xcc) return 0;
    output->length = 1;
    output->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    output->operand_count = 2;
    memcpy(output->mnemonic, "sample-sem", sizeof("sample-sem"));
    output->operands[0].kind = HEXLAB_SEMANTIC_REGISTER;
    output->operands[0].bank = HEXLAB_SEMANTIC_GPR;
    output->operands[0].index = 0;
    output->operands[0].width = 64;
    output->operands[0].access = HEXLAB_SEMANTIC_WRITE;
    output->operands[1].kind = HEXLAB_SEMANTIC_IMMEDIATE;
    output->operands[1].width = 64;
    output->operands[1].access = HEXLAB_SEMANTIC_READ;
    output->operands[1].value = 42;
    return 1;
}

static int32_t start_plugin(const HexLabHostApi *host, void **instance) {
    if (!host || host->abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !host->register_action) return -1;
    *instance = 0;
    {
        SampleContext *state = (SampleContext *)malloc(sizeof(*state));
        if (!state) return -1;
        state->marker = SAMPLE_CONTEXT_MARKER;
        state->host_context = host->host_context;
        state->log = host->log;
        *instance = state;
    }
    if (host->struct_size >= offsetof(HexLabHostApi, project_api) + sizeof(host->project_api) &&
        host->project_api && host->project_api->struct_size >= sizeof(HexLabProjectApi) &&
        host->project_api->api_version == HEXLAB_PROJECT_API_VERSION) {
        const char *input = getenv("HEXLAB_SDK_INPUT");
        const char *project_path = getenv("HEXLAB_SDK_PROJECT");
        void *project = 0;
        HexLabProjectSummary summary;
        HexLabFunction functions[16];
        HexLabInstruction instructions[16];
        HexLabReference references[16];
        HexLabString strings[16];
        HexLabProjectLocation edit_location;
        uint32_t written = 0;
        uint32_t i;
        if (!input || !project_path || host->project_api->create(host->project_api->host_context,
                project_path, input, HEXLAB_PROJECT_FORMAT_AUTO, &project) != 0 || !project) return -1;
        if (host->project_api->analyze(host->project_api->host_context, project) != 0) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        memset(&summary, 0, sizeof(summary)); summary.struct_size = (uint32_t)sizeof(summary);
        if (host->project_api->summary(host->project_api->host_context, project, &summary) != 0 ||
            summary.input_size == 0 || summary.derived_status > 4) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        for (i = 0; i < 16; ++i) functions[i].struct_size = (uint32_t)sizeof(HexLabFunction);
        if (host->project_api->functions(host->project_api->host_context, project, 0, 16,
                functions, &written) != 0 || written > 16) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        for (i = 0; i < 16; ++i) {
            instructions[i].struct_size = (uint32_t)sizeof(HexLabInstruction);
            references[i].struct_size = (uint32_t)sizeof(HexLabReference);
            strings[i].struct_size = (uint32_t)sizeof(HexLabString);
        }
        if (host->project_api->struct_size < offsetof(HexLabProjectApi, strings) + sizeof(host->project_api->strings) ||
            !host->project_api->instructions || !host->project_api->references || !host->project_api->strings ||
            host->project_api->instructions(host->project_api->host_context, project, 0, 16, instructions, &written) != 0 ||
            written == 0 || instructions[0].length != 5 || instructions[0].address != 0x400000 ||
            host->project_api->references(host->project_api->host_context, project, 0, 0x400000, 0, 16, references, &written) != 0 ||
            written == 0 || references[0].target_kind != HEXLAB_REFERENCE_TARGET_LOCATION || references[0].target != 0x400006 ||
            host->project_api->strings(host->project_api->host_context, project, 0, 16, strings, &written) != 0 ||
            written == 0) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        {
            int found = 0;
            for (i = 0; i < written; ++i)
                if (strcmp(strings[i].preview, "HexLab SDK string") == 0) found = 1;
            if (!found) { host->project_api->close(host->project_api->host_context, project); return -1; }
        }
        if (host->project_api->struct_size < offsetof(HexLabProjectApi, bookmark) + sizeof(host->project_api->bookmark) ||
            !host->project_api->rename || !host->project_api->comment || !host->project_api->bookmark) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        memset(&edit_location, 0, sizeof(edit_location));
        edit_location.struct_size = (uint32_t)sizeof(edit_location);
        edit_location.kind = HEXLAB_PROJECT_LOCATION_ADDRESS;
        edit_location.address_space = 0;
        edit_location.offset = 0x400000;
        if (host->project_api->rename(host->project_api->host_context, project, 0, 0x400000, "sdk_entry") != 0 ||
            host->project_api->comment(host->project_api->host_context, project, &edit_location,
                                       "written by native plugin") != 0 ||
            host->project_api->bookmark(host->project_api->host_context, project, &edit_location,
                                        "SDK bookmark", 0) != 0) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        {
            char oversized_name[514];
            HexLabProjectLocation invalid_location = edit_location;
            memset(oversized_name, 'n', sizeof(oversized_name) - 1);
            oversized_name[sizeof(oversized_name) - 1] = '\0';
            invalid_location.reserved = 1;
            if (host->project_api->rename(host->project_api->host_context, project, 0, 0x400000,
                                          oversized_name) != -1 ||
                host->project_api->comment(host->project_api->host_context, project, &invalid_location,
                                           "invalid") != -1 ||
                host->project_api->bookmark(host->project_api->host_context, project, &edit_location,
                                            "invalid", 2) != -1) {
                host->project_api->close(host->project_api->host_context, project); return -1;
            }
        }
        written = 99;
        if (host->project_api->strings(host->project_api->host_context, project, 0,
                HEXLAB_PROJECT_MAX_PAGE + 1u, strings, &written) != -1 || written != 0) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        written = 99;
        if (host->project_api->functions(host->project_api->host_context, project, 0,
                HEXLAB_PROJECT_MAX_PAGE + 1u, functions, &written) != -1 || written != 0) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        host->project_api->close(host->project_api->host_context, project);
        project = 0;
        if (host->project_api->open(host->project_api->host_context, project_path, 1, &project) != 0 || !project) return -1;
        memset(&summary, 0, sizeof(summary)); summary.struct_size = (uint32_t)sizeof(summary);
        if (host->project_api->summary(host->project_api->host_context, project, &summary) != 0 ||
            summary.input_size == 0) {
            host->project_api->close(host->project_api->host_context, project); return -1;
        }
        host->project_api->close(host->project_api->host_context, project);
    }
    if (host->struct_size >= offsetof(HexLabHostApi, register_processor_extension) +
            sizeof(host->register_processor_extension) && host->register_loader_extension &&
        host->register_processor_extension) {
        SampleContext *state = (SampleContext *)*instance;
        HexLabLoaderExtension loader = {(uint32_t)sizeof(HexLabLoaderExtension),
            HEXLAB_EXTENSION_API_VERSION, "sample.loader", "test-format", state, sample_loader_probe};
        HexLabLoaderExtension secondary_loader = {(uint32_t)sizeof(HexLabLoaderExtension),
            HEXLAB_EXTENSION_API_VERSION, "sample.loader.low", "test-format", state, secondary_loader_probe};
        HexLabLoaderExtension bad_loader = loader;
        HexLabProcessorExtension processor = {(uint32_t)sizeof(HexLabProcessorExtension),
            HEXLAB_EXTENSION_API_VERSION, "sample.processor", "example", "mode32", state,
            sample_processor_decode};
        HexLabProcessorExtension semantic_processor = {(uint32_t)sizeof(HexLabProcessorExtension),
            HEXLAB_EXTENSION_API_VERSION, "sample.semantic", "x86_64", "x86_64", state,
            sample_processor_decode, sample_processor_semantic};
        HexLabProcessorExtension bad_processor = processor;
        bad_loader.api_version++;
        if (host->register_loader_extension(host->host_context, &bad_loader) == 0) return -1;
        bad_loader = loader;
        bad_loader.struct_size = (uint32_t)offsetof(HexLabLoaderExtension, probe);
        if (host->register_loader_extension(host->host_context, &bad_loader) == 0) return -1;
        if (host->register_loader_extension(host->host_context, &loader) != 0 ||
            host->register_loader_extension(host->host_context, &loader) == 0) return -1;
        if (host->register_loader_extension(host->host_context, &secondary_loader) != 0) return -1;
        bad_processor.api_version++;
        if (host->register_processor_extension(host->host_context, &bad_processor) == 0) return -1;
        bad_processor = processor;
        bad_processor.struct_size = (uint32_t)offsetof(HexLabProcessorExtension, decode);
        if (host->register_processor_extension(host->host_context, &bad_processor) == 0) return -1;
        if (host->register_processor_extension(host->host_context, &processor) != 0 ||
            host->register_processor_extension(host->host_context, &processor) == 0) return -1;
        if (host->register_processor_extension(host->host_context, &semantic_processor) != 0) return -1;
    }
    {
        SampleContext *state = (SampleContext *)*instance;
        if (host->register_action(host->host_context, "sample.inspect", "Sample inspect",
                                  state, sample_action) != 0) return -1;
        if (host->struct_size >= offsetof(HexLabHostApi, register_menu_action) +
                                sizeof(host->register_menu_action) && host->register_menu_action &&
            host->register_menu_action(host->host_context, "Analysis/Examples",
                                       "sample.inspect.menu", "Log sample action",
                                       state, sample_action) != 0) return -1;
    }
    return 0;
}
static void stop_plugin(void *instance) {
    SampleContext *state = (SampleContext *)instance;
    if (state) {
        state->marker = 0;
        free(state);
    }
}
static const char *const capabilities[] = {"example.inspect"};
static const HexLabCapability declared_capabilities[] = {
    {(uint32_t)sizeof(HexLabCapability), 1, 0, 0, "analysis.project.read"},
    {(uint32_t)sizeof(HexLabCapability), 1, 1, 0, "processor.decode.display"}
};
static const HexLabPluginApi api = HEXLAB_PLUGIN_API_INITIALIZER_V15(
    "org.hexlab.example", "HexLab C SDK example", "1.0.0", capabilities, 1,
    start_plugin, stop_plugin, declared_capabilities, 2);
HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                const HexLabHostApi *host,
                                                HexLabPluginApi *plugin_api) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < sizeof(HexLabPluginApi)) return -1;
    *plugin_api = api;
    return 0;
}

