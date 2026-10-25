#include "hexlab/plugins/sdk.h"

#include <stddef.h>
#include <string.h>

static int32_t decode_display(void* context, uint64_t address, const uint8_t* data,
                              uint32_t size, HexLabDecodedInstruction* instruction) {
    (void)context; (void)address; (void)data; (void)size; (void)instruction;
    return 0;
}

static int32_t decode_semantic_v2(void* context, uint64_t address, const uint8_t* data,
                                 uint32_t size, HexLabSemanticInstructionV2* instruction) {
    (void)context; (void)address;
    if (!data || !instruction || size < 3 || data[0] != 0x8b || data[1] != 0x04 || data[2] != 0x88)
        return 0;

    memset(instruction, 0, sizeof(*instruction));
    instruction->struct_size = (uint32_t)sizeof(*instruction);
    instruction->api_version = 2;
    instruction->length = 3;
    instruction->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    instruction->operand_count = 2;
    memcpy(instruction->mnemonic, "mov", sizeof("mov"));

    instruction->operands[0].struct_size = (uint32_t)sizeof(HexLabSemanticOperandV2);
    instruction->operands[0].kind = HEXLAB_SEMANTIC_REGISTER_V2;
    instruction->operands[0].bank = HEXLAB_SEMANTIC_GPR_V2;
    instruction->operands[0].index = 0;
    instruction->operands[0].width = 32;
    instruction->operands[0].access = HEXLAB_SEMANTIC_WRITE;

    instruction->operands[1].struct_size = (uint32_t)sizeof(HexLabSemanticOperandV2);
    instruction->operands[1].kind = HEXLAB_SEMANTIC_BASE_INDEX_MEMORY_V2;
    instruction->operands[1].width = 32;
    instruction->operands[1].access = HEXLAB_SEMANTIC_READ;
    instruction->operands[1].address_width = 64;
    instruction->operands[1].base_bank = HEXLAB_SEMANTIC_GPR_V2;
    instruction->operands[1].base_index = 0;
    instruction->operands[1].base_width = 64;
    instruction->operands[1].index_bank = HEXLAB_SEMANTIC_GPR_V2;
    instruction->operands[1].index_index = 1;
    instruction->operands[1].index_width = 64;
    instruction->operands[1].scale = 4;
    return 1;
}

static int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = NULL;
    if (!host || host->struct_size < offsetof(HexLabHostApi, register_processor_extension) +
                                   sizeof(host->register_processor_extension) ||
        !host->register_processor_extension) return -1;
    HexLabProcessorExtension extension = {0};
    extension.struct_size = (uint32_t)sizeof(extension);
    extension.api_version = HEXLAB_EXTENSION_API_VERSION;
    extension.extension_id = "example.x86_64.sib-load";
    extension.architecture_id = "x86_64";
    extension.mode_id = "x86_64";
    extension.decode = decode_display;
    extension.decode_semantic_v2 = decode_semantic_v2;
    return host->register_processor_extension(host->host_context, &extension);
}

static void stop(void* instance) { (void)instance; }

static const char* capabilities[] = {"processor.semantic.v2"};
static const HexLabPluginApi plugin_api = HEXLAB_PLUGIN_API_INITIALIZER(
    "example.semantic-v2", "Semantic V2 example", "1.0",
    capabilities, 1, start, stop);

HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t host_abi_major,
                                                const HexLabHostApi* host,
                                                HexLabPluginApi* result) {
    (void)host;
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !result) return -1;
    *result = plugin_api;
    return 0;
}
