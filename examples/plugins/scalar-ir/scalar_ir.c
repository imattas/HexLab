#include "hexlab/plugins/sdk.h"
#include <stddef.h>
#include <string.h>

#if HEXLAB_PLUGIN_ABI_MINOR < 22
#error This example requires the ABI 1.22 scalar IR SDK
#endif

static int32_t display_decline(void* context,uint64_t address,const uint8_t* bytes,uint32_t size,
                                HexLabDecodedInstruction* output){
    (void)context;(void)address;(void)bytes;(void)size;(void)output;return 0;
}
static void node_header(HexLabScalarIRNode* node,uint32_t operation){
    node->struct_size=(uint32_t)sizeof(*node);node->operation=operation;node->width=64;
    node->left=HEXLAB_SCALAR_IR_NO_NODE;node->right=HEXLAB_SCALAR_IR_NO_NODE;
}
/* An example extension-defined RISC-V custom-0 encoding, not a standard ISA
   instruction: 0b 05 06 00 means x10 = x12 + 5 modulo 2^64. */
static int32_t decode_ir(void* context,uint64_t address,const uint8_t* bytes,uint32_t size,
                          HexLabInstructionIR* output){
    HexLabSemanticInstructionV2* semantic;
    (void)context;
    if(!bytes||!output||size<4||(address&3)||bytes[0]!=0x0b||bytes[1]!=0x05||bytes[2]!=0x06||bytes[3]!=0)return 0;
    memset(output,0,sizeof(*output));
    output->struct_size=(uint32_t)sizeof(*output);output->api_version=HEXLAB_SCALAR_IR_API_VERSION;
    output->semantic.struct_size=(uint32_t)sizeof(output->semantic);output->semantic.api_version=3;
    semantic=&output->semantic.semantic;
    semantic->struct_size=(uint32_t)sizeof(*semantic);semantic->api_version=2;
    semantic->length=4;semantic->flow=HEXLAB_INSTRUCTION_FLOW_NORMAL;semantic->operand_count=3;
    memcpy(semantic->mnemonic,"custom_add5",sizeof("custom_add5"));
    semantic->operands[0].struct_size=(uint32_t)sizeof(semantic->operands[0]);
    semantic->operands[0].kind=HEXLAB_SEMANTIC_REGISTER_V2;semantic->operands[0].access=HEXLAB_SEMANTIC_WRITE;
    semantic->operands[0].bank=HEXLAB_SEMANTIC_RISCV_GPR_V2;semantic->operands[0].index=10;semantic->operands[0].width=64;
    semantic->operands[1].struct_size=(uint32_t)sizeof(semantic->operands[1]);
    semantic->operands[1].kind=HEXLAB_SEMANTIC_REGISTER_V2;semantic->operands[1].access=HEXLAB_SEMANTIC_READ;
    semantic->operands[1].bank=HEXLAB_SEMANTIC_RISCV_GPR_V2;semantic->operands[1].index=12;semantic->operands[1].width=64;
    semantic->operands[2].struct_size=(uint32_t)sizeof(semantic->operands[2]);
    semantic->operands[2].kind=HEXLAB_SEMANTIC_IMMEDIATE_V2;semantic->operands[2].access=HEXLAB_SEMANTIC_READ;
    semantic->operands[2].width=64;semantic->operands[2].value=5;
    output->node_count=3;output->output_count=1;
    node_header(&output->nodes[0],HEXLAB_SCALAR_IR_REGISTER);
    output->nodes[0].reg.bank=HEXLAB_SEMANTIC_RISCV_GPR_V2;output->nodes[0].reg.index=12;output->nodes[0].reg.width=64;
    node_header(&output->nodes[1],HEXLAB_SCALAR_IR_CONSTANT);output->nodes[1].value=5;
    node_header(&output->nodes[2],HEXLAB_SCALAR_IR_ADD);output->nodes[2].left=0;output->nodes[2].right=1;
    output->outputs[0].struct_size=(uint32_t)sizeof(output->outputs[0]);output->outputs[0].node_index=2;
    output->outputs[0].destination.bank=HEXLAB_SEMANTIC_RISCV_GPR_V2;
    output->outputs[0].destination.index=10;output->outputs[0].destination.width=64;
    return 1;
}
static int32_t start(const HexLabHostApi* host,void** instance){
    HexLabProcessorExtension extension={0};
    if(instance)*instance=NULL;
    if(!host||host->abi_major!=1||host->abi_minor<22||
       host->struct_size<offsetof(HexLabHostApi,register_processor_extension)+sizeof(host->register_processor_extension)||
       !host->register_processor_extension)return -1;
    extension.struct_size=(uint32_t)sizeof(extension);extension.api_version=HEXLAB_EXTENSION_API_VERSION;
    extension.extension_id="example.riscv64.add5";extension.architecture_id="riscv64";extension.mode_id="rv64";
    extension.decode=display_decline;extension.decode_ir=decode_ir;
    return host->register_processor_extension(host->host_context,&extension);
}
static void stop(void* instance){(void)instance;}
static const char* capabilities[]={"processor.ir.scalar"};
static const HexLabCapability declared[]={HEXLAB_CAPABILITY_INITIALIZER("processor.ir.scalar",1,22,0)};
static const HexLabCapability required[]={HEXLAB_CAPABILITY_INITIALIZER("processor.ir.scalar",1,22,0)};
static const HexLabPluginApi api=HEXLAB_PLUGIN_API_INITIALIZER_V120(
    "example.scalar-ir","Scalar IR example","1.0",capabilities,1,start,stop,declared,1,required,1);
HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(uint32_t major,const HexLabHostApi* host,HexLabPluginApi* result){
    (void)host;if(major!=1||!result)return -1;*result=api;return 0;
}
