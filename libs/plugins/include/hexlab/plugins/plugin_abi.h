#ifndef HEXLAB_PLUGIN_ABI_H
#define HEXLAB_PLUGIN_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEXLAB_PLUGIN_ABI_MAJOR 1u
#define HEXLAB_PLUGIN_ABI_MINOR 35u
#define HEXLAB_PLUGIN_QUERY_SYMBOL "hexlab_plugin_query"
#define HEXLAB_EXTENSION_API_VERSION 1u
#define HEXLAB_PLUGIN_MAX_EXTENSION_INPUT 32u
#define HEXLAB_PLUGIN_MAX_LOADER_PROBE_BYTES 4096u
#define HEXLAB_ANALYSIS_PROVIDER_API_VERSION 1u
#define HEXLAB_ANALYSIS_PROVIDER_MAX_OUTPUT 16384u
#define HEXLAB_IMAGE_PROVIDER_API_VERSION 1u
#define HEXLAB_IMAGE_MAX_SEGMENTS 256u
#define HEXLAB_IMAGE_MAX_ENTRIES 64u
#define HEXLAB_IMAGE_MAX_READ 1048576u

/* ABI 1.10: a single flat, byte-addressed domain backed by the original
   input. Output is host-owned and zero-initialized. No transformed bytes,
   relocations, encryption, mixed code modes or segmented state are expressible;
   providers must return an error when any is required for a sound mapping. */
typedef struct HexLabImageInput {
    uint32_t struct_size, api_version;
    uint64_t total_size;
    void* input_context;
    /* Exact reads only; 0 succeeds, negative fails. At most 1 MiB per read,
       4096 calls and 64 MiB cumulative bytes per image invocation. */
    int32_t (*read)(void*, uint64_t offset, uint8_t* output, uint32_t size);
    int32_t (*is_canceled)(void*);
} HexLabImageInput;
typedef struct HexLabImageSegment {
    uint32_t struct_size, permissions; /* read=1, write=2, execute=4 */
    uint64_t address, memory_size, file_offset, file_size;
    uint32_t reserved;
    char name[64];
} HexLabImageSegment;
typedef struct HexLabImageMapping {
    uint32_t struct_size, api_version, reserved;
    uint32_t address_space, address_width, byte_order; /* order: little=0, big=1 */
    char architecture_id[32], mode_id[32];
    uint32_t segment_count, entry_count;
    HexLabImageSegment segments[HEXLAB_IMAGE_MAX_SEGMENTS];
    uint64_t entries[HEXLAB_IMAGE_MAX_ENTRIES];
} HexLabImageMapping;
typedef int32_t (*HexLabLoadImage)(void* extension_context, const HexLabImageInput*, HexLabImageMapping*);

typedef enum HexLabLogLevel {
    HEXLAB_LOG_DEBUG = 0,
    HEXLAB_LOG_INFO = 1,
    HEXLAB_LOG_WARNING = 2,
    HEXLAB_LOG_ERROR = 3
} HexLabLogLevel;

/* Versioned extension descriptors are copied by the host during plugin start.
   Callback/context pointers remain owned by the plugin and are valid only
   until stop returns. The host unregisters them before unloading the module. */
typedef struct HexLabLoaderExtension {
    uint32_t struct_size;
    uint32_t api_version;
    const char* extension_id;
    const char* format_id;
    void* extension_context;
    /* Return 1 to claim the input and set confidence [0,1000], 0 to decline,
       or a negative value on callback failure. */
    int32_t (*probe)(void* extension_context, const uint8_t* prefix, uint32_t prefix_size,
                     uint64_t total_size, uint32_t* confidence);
    /* Optional ABI 1.10 tail. Check struct_size before accessing. load_image
       returns 0 for a complete representable mapping, negative on failure. */
    uint32_t image_api_version;
    HexLabLoadImage load_image;
} HexLabLoaderExtension;

typedef enum HexLabInstructionFlow {
    HEXLAB_INSTRUCTION_FLOW_NORMAL = 0,
    HEXLAB_INSTRUCTION_FLOW_BRANCH = 1,
    HEXLAB_INSTRUCTION_FLOW_CALL = 2,
    HEXLAB_INSTRUCTION_FLOW_RETURN = 3,
    HEXLAB_INSTRUCTION_FLOW_JUMP = 4
} HexLabInstructionFlow;
typedef struct HexLabDecodedInstruction {
    uint32_t struct_size;
    uint32_t length;
    uint32_t flow;
    uint32_t reserved;
    char mnemonic[64];
    char operands[192];
} HexLabDecodedInstruction;
/* Optional semantic decode record. Values are deliberately generic and are
   validated before conversion to the host IR. */
typedef enum HexLabSemanticOperandKind {
    HEXLAB_SEMANTIC_REGISTER = 1,
    HEXLAB_SEMANTIC_IMMEDIATE = 2,
    HEXLAB_SEMANTIC_RELATIVE = 3,
    HEXLAB_SEMANTIC_ABSOLUTE_MEMORY = 4
} HexLabSemanticOperandKind;
typedef enum HexLabSemanticRegisterBank {
    HEXLAB_SEMANTIC_GPR = 0, HEXLAB_SEMANTIC_IP = 1,
    HEXLAB_SEMANTIC_FLAGS = 2, HEXLAB_SEMANTIC_ARM32_GPR = 3,
    HEXLAB_SEMANTIC_ARM64_GPR = 4, HEXLAB_SEMANTIC_RISCV_GPR = 5,
    HEXLAB_SEMANTIC_MIPS_GPR = 6, HEXLAB_SEMANTIC_PPC_GPR = 7
} HexLabSemanticRegisterBank;
typedef enum HexLabSemanticOperandAccess {
    HEXLAB_SEMANTIC_READ = 1, HEXLAB_SEMANTIC_WRITE = 2,
    HEXLAB_SEMANTIC_READ_WRITE = 3
} HexLabSemanticOperandAccess;
typedef struct HexLabSemanticOperand {
    uint32_t kind, bank, index, width, access;
    uint32_t reserved;
    uint64_t value;
} HexLabSemanticOperand;
typedef struct HexLabSemanticInstruction {
    uint32_t struct_size, length, flow, operand_count;
    uint32_t reserved;
    char mnemonic[64];
    HexLabSemanticOperand operands[4];
} HexLabSemanticInstruction;
typedef int32_t (*HexLabProcessorSemanticDecode)(void* extension_context, uint64_t address,
                                                const uint8_t* data, uint32_t size,
                                                HexLabSemanticInstruction* instruction);
/* ABI 1.7 semantic records keep the v1 callback layout untouched while adding
   address expressions, implicit register effects, and delayed transfers. */
typedef enum HexLabSemanticOperandKindV2 {
    HEXLAB_SEMANTIC_REGISTER_V2 = 1,
    HEXLAB_SEMANTIC_IMMEDIATE_V2 = 2,
    HEXLAB_SEMANTIC_RELATIVE_V2 = 3,
    HEXLAB_SEMANTIC_ABSOLUTE_MEMORY_V2 = 4,
    HEXLAB_SEMANTIC_BASE_INDEX_MEMORY_V2 = 5
} HexLabSemanticOperandKindV2;
typedef enum HexLabSemanticRegisterBankV2 {
    HEXLAB_SEMANTIC_GPR_V2 = 0, HEXLAB_SEMANTIC_IP_V2 = 1,
    HEXLAB_SEMANTIC_FLAGS_V2 = 2, HEXLAB_SEMANTIC_ARM32_GPR_V2 = 3,
    HEXLAB_SEMANTIC_ARM64_GPR_V2 = 4, HEXLAB_SEMANTIC_RISCV_GPR_V2 = 5,
    HEXLAB_SEMANTIC_MIPS_GPR_V2 = 6, HEXLAB_SEMANTIC_PPC_GPR_V2 = 7,
    HEXLAB_SEMANTIC_ARM_FLAGS_V2 = 8, HEXLAB_SEMANTIC_RISCV_FSTATUS_V2 = 9,
    HEXLAB_SEMANTIC_MIPS_FCSR_V2 = 10, HEXLAB_SEMANTIC_MOS6502_V2 = 11,
    HEXLAB_SEMANTIC_MIPS_HILO_V2 = 12, HEXLAB_SEMANTIC_PPC_CR_V2 = 13,
    HEXLAB_SEMANTIC_ARM64_SP_V2 = 14, HEXLAB_SEMANTIC_ARM64_ZERO_V2 = 15
} HexLabSemanticRegisterBankV2;
typedef struct HexLabSemanticRegisterV2 {
    uint32_t bank, index, width, reserved;
} HexLabSemanticRegisterV2;
typedef struct HexLabSemanticOperandV2 {
    uint32_t struct_size, kind, bank, index, width, access, reserved;
    uint64_t value;
    /* Used only by BASE_INDEX_MEMORY; UINT32_MAX denotes an absent base/index. */
    uint32_t address_width, base_bank, base_index, base_width;
    uint32_t index_bank, index_index, index_width, scale;
    int64_t displacement;
} HexLabSemanticOperandV2;
typedef struct HexLabSemanticInstructionV2 {
    uint32_t struct_size, api_version, length, flow, operand_count;
    uint32_t condition, delay_slots, register_read_count, register_write_count, reserved;
    char mnemonic[64];
    HexLabSemanticOperandV2 operands[4];
    HexLabSemanticRegisterV2 register_reads[16];
    HexLabSemanticRegisterV2 register_writes[16];
} HexLabSemanticInstructionV2;
typedef int32_t (*HexLabProcessorSemanticDecodeV2)(void* extension_context, uint64_t address,
                                                  const uint8_t* data, uint32_t size,
                                                  HexLabSemanticInstructionV2* instruction);
/* ABI 1.16 adds explicit base-register update semantics without changing the
   V2 instruction or operand record layouts. Update records refer to one
   BASE_INDEX_MEMORY operand in the nested semantic record. */
typedef enum HexLabSemanticMemoryUpdateKindV3 {
    HEXLAB_SEMANTIC_MEMORY_PRE_INDEX_WRITEBACK_V3 = 1,
    HEXLAB_SEMANTIC_MEMORY_POST_INDEX_WRITEBACK_V3 = 2
} HexLabSemanticMemoryUpdateKindV3;
typedef struct HexLabSemanticMemoryUpdateV3 {
    uint32_t struct_size, operand_index, kind, reserved;
    int64_t writeback_displacement;
} HexLabSemanticMemoryUpdateV3;
typedef struct HexLabSemanticInstructionV3 {
    uint32_t struct_size, api_version, memory_update_count, reserved;
    HexLabSemanticInstructionV2 semantic;
    HexLabSemanticMemoryUpdateV3 memory_updates[4];
} HexLabSemanticInstructionV3;
typedef int32_t (*HexLabProcessorSemanticDecodeV3)(void* extension_context, uint64_t address,
                                                  const uint8_t* data, uint32_t size,
                                                  HexLabSemanticInstructionV3* instruction);
/* ABI 1.22: bounded, pure scalar bit-vector instruction IR. Output storage is
   host-owned; conversion finishes under the module lock after callback return.
   No plugin pointers survive. Integer arithmetic wraps to width bits (8/16/32/64).
   is_signed is 0 or 1 and must agree across an operation and its inputs. ABI
   1.23 through 1.25 append operations, 1.26 adds complete x86 FLAGS formulas,
   1.27 adds bit-count operations, 1.28 adds byte swapping, and 1.29 adds modular negation; the record API version and layout stay fixed,
   and the host capability minor negotiates the expanded operation set. */
#define HEXLAB_SCALAR_IR_API_VERSION 1u
#define HEXLAB_SCALAR_IR_MAX_NODES 32u
#define HEXLAB_SCALAR_IR_MAX_OUTPUTS 8u
#define HEXLAB_SCALAR_IR_MAX_DEPTH 16u
#define HEXLAB_SCALAR_IR_MAX_EXPANDED_NODES 1024u
#define HEXLAB_SCALAR_IR_NO_NODE UINT32_MAX

typedef enum HexLabScalarIROperation {
    HEXLAB_SCALAR_IR_CONSTANT = 1,
    HEXLAB_SCALAR_IR_REGISTER = 2,
    HEXLAB_SCALAR_IR_ADD = 3,
    HEXLAB_SCALAR_IR_SUB = 4,
    HEXLAB_SCALAR_IR_MUL = 5,
    HEXLAB_SCALAR_IR_AND = 6,
    HEXLAB_SCALAR_IR_OR = 7,
    HEXLAB_SCALAR_IR_XOR = 8,
    HEXLAB_SCALAR_IR_NOT = 9,
    /* ABI 1.23: result is a width-sized integer 0 or 1. Signed/unsigned
       ordering is selected by the operation, not by host-language casts. */
    HEXLAB_SCALAR_IR_EQ = 10,
    HEXLAB_SCALAR_IR_NE = 11,
    HEXLAB_SCALAR_IR_ULT = 12,
    HEXLAB_SCALAR_IR_UGE = 13,
    HEXLAB_SCALAR_IR_ULE = 14,
    HEXLAB_SCALAR_IR_UGT = 15,
    HEXLAB_SCALAR_IR_SLT = 16,
    HEXLAB_SCALAR_IR_SGE = 17,
    HEXLAB_SCALAR_IR_SLE = 18,
    HEXLAB_SCALAR_IR_SGT = 19,
    /* ABI 1.24: logical left/right and arithmetic right shifts. */
    HEXLAB_SCALAR_IR_SHL = 20,
    HEXLAB_SCALAR_IR_LSHR = 21,
    HEXLAB_SCALAR_IR_ASHR = 22,
    /* ABI 1.25: rotates with count reduced modulo operand width. */
    HEXLAB_SCALAR_IR_ROL = 23,
    HEXLAB_SCALAR_IR_ROR = 24,
    /* ABI 1.27: zero input returns the operand width for CLZ and CTZ. */
    HEXLAB_SCALAR_IR_CLZ = 25,
    HEXLAB_SCALAR_IR_CTZ = 26,
    HEXLAB_SCALAR_IR_POPCOUNT = 27,
    /* ABI 1.28: reverse byte order across the declared integer width. */
    HEXLAB_SCALAR_IR_BSWAP = 28,
    /* ABI 1.29: width-wrapping two's-complement negation. */
    HEXLAB_SCALAR_IR_NEG = 29
} HexLabScalarIROperation;

typedef struct HexLabScalarIRNode {
    uint32_t struct_size, operation, width, is_signed;
    /* Operands reference preceding nodes. Unused references are NO_NODE. */
    uint32_t left, right, reserved0, reserved1;
    uint64_t value; /* CONSTANT bit pattern only; otherwise zero. */
    HexLabSemanticRegisterV2 reg; /* REGISTER only; otherwise all zero. */
} HexLabScalarIRNode;

typedef struct HexLabScalarIROutput {
    uint32_t struct_size, node_index, reserved0, reserved1;
    HexLabSemanticRegisterV2 destination;
} HexLabScalarIROutput;

typedef struct HexLabInstructionIR {
    uint32_t struct_size, api_version, node_count, output_count, reserved0, reserved1;
    /* Must be opaque, unconditional fallthrough with no memory/writeback,
       delay slots, IP, hidden effects or partial-register outputs. The only
       supported status effect is an explicitly declared complete x86 FLAGS
       register read/write represented by register leaves and outputs. */
    HexLabSemanticInstructionV3 semantic;
    HexLabScalarIRNode nodes[HEXLAB_SCALAR_IR_MAX_NODES];
    HexLabScalarIROutput outputs[HEXLAB_SCALAR_IR_MAX_OUTPUTS];
} HexLabInstructionIR;

typedef int32_t (*HexLabProcessorDecodeIR)(void* extension_context, uint64_t address,
                                          const uint8_t* data, uint32_t size,
                                          HexLabInstructionIR* instruction);

typedef struct HexLabProcessorExtension {
    uint32_t struct_size;
    uint32_t api_version;
    const char* extension_id;
    const char* architecture_id;
    const char* mode_id;
    void* extension_context;
    /* Return 1 when decoded and fill the output, 0 when bytes are not handled,
       or a negative value on callback failure. Input is capped at 32 bytes. */
    int32_t (*decode)(void* extension_context, uint64_t address,
                      const uint8_t* data, uint32_t size,
                      HexLabDecodedInstruction* instruction);
    /* Optional append-only semantic callback. Check struct_size before use;
       older descriptors ending at decode remain valid. */
    HexLabProcessorSemanticDecode decode_semantic;
    /* Optional ABI 1.7 callback. It uses V2 records and is preferred when
       present; the old callback remains available to older modules/hosts. */
    HexLabProcessorSemanticDecodeV2 decode_semantic_v2;
    /* Optional ABI 1.16 callback. V3 embeds the unchanged V2 semantic record
       and appends validated pre/post-index base writeback metadata. */
    HexLabProcessorSemanticDecodeV3 decode_semantic_v3;
    /* Optional ABI 1.22 tail. Preferred pure scalar-IR decode. Same 1/0/negative
       claim/decline/failure convention; older descriptor prefixes are intact. */
    HexLabProcessorDecodeIR decode_ir;
} HexLabProcessorExtension;
typedef int32_t (*HexLabRegisterLoaderExtension)(void* host_context,
                                                const HexLabLoaderExtension* extension);
typedef int32_t (*HexLabRegisterProcessorExtension)(void* host_context,
                                                   const HexLabProcessorExtension* extension);
struct HexLabProjectApi;
struct HexLabActiveDocumentApi;
struct HexLabActiveDebuggerApi;
/* Read-only, bounded project report provider. The callback may use the host's
   project_api to open the supplied project path read-only and inspect it. */
typedef struct HexLabAnalysisProvider {
    uint32_t struct_size;
    uint32_t api_version;
    const char* provider_id;
    const char* display_name;
    void* provider_context;
    int32_t (*analyze)(void* provider_context, const struct HexLabProjectApi* project_api,
                       const char* project_path, char* output, uint32_t output_capacity);
} HexLabAnalysisProvider;
typedef int32_t (*HexLabRegisterAnalysisProvider)(void* host_context,
                                                 const HexLabAnalysisProvider* provider);
typedef int32_t (*HexLabRegisterMenuAction)(void* host_context, const char* menu_path,
                                            const char* action_id, const char* label,
                                            void* action_context, void (*invoke)(void* action_context));
struct HexLabCapability;

/* ABI 1.33: host-owned, plugin-ID-scoped opaque state. Values live for the
   PluginManager lifetime and survive module unload/reload, but are not saved
   to project or host configuration files. Mutations use per-key revisions. */
#define HEXLAB_PLUGIN_STATE_API_VERSION 1u
#define HEXLAB_PLUGIN_STATE_MAX_KEY 128u
#define HEXLAB_PLUGIN_STATE_MAX_VALUE 65536u
enum {
    HEXLAB_PLUGIN_STATE_OK = 0,
    HEXLAB_PLUGIN_STATE_INVALID = -1,
    HEXLAB_PLUGIN_STATE_FAILED = -2,
    HEXLAB_PLUGIN_STATE_NOT_FOUND = -3,
    HEXLAB_PLUGIN_STATE_CONFLICT = -4,
    HEXLAB_PLUGIN_STATE_BUFFER_TOO_SMALL = -5,
    HEXLAB_PLUGIN_STATE_LIMIT = -6
};
typedef struct HexLabPluginStateApi {
    uint32_t struct_size, api_version;
    void* host_context;
    /* Key syntax is ASCII [A-Za-z0-9._-], length 1..128. A zero-capacity
       read reports required bytes and revision without writing output. */
    int32_t (*get)(void* host_context, const char* key, uint32_t capacity,
                   uint8_t* output, uint32_t* required, uint64_t* revision);
    /* expected_revision=0 creates a new key. Each successful set/erase
       increments the key revision. Erased keys retain their revision. */
    int32_t (*set)(void* host_context, const char* key, uint64_t expected_revision,
                   const uint8_t* value, uint32_t size, uint64_t* new_revision);
    int32_t (*erase)(void* host_context, const char* key, uint64_t expected_revision,
                     uint64_t* new_revision);
} HexLabPluginStateApi;

/* All strings and arrays passed across this ABI are borrowed for the duration
   of the callback. No C++ object, allocator, exception, or STL type crosses it. */
typedef struct HexLabHostApi {
    uint32_t struct_size;
    uint32_t abi_major;
    uint32_t abi_minor;
    void* host_context;
    void (*log)(void* host_context, uint32_t level, const char* message);
    int32_t (*register_action)(void* host_context, const char* action_id,
                               const char* label, void* action_context,
                               void (*invoke)(void* action_context));
    /* Optional in ABI 1.1. Check struct_size and project_api before use. */
    const struct HexLabProjectApi* project_api;
    /* Optional in ABI 1.3. Check struct_size and callback pointer before use. */
    HexLabRegisterLoaderExtension register_loader_extension;
    HexLabRegisterProcessorExtension register_processor_extension;
    /* Optional in ABI 1.8. Check struct_size and debugger_api before use. */
    const struct HexLabDebuggerApi* debugger_api;
    /* Optional in ABI 1.9. */
    HexLabRegisterAnalysisProvider register_analysis_provider;
    /* Optional in ABI 1.12. Menu path is slash-separated beneath Extensions. */
    HexLabRegisterMenuAction register_menu_action;
    /* Optional ABI 1.15. Query/read/navigate the current desktop document. */
    const struct HexLabActiveDocumentApi* active_document_api;
    /* Optional ABI 1.17. Read-only view of the active desktop debugger. */
    const struct HexLabActiveDebuggerApi* active_debugger_api;
    /* Optional ABI 1.18. Durable project breakpoints for the active saved project. */
    const struct HexLabActiveProjectBreakpointApi* active_project_breakpoint_api;
    /* Optional ABI 1.20. Independently versioned host service contracts. */
    const struct HexLabCapability* declared_capabilities;
    uint32_t declared_capability_count;
    /* Optional ABI 1.33. Plugin-ID-scoped opaque state; check table size and
       API version before use. */
    const HexLabPluginStateApi* plugin_state_api;
} HexLabHostApi;

#define HEXLAB_PROJECT_API_VERSION 1u
#define HEXLAB_PROJECT_MAX_PAGE 4096u
#define HEXLAB_PROJECT_MAX_PATH 32768u
#define HEXLAB_PROJECT_MAX_READ (1024u * 1024u)
#define HEXLAB_PROJECT_MAX_ANNOTATION_BATCH 4096u

/* ABI 1.28 project undo/redo results. A stale revision never moves history. */
enum {
    HEXLAB_PROJECT_HISTORY_OK = 0,
    HEXLAB_PROJECT_HISTORY_INVALID = -1,
    HEXLAB_PROJECT_HISTORY_FAILED = -2,
    HEXLAB_PROJECT_HISTORY_STALE = -3
};
typedef enum HexLabProjectLocationKind {
    HEXLAB_PROJECT_LOCATION_ADDRESS = 0,
    HEXLAB_PROJECT_LOCATION_FILE = 1
} HexLabProjectLocationKind;
typedef struct HexLabProjectLocation {
    uint32_t struct_size;
    uint32_t kind;
    uint32_t address_space;
    uint32_t reserved;
    uint64_t offset;
} HexLabProjectLocation;
typedef enum HexLabProjectAnnotationEditKind {
    HEXLAB_PROJECT_EDIT_RENAME = 0,
    HEXLAB_PROJECT_EDIT_COMMENT = 1,
    HEXLAB_PROJECT_EDIT_BOOKMARK = 2
} HexLabProjectAnnotationEditKind;
typedef struct HexLabProjectAnnotationEdit {
    uint32_t struct_size;
    uint32_t kind;
    HexLabProjectLocation location;
    uint32_t flags; /* Bookmark: bit 0 removes the bookmark. Zero for other kinds. */
    uint32_t reserved;
    const char* value; /* Borrowed UTF-8, copied before the callback returns. */
} HexLabProjectAnnotationEdit;
typedef enum HexLabProjectFormat {
    HEXLAB_PROJECT_FORMAT_AUTO = 0,
    HEXLAB_PROJECT_FORMAT_PE = 1,
    HEXLAB_PROJECT_FORMAT_ELF = 2,
    HEXLAB_PROJECT_FORMAT_MACHO = 3,
    HEXLAB_PROJECT_FORMAT_AR = 4
} HexLabProjectFormat;
typedef struct HexLabProjectSummary {
    uint32_t struct_size;
    uint32_t derived_status;
    uint64_t function_count;
    uint64_t instruction_count;
    uint64_t input_size;
    /* Optional tail; read only when struct_size reaches this field. */
    uint64_t edit_revision;
} HexLabProjectSummary;
typedef struct HexLabFunction {
    uint32_t struct_size;
    uint32_t address_space;
    uint64_t entry;
    uint64_t chunk_count;
    uint8_t complete;
    uint8_t reserved[7];
} HexLabFunction;
/* ABI 1.29. A code address can be owned by multiple recovered functions
   (for example shared tails); each row identifies one owner and its entry. */
typedef struct HexLabFunctionOwner {
    uint32_t struct_size;
    uint32_t address_space;
    uint64_t function_id;
    uint64_t entry;
    uint8_t reserved[8];
} HexLabFunctionOwner;
typedef struct HexLabInstruction {
    uint32_t struct_size;
    uint32_t address_space;
    uint64_t address;
    uint8_t length;
    uint8_t bytes[15];
    char text[256];
} HexLabInstruction;
#define HEXLAB_PROJECT_INSTRUCTION_TEXT_CAPACITY 1024u
/* ABI 1.30 paged instruction record. The original HexLabInstruction remains
   unchanged for older modules; this tail carries a longer formatted text. */
typedef struct HexLabInstructionText {
    uint32_t struct_size;
    uint32_t address_space;
    uint64_t address;
    uint8_t length;
    uint8_t bytes[15];
    char text[HEXLAB_PROJECT_INSTRUCTION_TEXT_CAPACITY];
} HexLabInstructionText;
typedef enum HexLabReferenceTargetKind {
    HEXLAB_REFERENCE_TARGET_NONE = 0,
    HEXLAB_REFERENCE_TARGET_LOCATION = 1,
    HEXLAB_REFERENCE_TARGET_EXTERNAL = 2,
    HEXLAB_REFERENCE_TARGET_UNRESOLVED = 3
} HexLabReferenceTargetKind;
typedef struct HexLabReference {
    uint32_t struct_size;
    uint32_t source_space;
    uint64_t source;
    uint8_t source_is_file;
    uint8_t reserved0[3];
    uint32_t target_space;
    uint64_t target;
    uint8_t target_is_file;
    uint8_t reserved1[3];
    uint32_t kind;
    uint32_t target_kind;
    char external_library[128];
    char external_name[128];
} HexLabReference;
typedef struct HexLabString {
    uint32_t struct_size;
    uint32_t encoding;
    uint64_t file_offset;
    uint64_t address;
    uint64_t characters;
    uint64_t byte_length;
    uint32_t address_space;
    uint8_t has_address;
    uint8_t terminated;
    uint8_t reserved[2];
    char preview[256];
} HexLabString;
#define HEXLAB_PROJECT_STRING_PREVIEW_CAPACITY 1024u
/* ABI 1.32 string record. The original HexLabString remains unchanged; this
   record exposes up to 1023 bytes of the analysis preview. */
typedef struct HexLabStringText {
    uint32_t struct_size;
    uint32_t encoding;
    uint64_t file_offset;
    uint64_t address;
    uint64_t characters;
    uint64_t byte_length;
    uint32_t address_space;
    uint8_t has_address;
    uint8_t terminated;
    uint8_t reserved[2];
    char preview[HEXLAB_PROJECT_STRING_PREVIEW_CAPACITY];
} HexLabStringText;
/* ABI 1.13 native C type authoring. Header includes are rejected unless the
   host later provides an explicit include resolver. */
#define HEXLAB_PROJECT_MAX_HEADER_BYTES (4u * 1024u * 1024u)
#define HEXLAB_PROJECT_TYPE_NAME_CAPACITY 256u
#define HEXLAB_PROJECT_TYPE_TEXT_CAPACITY 1024u
typedef struct HexLabHeaderImportOptions {
    uint32_t struct_size;
    uint8_t pointer_bytes, char_bytes, short_bytes, int_bytes;
    uint8_t long_bytes, long_long_bytes, float_bytes, double_bytes;
    /* Optional ABI 1.35 tail. Zero floating alignments mean natural-width. */
    uint8_t long_double_bytes, float_alignment, double_alignment, long_double_alignment;
} HexLabHeaderImportOptions;
typedef struct HexLabHeaderImportSummary {
    uint32_t struct_size;
    uint32_t imported_types;
    uint32_t typedefs;
    uint32_t tags;
    uint32_t enum_constants;
} HexLabHeaderImportSummary;
typedef struct HexLabTypeRecord {
    uint32_t struct_size;
    uint64_t id;
    char name[HEXLAB_PROJECT_TYPE_NAME_CAPACITY];
    char formatted[HEXLAB_PROJECT_TYPE_TEXT_CAPACITY];
} HexLabTypeRecord;
/* ABI 1.14 keeps declaration roles separate from the underlying type kind. */
typedef enum HexLabDeclarationKind {
    HEXLAB_DECLARATION_TYPE = 0,
    HEXLAB_DECLARATION_OBJECT = 1,
    HEXLAB_DECLARATION_FUNCTION = 2
} HexLabDeclarationKind;
typedef struct HexLabDeclarationRecord {
    uint32_t struct_size;
    uint64_t id;
    uint32_t kind;
    uint32_t enum_constant_count;
    char name[HEXLAB_PROJECT_TYPE_NAME_CAPACITY];
    char formatted[HEXLAB_PROJECT_TYPE_TEXT_CAPACITY];
} HexLabDeclarationRecord;
typedef struct HexLabEnumConstantRecord {
    uint32_t struct_size;
    uint64_t value; /* Exact 64-bit representation; signed values are two's complement. */
    uint8_t is_signed;
    uint8_t reserved[7];
    char name[HEXLAB_PROJECT_TYPE_NAME_CAPACITY];
} HexLabEnumConstantRecord;
/* ABI 1.21 bounded CFG records. Block IDs are opaque and valid only for the
   current analyzed project generation. Edge kind values are stable ABI values. */
typedef enum HexLabBlockEdgeKind {
    HEXLAB_BLOCK_EDGE_FALLTHROUGH = 0,
    HEXLAB_BLOCK_EDGE_CONDITIONAL_TRUE = 1,
    HEXLAB_BLOCK_EDGE_CONDITIONAL_FALSE = 2,
    HEXLAB_BLOCK_EDGE_JUMP = 3,
    HEXLAB_BLOCK_EDGE_CALL_CONTINUATION = 4,
    HEXLAB_BLOCK_EDGE_UNRESOLVED = 5,
    HEXLAB_BLOCK_EDGE_DELAY_SLOT = 6,
    HEXLAB_BLOCK_EDGE_EXCEPTION = 7
} HexLabBlockEdgeKind;
typedef struct HexLabBasicBlock {
    uint32_t struct_size;
    uint32_t address_space;
    uint64_t id;
    uint64_t address;
    uint64_t instruction_count;
    uint64_t successor_count;
    uint8_t has_stop;
    uint8_t reserved[7];
    char stop_detail[256];
} HexLabBasicBlock;
typedef struct HexLabBlockSuccessor {
    uint32_t struct_size;
    uint32_t source_space;
    uint32_t target_space;
    uint32_t kind;
    uint64_t source;
    uint64_t target;
    uint64_t target_block_id;
    uint8_t has_target;
    uint8_t has_block;
    uint8_t reserved[6];
} HexLabBlockSuccessor;
typedef struct HexLabProjectApi {
    uint32_t struct_size;
    uint32_t api_version;
    void* host_context;
    int32_t (*create)(void* host_context, const char* project_path, const char* input_path,
                      uint32_t format, void** project);
    int32_t (*open)(void* host_context, const char* project_path, uint8_t read_only,
                    void** project);
    void (*close)(void* host_context, void* project);
    int32_t (*analyze)(void* host_context, void* project);
    int32_t (*summary)(void* host_context, void* project, HexLabProjectSummary* summary);
    int32_t (*functions)(void* host_context, void* project, uint64_t start,
                         uint32_t capacity, HexLabFunction* output, uint32_t* written);
    /* Optional append-only ABI 1 extensions. Check struct_size before use. */
    int32_t (*instructions)(void* host_context, void* project, uint64_t start,
                            uint32_t capacity, HexLabInstruction* output, uint32_t* written);
    int32_t (*references)(void* host_context, void* project, uint32_t source_space, uint64_t source,
                          uint64_t start, uint32_t capacity, HexLabReference* output, uint32_t* written);
    int32_t (*strings)(void* host_context, void* project, uint64_t start,
                       uint32_t capacity, HexLabString* output, uint32_t* written);
    /* Optional append-only project editing operations. Check struct_size through
       each callback before using it. All edits use the normal project command path. */
    int32_t (*rename)(void* host_context, void* project, uint32_t address_space,
                      uint64_t address, const char* name);
    int32_t (*comment)(void* host_context, void* project, const HexLabProjectLocation* location,
                       const char* text);
    int32_t (*bookmark)(void* host_context, void* project, const HexLabProjectLocation* location,
                        const char* label, uint8_t remove);
    /* Optional ABI 1.11. Exact read from the project's effective image; capped at 1 MiB. */
    int32_t (*read)(void* host_context, void* project, const HexLabProjectLocation* location,
                    uint32_t size, uint8_t* output);
    /* Optional ABI 1.13: bounded C header import, paged type listing, and
       durable address type assignment. Check struct_size before each call. */
    int32_t (*import_header)(void* host_context, void* project, const char* source,
                             const HexLabHeaderImportOptions* options,
                             HexLabHeaderImportSummary* summary);
    int32_t (*types)(void* host_context, void* project, uint64_t start,
                     uint32_t capacity, HexLabTypeRecord* output, uint32_t* written);
    int32_t (*assign_type)(void* host_context, void* project, uint32_t address_space,
                           uint64_t address, uint64_t type_id, uint8_t remove);
    /* Optional ABI 1.14. Header imports retain object/function declaration roles
       and exact enum values. Legacy `types` records keep their original layout. */
    int32_t (*declarations)(void* host_context, void* project, uint64_t start,
                            uint32_t capacity, HexLabDeclarationRecord* output, uint32_t* written);
    int32_t (*enum_values)(void* host_context, void* project, uint64_t type_id,
                           uint64_t start, uint32_t capacity, HexLabEnumConstantRecord* output,
                           uint32_t* written);
    /* Optional ABI 1.21. Paged CFG queries require current derived analysis;
       block IDs expire when analysis is replaced or the project is reopened. */
    int32_t (*function_blocks)(void* host_context, void* project, uint32_t address_space,
                               uint64_t function_entry, uint64_t start, uint32_t capacity,
                               HexLabBasicBlock* output, uint32_t* written);
    int32_t (*block_instructions)(void* host_context, void* project, uint64_t block_id,
                                  uint64_t start, uint32_t capacity,
                                  HexLabInstruction* output, uint32_t* written);
    int32_t (*block_successors)(void* host_context, void* project, uint64_t block_id,
                                uint64_t start, uint32_t capacity,
                                HexLabBlockSuccessor* output, uint32_t* written);
    /* Optional atomic rename/comment/bookmark batch. The expected revision is
       checked before validation and commit; every edit is one undoable group. */
    int32_t (*annotation_batch)(void* host_context, void* project,
                                uint64_t expected_edit_revision, uint64_t group,
                                const HexLabProjectAnnotationEdit* edits, uint32_t count);
    /* Optional ABI 1.28. Move one durable history group on a writable handle.
       Pass the latest summary edit_revision; query summary again after success.
       History changes can invalidate derived facts and previously returned IDs. */
    int32_t (*undo)(void* host_context, void* project, uint64_t expected_edit_revision);
    int32_t (*redo)(void* host_context, void* project, uint64_t expected_edit_revision);
    /* Optional ABI 1.29. Page all recovered function owners for one address. */
    int32_t (*function_owners)(void* host_context, void* project,
                               uint32_t address_space, uint64_t address,
                               uint64_t start, uint32_t capacity,
                               HexLabFunctionOwner* output, uint32_t* written);
    /* Optional ABI 1.30. Same instruction pages with up to 1023 UTF-8 text
       bytes plus terminator; old 256-byte callbacks remain unchanged. */
    int32_t (*instructions_text)(void* host_context, void* project, uint64_t start,
                                 uint32_t capacity, HexLabInstructionText* output,
                                 uint32_t* written);
    int32_t (*block_instructions_text)(void* host_context, void* project, uint64_t block_id,
                                       uint64_t start, uint32_t capacity,
                                       HexLabInstructionText* output, uint32_t* written);
    /* Optional ABI 1.32. String pages with previews up to 1023 bytes. */
    int32_t (*strings_text)(void* host_context, void* project, uint64_t start,
                            uint32_t capacity, HexLabStringText* output, uint32_t* written);
    /* Optional ABI 1.34. Page outgoing references whose source is inside the
       half-open virtual range [begin, begin + size). */
    int32_t (*outgoing_references_range)(void* host_context, void* project,
                                         uint32_t begin_space, uint64_t begin,
                                         uint64_t size, uint64_t start,
                                         uint32_t capacity, HexLabReference* output,
                                         uint32_t* written);
} HexLabProjectApi;

/* Optional host-owned debugger service. Sessions and all returned data remain
   host-owned; input strings/arrays are borrowed only for the callback. A
   session is thread-affine. Every session must be closed before plugin stop
   returns; the host also closes leaked sessions after stop and before unload. */
#define HEXLAB_DEBUGGER_API_VERSION 1u
#define HEXLAB_DEBUGGER_MAX_PAGE 4096u
#define HEXLAB_DEBUGGER_MAX_IO (1024u * 1024u)
#define HEXLAB_DEBUGGER_MAX_ARGUMENTS 256u
#define HEXLAB_DEBUGGER_MAX_WAIT_MS 30000u
#define HEXLAB_DEBUGGER_NAME_CAPACITY 256u
#define HEXLAB_DEBUGGER_PATH_CAPACITY 1024u
#define HEXLAB_DEBUGGER_REGISTER_BYTES 64u
#define HEXLAB_DEBUGGER_CONDITION_CAPACITY 257u
#define HEXLAB_DEBUGGER_LOG_MESSAGE_CAPACITY 1025u

typedef enum HexLabDebuggerBackendKind {
    HEXLAB_DEBUGGER_BACKEND_NATIVE = 0,
    HEXLAB_DEBUGGER_BACKEND_GDB_REMOTE = 1
} HexLabDebuggerBackendKind;
typedef enum HexLabDebuggerSessionState {
    HEXLAB_DEBUGGER_STATE_IDLE = 0,
    HEXLAB_DEBUGGER_STATE_RUNNING = 1,
    HEXLAB_DEBUGGER_STATE_STOPPED = 2,
    HEXLAB_DEBUGGER_STATE_EXITED = 3,
    HEXLAB_DEBUGGER_STATE_DETACHED = 4,
    HEXLAB_DEBUGGER_STATE_FAULTED = 5
} HexLabDebuggerSessionState;
typedef enum HexLabDebuggerThreadState {
    HEXLAB_DEBUGGER_THREAD_RUNNING = 0,
    HEXLAB_DEBUGGER_THREAD_STOPPED = 1,
    HEXLAB_DEBUGGER_THREAD_EXITED = 2,
    HEXLAB_DEBUGGER_THREAD_UNKNOWN = 3
} HexLabDebuggerThreadState;
typedef enum HexLabDebuggerEventKind {
    HEXLAB_DEBUGGER_EVENT_BREAKPOINT = 0,
    HEXLAB_DEBUGGER_EVENT_SINGLE_STEP = 1,
    HEXLAB_DEBUGGER_EVENT_EXCEPTION = 2,
    HEXLAB_DEBUGGER_EVENT_THREAD_CREATED = 3,
    HEXLAB_DEBUGGER_EVENT_THREAD_EXITED = 4,
    HEXLAB_DEBUGGER_EVENT_MODULE_LOADED = 5,
    HEXLAB_DEBUGGER_EVENT_MODULE_UNLOADED = 6,
    HEXLAB_DEBUGGER_EVENT_PROCESS_EXITED = 7,
    HEXLAB_DEBUGGER_EVENT_OUTPUT = 8,
    HEXLAB_DEBUGGER_EVENT_UNKNOWN = 9
} HexLabDebuggerEventKind;
typedef enum HexLabDebuggerBreakpointKind {
    HEXLAB_DEBUGGER_BREAKPOINT_SOFTWARE = 0,
    HEXLAB_DEBUGGER_BREAKPOINT_HARDWARE = 1,
    HEXLAB_DEBUGGER_BREAKPOINT_EXECUTE = 2,
    HEXLAB_DEBUGGER_BREAKPOINT_READ = 3,
    HEXLAB_DEBUGGER_BREAKPOINT_WRITE = 4,
    HEXLAB_DEBUGGER_BREAKPOINT_ACCESS = 5
} HexLabDebuggerBreakpointKind;
typedef enum HexLabDebuggerContinueStatus {
    HEXLAB_DEBUGGER_CONTINUE_HANDLED = 0,
    HEXLAB_DEBUGGER_CONTINUE_NOT_HANDLED = 1
} HexLabDebuggerContinueStatus;
typedef enum HexLabDebuggerByteOrder {
    HEXLAB_DEBUGGER_BYTE_ORDER_UNKNOWN = 0,
    HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE = 1,
    HEXLAB_DEBUGGER_BYTE_ORDER_BIG = 2
} HexLabDebuggerByteOrder;
typedef struct HexLabDebuggerTarget {
    uint32_t struct_size;
    const char* executable;
    const char* const* arguments;
    uint32_t argument_count;
    const char* working_directory;
} HexLabDebuggerTarget;
typedef struct HexLabDebugProcess {
    uint32_t struct_size;
    uint32_t architecture; /* HexLab Architecture ordinal; see core architecture.hpp. */
    uint64_t id;
    char name[HEXLAB_DEBUGGER_NAME_CAPACITY];
} HexLabDebugProcess;
typedef struct HexLabDebugThread {
    uint32_t struct_size;
    uint32_t state;
    uint64_t id;
    char name[HEXLAB_DEBUGGER_NAME_CAPACITY];
} HexLabDebugThread;
typedef struct HexLabDebugModule {
    uint32_t struct_size;
    uint32_t reserved;
    uint64_t base;
    uint64_t size;
    char name[HEXLAB_DEBUGGER_NAME_CAPACITY];
    char path[HEXLAB_DEBUGGER_PATH_CAPACITY];
} HexLabDebugModule;
typedef struct HexLabDebugMemoryRegion {
    uint32_t struct_size;
    uint8_t readable;
    uint8_t writable;
    uint8_t executable;
    uint8_t reserved;
    uint64_t start;
    uint64_t length;
    char type[64];
} HexLabDebugMemoryRegion;
typedef struct HexLabDebugRegister {
    uint32_t struct_size;
    uint32_t byte_count;
    uint64_t number;
    uint32_t byte_order;
    uint32_t reserved;
    char name[64];
    char group[64];
    uint8_t bytes[HEXLAB_DEBUGGER_REGISTER_BYTES];
} HexLabDebugRegister;
typedef struct HexLabDebugEvent {
    uint32_t struct_size;
    uint32_t kind;
    uint64_t sequence;
    uint64_t process;
    uint64_t thread;
    uint64_t address;
    uint32_t code;
    uint8_t first_chance_present;
    uint8_t first_chance;
    uint8_t reserved[2];
    char message[HEXLAB_DEBUGGER_NAME_CAPACITY];
} HexLabDebugEvent;
#define HEXLAB_DEBUGGER_EVENT_MESSAGE_CAPACITY 4097u
/* ABI 1.31 event record. The original 256-byte HexLabDebugEvent remains
   unchanged; this separate record can retain up to 4096 message bytes. */
typedef struct HexLabDebugEventText {
    uint32_t struct_size;
    uint32_t kind;
    uint64_t sequence;
    uint64_t process;
    uint64_t thread;
    uint64_t address;
    uint32_t code;
    uint8_t first_chance_present;
    uint8_t first_chance;
    uint8_t reserved[2];
    char message[HEXLAB_DEBUGGER_EVENT_MESSAGE_CAPACITY];
} HexLabDebugEventText;
typedef struct HexLabDebugBreakpoint {
    uint32_t struct_size;
    uint32_t kind;
    uint64_t id;
    uint64_t address;
    uint8_t enabled;
    uint8_t size;
    uint8_t reserved[6];
} HexLabDebugBreakpoint;
/* ABI 1.19 append-only runtime policy view. This record is separate from the
   stable breakpoint inventory record so older callers retain its exact size. */
typedef struct HexLabDebugBreakpointRule {
    uint32_t struct_size;
    uint32_t reserved;
    uint64_t id;
    uint64_t hit_count;
    uint64_t ignore_count;
    uint8_t logpoint;
    uint8_t reserved_flags[7];
    char condition[HEXLAB_DEBUGGER_CONDITION_CAPACITY];
    char log_message[HEXLAB_DEBUGGER_LOG_MESSAGE_CAPACITY];
} HexLabDebugBreakpointRule;
typedef struct HexLabDebuggerApi {
    uint32_t struct_size;
    uint32_t api_version;
    void* host_context;
    int32_t (*create)(void* host_context, uint32_t backend_kind, void** session);
    void (*close)(void* host_context, void* session);
    int32_t (*processes)(void* host_context, void* session, uint64_t start, uint32_t capacity,
                         HexLabDebugProcess* output, uint32_t* written);
    int32_t (*launch)(void* host_context, void* session, const HexLabDebuggerTarget* target,
                      HexLabDebugProcess* process);
    int32_t (*attach)(void* host_context, void* session, uint64_t process_id,
                      HexLabDebugProcess* process);
    int32_t (*connect_remote)(void* host_context, void* session, const char* host,
                              uint16_t port, HexLabDebugProcess* process);
    int32_t (*state)(void* host_context, void* session, uint32_t* state,
                     uint8_t* has_process, HexLabDebugProcess* process);
    int32_t (*detach)(void* host_context, void* session);
    int32_t (*request_interrupt)(void* host_context, void* session);
    int32_t (*wait_event)(void* host_context, void* session, uint32_t timeout_ms,
                          HexLabDebugEvent* event);
    int32_t (*continue_event)(void* host_context, void* session, uint64_t sequence,
                              uint32_t status);
    int32_t (*single_step_event)(void* host_context, void* session, uint64_t sequence,
                                 uint32_t status);
    int32_t (*threads)(void* host_context, void* session, uint64_t start, uint32_t capacity,
                       HexLabDebugThread* output, uint32_t* written);
    int32_t (*modules)(void* host_context, void* session, uint64_t start, uint32_t capacity,
                       HexLabDebugModule* output, uint32_t* written);
    int32_t (*memory_regions)(void* host_context, void* session, uint64_t start, uint32_t capacity,
                              HexLabDebugMemoryRegion* output, uint32_t* written);
    int32_t (*read_memory)(void* host_context, void* session, uint64_t address,
                           uint32_t size, uint8_t* output);
    int32_t (*write_memory)(void* host_context, void* session, uint64_t address,
                            uint32_t size, const uint8_t* input);
    int32_t (*read_registers)(void* host_context, void* session, uint64_t thread_id,
                              uint64_t start, uint32_t capacity,
                              HexLabDebugRegister* output, uint32_t* written);
    int32_t (*write_registers)(void* host_context, void* session, uint64_t thread_id,
                               uint32_t count, const HexLabDebugRegister* input);
    int32_t (*add_breakpoint)(void* host_context, void* session, uint64_t address,
                              uint32_t kind, uint8_t size, HexLabDebugBreakpoint* output);
    int32_t (*remove_breakpoint)(void* host_context, void* session, uint64_t id);
    int32_t (*set_breakpoint_enabled)(void* host_context, void* session, uint64_t id, uint8_t enabled);
    int32_t (*breakpoints)(void* host_context, void* session, uint64_t start, uint32_t capacity,
                           HexLabDebugBreakpoint* output, uint32_t* written);
    /* Optional ABI 1.19 breakpoint policy. Check struct_size before use. */
    int32_t (*set_breakpoint_ignore_count)(void* host_context, void* session,
                                           uint64_t id, uint64_t ignore_count);
    int32_t (*set_breakpoint_condition)(void* host_context, void* session,
                                        uint64_t id, const char* expression);
    int32_t (*set_breakpoint_logpoint)(void* host_context, void* session,
                                       uint64_t id, uint8_t enabled, const char* message);
    int32_t (*breakpoint_rule)(void* host_context, void* session,
                               uint64_t id, HexLabDebugBreakpointRule* output);
    /* Optional ABI 1.31. Same event wait with up to 4096 message bytes. */
    int32_t (*wait_event_text)(void* host_context, void* session, uint32_t timeout_ms,
                               HexLabDebugEventText* event);
} HexLabDebuggerApi;

/* ABI 1.15: ephemeral active-document access. Tokens identify one active
   document snapshot; the host revalidates them for every read/navigation. */
#define HEXLAB_ACTIVE_DOCUMENT_API_VERSION 1u
#define HEXLAB_ACTIVE_DOCUMENT_MAX_READ (1024u * 1024u)
#define HEXLAB_ACTIVE_DOCUMENT_NAVIGATION_TIMEOUT_MS 5000u
typedef struct HexLabDocumentToken {
    uint32_t struct_size, reserved;
    uint64_t document_id, open_generation;
    uint64_t edit_revision, byte_revision, decision_revision;
} HexLabDocumentToken;
typedef struct HexLabActiveDocumentInfo {
    uint32_t struct_size;
    uint32_t address_space, address_width, byte_order; /* little=0, big=1 */
    HexLabDocumentToken token;
    uint64_t image_size, file_size;
    char architecture_id[32], mode_id[32];
} HexLabActiveDocumentInfo;
enum {
    HEXLAB_ACTIVE_DOCUMENT_OK = 0,
    HEXLAB_ACTIVE_DOCUMENT_INVALID = -1,
    HEXLAB_ACTIVE_DOCUMENT_FAILED = -2,
    HEXLAB_ACTIVE_DOCUMENT_STALE = -3
};
typedef struct HexLabActiveDocumentApi {
    uint32_t struct_size, api_version;
    void* host_context;
    /* Caller initializes info->struct_size to sizeof(HexLabActiveDocumentInfo). */
    int32_t (*query)(void* host_context, HexLabActiveDocumentInfo* info);
    /* Address locations read the effective mapped image; file locations read
       the effective file view. Requests are exact and bounded to 1 MiB. */
    int32_t (*read)(void* host_context, const HexLabDocumentToken* token,
                    const HexLabProjectLocation* location, uint32_t size, uint8_t* output);
    /* Off-thread calls marshal to the UI owner thread and wait up to five seconds. */
    int32_t (*navigate)(void* host_context, const HexLabDocumentToken* token,
                        const HexLabProjectLocation* location);
} HexLabActiveDocumentApi;

/* ABI 1.18: durable breakpoints in the active saved project. These operations
   edit only project state through the host workspace command path. They never
   install/remove runtime debugger breakpoints. The token binds calls to one
   active document, saved-project binding, and project revision. */
#define HEXLAB_ACTIVE_PROJECT_BREAKPOINT_API_VERSION 1u
#define HEXLAB_ACTIVE_PROJECT_BREAKPOINT_MAX_PAGE 4096u
typedef enum HexLabProjectBreakpointKind {
    HEXLAB_PROJECT_BREAKPOINT_SOFTWARE = 0,
    HEXLAB_PROJECT_BREAKPOINT_HARDWARE = 1,
    HEXLAB_PROJECT_BREAKPOINT_EXECUTE = 2,
    HEXLAB_PROJECT_BREAKPOINT_READ = 3,
    HEXLAB_PROJECT_BREAKPOINT_WRITE = 4,
    HEXLAB_PROJECT_BREAKPOINT_ACCESS = 5
} HexLabProjectBreakpointKind;
typedef struct HexLabActiveProjectToken {
    uint32_t struct_size, reserved;
    HexLabDocumentToken document;
    uint64_t project_identity, project_generation;
} HexLabActiveProjectToken;
typedef struct HexLabProjectBreakpointRecord {
    uint32_t struct_size, address_space;
    uint64_t id, address;
    uint32_t kind;
    uint8_t enabled, size;
    uint8_t reserved[6];
} HexLabProjectBreakpointRecord;
typedef struct HexLabActiveProjectBreakpointApi {
    uint32_t struct_size, api_version;
    void* host_context;
    int32_t (*snapshot)(void* host_context, HexLabActiveProjectToken* token);
    /* Query only works while a saved project is active. Pages are capped at 4096. */
    int32_t (*query)(void* host_context, const HexLabActiveProjectToken* token,
                     uint64_t start, uint32_t capacity,
                     HexLabProjectBreakpointRecord* output, uint32_t* written);
    /* Upsert/remove by address. The host validates address mapping and token,
       then records a normal durable workspace command. */
    int32_t (*set)(void* host_context, const HexLabActiveProjectToken* token,
                   uint32_t address_space, uint64_t address, uint32_t kind,
                   uint8_t size, uint8_t enabled, uint8_t remove);
} HexLabActiveProjectBreakpointApi;

/* ABI 1.17: read-only access to the desktop-owned active debugger session.
   Tokens bind operations to one session/stop and one active document open. */
#define HEXLAB_ACTIVE_DEBUGGER_API_VERSION 1u
#define HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE 4096u
#define HEXLAB_ACTIVE_DEBUGGER_MAX_READ (1024u * 1024u)
typedef struct HexLabActiveDebuggerToken {
    uint32_t struct_size, reserved;
    uint64_t session_id, session_generation, stop_generation;
    HexLabDocumentToken document;
} HexLabActiveDebuggerToken;
typedef struct HexLabActiveDebuggerInfo {
    uint32_t struct_size, state;
    uint8_t has_process;
    uint8_t reserved[3];
    HexLabActiveDebuggerToken token;
    HexLabDebugProcess process;
} HexLabActiveDebuggerInfo;
enum {
    HEXLAB_ACTIVE_DEBUGGER_OK = 0,
    HEXLAB_ACTIVE_DEBUGGER_INVALID = -1,
    HEXLAB_ACTIVE_DEBUGGER_FAILED = -2,
    HEXLAB_ACTIVE_DEBUGGER_STALE = -3,
    HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED = -4
};
typedef struct HexLabActiveDebuggerApi {
    uint32_t struct_size, api_version;
    void* host_context;
    int32_t (*query)(void*, HexLabActiveDebuggerInfo*);
    int32_t (*threads)(void*, const HexLabActiveDebuggerToken*, uint64_t, uint32_t,
                       HexLabDebugThread*, uint32_t*);
    int32_t (*read_registers)(void*, const HexLabActiveDebuggerToken*, uint64_t, uint64_t,
                              uint32_t, HexLabDebugRegister*, uint32_t*);
    int32_t (*read_memory)(void*, const HexLabActiveDebuggerToken*, uint64_t, uint32_t, uint8_t*);
} HexLabActiveDebuggerApi;

/* start receives an output slot initialized to NULL. If start returns nonzero,
   the host calls stop exactly once before unloading the module, passing the
   value left in the slot (which may still be NULL). stop must accept NULL and
   release any resources acquired during a failed start. The borrowed host
   table and its service contexts remain valid until stop returns, including
   while other plugins are activated or unloaded. They must not be used after
   stop; plugin worker threads must finish before stop returns. */
typedef int32_t (*HexLabPluginStart)(const HexLabHostApi* host, void** instance);
typedef void (*HexLabPluginStop)(void* instance);

typedef struct HexLabPluginApi {
    uint32_t struct_size;
    uint32_t abi_major;
    uint32_t abi_minor;
    const char* plugin_id;
    const char* name;
    const char* version;
    const char* const* capabilities;
    uint32_t capability_count;
    HexLabPluginStart start;
    HexLabPluginStop stop;
    /* Optional ABI 1.4 append-only, versioned capability declarations. */
    const struct HexLabCapability* declared_capabilities;
    uint32_t declared_capability_count;
    /* Optional ABI 1.20. Required host or loaded-provider capabilities are
       checked before start; declarations do not transfer provider services. */
    const struct HexLabCapability* required_capabilities;
    uint32_t required_capability_count;
} HexLabPluginApi;

/* Capabilities name an independently versioned service contract. Provided
   declarations are descriptive. Required declarations (ABI 1.20) are checked
   by compatible hosts before plugin start; `flags` must be zero there. */
typedef struct HexLabCapability {
    uint32_t struct_size;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t flags;
    const char* capability_id;
} HexLabCapability;

typedef int32_t (*HexLabPluginQuery)(uint32_t host_abi_major,
                                     const HexLabHostApi* host,
                                     HexLabPluginApi* plugin_api);

#ifdef __cplusplus
}
#endif
#endif
