#pragma once
#include "hexlab/analysis/analysis.hpp"
#include "hexlab/analysis/decisions.hpp"
#include "hexlab/analysis/dependencies.hpp"
namespace hexlab {
struct FunctionId {std::uint64_t value;auto operator<=>(const FunctionId&)const=default;};
struct BlockId {std::uint64_t value;auto operator<=>(const BlockId&)const=default;};
enum class FunctionSeedKind {entry,export_symbol,direct_call,user_function,user_code,symbol,unwind,arm_context_root,tls_callback,initializer,guard_cf,dex_method,safe_seh,pogo,wasm_export,wasm_start,wasm_element,wasm_defined,dwarf_subprogram,m6502_nmi_vector,m6502_reset_vector,m6502_irq_vector,dwarf_entry_point};
struct FunctionSeedUnwindEvidence {std::uint32_t section=0;std::uint64_t file_offset=0,record_size=0;bool operator==(const FunctionSeedUnwindEvidence&)const=default;};
struct FunctionSeedDwarfEvidence {std::uint64_t unit_offset=0,die_offset=0,record_size=0;bool operator==(const FunctionSeedDwarfEvidence&)const=default;};
struct FunctionSeedPogoEvidence {std::uint32_t profile_index=0,entry_index=0;std::uint64_t file_offset=0,record_size=0;bool operator==(const FunctionSeedPogoEvidence&)const=default;};
struct FunctionSeedWasmExportEvidence {std::uint32_t function_index=0,export_index=0,type_index=0;std::uint64_t section_file_offset=0,entry_file_offset=0;bool operator==(const FunctionSeedWasmExportEvidence&)const=default;};
struct FunctionSeedWasmStartEvidence {std::uint32_t function_index=0,type_index=0;std::uint64_t section_file_offset=0,entry_file_offset=0;bool operator==(const FunctionSeedWasmStartEvidence&)const=default;};
struct FunctionSeedWasmElementEvidence {std::uint32_t function_index=0,type_index=0,segment_index=0,element_index=0;std::uint64_t section_file_offset=0,entry_file_offset=0,body_file_offset=0;bool operator==(const FunctionSeedWasmElementEvidence&)const=default;};
struct FunctionSeedWasmDefinedEvidence {std::uint32_t function_index=0,type_index=0;std::uint64_t body_file_offset=0;bool operator==(const FunctionSeedWasmDefinedEvidence&)const=default;};
enum class FunctionInitializerSource : std::uint8_t { elf_init, elf_fini, elf_preinit_array, elf_init_array, elf_fini_array, macho_mod_init_func, macho_routines, macho_mod_term_func, elf_init_array_section, elf_fini_array_section, elf_ctors_section, elf_dtors_section };
struct FunctionSeedInitializerEvidence {
    FunctionInitializerSource source = FunctionInitializerSource::elf_init_array;
    std::optional<std::uint32_t> section;
    std::optional<std::uint64_t> index, file_offset;
    std::optional<std::int64_t> dynamic_tag;
    std::vector<std::uint64_t> relocation_rows, dyld_classic_rows, dyld_chained_rows;
    bool operator==(const FunctionSeedInitializerEvidence &) const = default;
};
struct FunctionSeed {FunctionSeedKind kind;Address entry;std::optional<Address> source;std::optional<std::uint64_t> decision;std::optional<FunctionSeedUnwindEvidence> unwind_evidence;std::optional<FunctionSeedInitializerEvidence> initializer_evidence;std::optional<FunctionSeedPogoEvidence> pogo_evidence;std::optional<FunctionSeedWasmExportEvidence> wasm_export_evidence;std::optional<FunctionSeedWasmStartEvidence> wasm_start_evidence;std::optional<FunctionSeedWasmElementEvidence> wasm_element_evidence;std::optional<FunctionSeedWasmDefinedEvidence> wasm_defined_evidence;std::optional<FunctionSeedDwarfEvidence> dwarf_evidence;bool operator==(const FunctionSeed&)const=default;};
enum class FunctionStopReason {ret,trap,unsupported,invalid,truncated,unmapped,uninitialized,non_executable,manual_data,overlap,indirect,budget,target_overflow,chunk_boundary,tail_candidate,elf_relocation,macho_relocation,macho_dyld,image_exclusion};
struct FunctionStop {Address address;FunctionStopReason reason;std::string detail;bool operator==(const FunctionStop&)const=default;};
struct InstructionFact {std::uint64_t id;Instruction instruction;ReadSet reads;};
enum class BlockEdgeKind {fallthrough,conditional_true,conditional_false,jump,call_continuation,unresolved,delay_slot,exception};
struct BlockSuccessor {Address source;std::optional<Address> target;std::optional<BlockId> block;BlockEdgeKind kind;bool operator==(const BlockSuccessor&)const=default;};
struct BasicBlock {
    BlockId id;Address begin;std::vector<std::shared_ptr<const InstructionFact>> instructions;
    std::vector<BlockSuccessor> successors;std::optional<FunctionStop> stop;std::vector<FunctionId> owners;
    bool operator==(const BasicBlock&)const=default;
};
struct FunctionChunk {Address begin;std::uint64_t size;std::vector<BlockId> blocks;bool operator==(const FunctionChunk&)const=default;};
struct FunctionRecord {
    FunctionId id;Address entry;std::vector<FunctionChunk> chunks;std::vector<BlockId> blocks;
    std::vector<FunctionSeed> seeds;std::vector<FunctionStop> stops;bool complete=true;bool thunk=false;
    bool operator==(const FunctionRecord&)const=default;
};
struct ExternalIdentity {
    std::string library;
    std::optional<std::string> name;
    std::optional<std::uint16_t> ordinal;
    // WebAssembly imports use the exact module/name pair and function-space
    // index. This identity is symbolic and never denotes executable bytes.
    std::optional<std::uint32_t> wasm_function_index;
    std::optional<std::string> host_binding;
    bool operator==(const ExternalIdentity &) const = default;
};
struct FunctionCall {
    FunctionId owner;
    Address source;
    std::optional<Address> target;
    std::optional<FunctionId> callee;
    bool tail_candidate = false;
    std::optional<ExternalIdentity> external_target;
};
struct FunctionCandidate {Address entry;std::optional<Address> source;FunctionStopReason reason;std::string detail;};
enum class FunctionConflictKind {instruction_overlap,decision_overlap};
struct FunctionConflict {
    FunctionConflictKind kind;Address first,second;std::string detail;
    std::shared_ptr<const InstructionFact> first_fact,second_fact;
};
struct FunctionSnapshot {
    std::vector<std::shared_ptr<const FunctionRecord>> functions;
    std::vector<std::shared_ptr<const BasicBlock>> blocks;
    std::vector<std::shared_ptr<const InstructionFact>> instructions;
    std::vector<FunctionCall> calls;std::vector<FunctionCandidate> candidates;
    std::vector<FunctionConflict> conflicts;std::vector<FactDependency> dependencies;
    std::optional<AnalysisKey> key;bool complete=true;
    std::size_t omitted_functions=0,omitted_blocks=0;
};
HEXLAB_ANALYSIS_EXPORT Sha256Digest function_engine_fingerprint();
HEXLAB_ANALYSIS_EXPORT Sha256Digest function_engine_fingerprint(const AnalysisOptions&);
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const FunctionSnapshot>> recover_functions(const Image&,const ImageMetadata&,const AnalysisDecisions&,const AnalysisOptions&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const FunctionSnapshot>> recover_functions(const Image&,const ImageMetadata&,const AnalysisDecisions&,const AnalysisOptions&,const AnalysisKey&,std::stop_token);
}
