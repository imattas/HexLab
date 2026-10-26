#pragma once
#include "hexlab/analysis/analysis.hpp"
#include "hexlab/analysis/decisions.hpp"
#include "hexlab/analysis/dependencies.hpp"
namespace hexlab {
struct FunctionId {std::uint64_t value;auto operator<=>(const FunctionId&)const=default;};
struct BlockId {std::uint64_t value;auto operator<=>(const BlockId&)const=default;};
enum class FunctionSeedKind {entry,export_symbol,direct_call,user_function,user_code,symbol,unwind,arm_context_root,tls_callback,initializer,guard_cf,dex_method};
struct FunctionSeedUnwindEvidence {std::uint32_t section=0;std::uint64_t file_offset=0,record_size=0;bool operator==(const FunctionSeedUnwindEvidence&)const=default;};
enum class FunctionInitializerSource : std::uint8_t { elf_init, elf_fini, elf_preinit_array, elf_init_array, elf_fini_array, macho_mod_init_func, macho_routines };
struct FunctionSeedInitializerEvidence {
    FunctionInitializerSource source = FunctionInitializerSource::elf_init_array;
    std::optional<std::uint32_t> section;
    std::optional<std::uint64_t> index, file_offset;
    std::optional<std::int64_t> dynamic_tag;
    std::vector<std::uint64_t> relocation_rows, dyld_classic_rows, dyld_chained_rows;
    bool operator==(const FunctionSeedInitializerEvidence &) const = default;
};
struct FunctionSeed {FunctionSeedKind kind;Address entry;std::optional<Address> source;std::optional<std::uint64_t> decision;std::optional<FunctionSeedUnwindEvidence> unwind_evidence;std::optional<FunctionSeedInitializerEvidence> initializer_evidence;bool operator==(const FunctionSeed&)const=default;};
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
struct FunctionCall {FunctionId owner;Address source;std::optional<Address> target;std::optional<FunctionId> callee;bool tail_candidate=false;};
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
