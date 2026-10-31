#pragma once
#include "hexlab/analysis/strings.hpp"
#include "hexlab/processors/decoder.hpp"

namespace hexlab {
enum class StopReason { ret, trap, unsupported, invalid, truncated, unmapped, non_executable, uninitialized, indirect, budget, target_overflow, no_entry, elf_relocation, macho_relocation, macho_dyld, image_exclusion };
struct AnalysisStop {Address address;StopReason reason;std::string detail;};
enum class EdgeKind { fallthrough, branch, call, unresolved_call, unresolved_jump, delay_slot, conditional_call };
struct CodeEdge {Address from;std::optional<Address> to;EdgeKind kind;};
struct AnalysisSnapshot {
    std::vector<Instruction> instructions;
    std::vector<CodeEdge> edges;
    std::vector<AnalysisStop> stops;
    std::vector<Diagnostic> diagnostics;
    std::vector<Address> candidates;
    StringScan strings;
    bool code_complete=true,complete=true;
};
HEXLAB_ANALYSIS_EXPORT Result<AnalysisSnapshot> analyze(const Image&,const AnalysisOptions&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<AnalysisSnapshot> analyze(const Image&,const ImageMetadata&,const AnalysisOptions&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<DecodeResult> decode_at(const Image&,Address);
HEXLAB_ANALYSIS_EXPORT Result<DecodeResult> decode_analysis_instruction(
    DecodeContext, std::span<const std::byte>, Address, const AnalysisOptions&);
}
