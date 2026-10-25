#pragma once

#include "hexlab/analysis/functions.hpp"
#include "hexlab/image/metadata.hpp"

#include <optional>

namespace hexlab {

struct SwitchCase {
    std::uint32_t index = 0;
    Address target{{0}, 0};
    enum class TargetSource { encoded_bytes, elf_relocation, macho_relocation, macho_dyld_rebase } source =
        TargetSource::encoded_bytes;
    std::vector<std::uint64_t> relocation_rows;
    std::vector<std::uint64_t> dyld_classic_rows;
    std::vector<std::uint64_t> dyld_chained_rows;
    bool operator==(const SwitchCase &) const = default;
};

enum class SwitchEntryEncoding {
    absolute_pointer,
    signed_offset_from_table,
    thumb_scaled_pc_relative
};

struct SwitchSite {
    Address dispatch{{0}, 0};
    Address table{{0}, 0};
    RegisterOperand selector{RegisterBank::gpr, 0, 0, false};
    std::uint8_t scale = 0;
    SwitchEntryEncoding entry_encoding = SwitchEntryEncoding::absolute_pointer;
    std::vector<SwitchCase> cases;
    // Present only when an unsigned compare/branch proves a case count and
    // default destination for the dispatch. Counts are in [1, 4096]; cases may
    // contain a shorter verified prefix when complete is false.
    std::optional<std::uint32_t> case_count;
    std::optional<Address> default_target;
    // False means the table ended at an invalid/unreadable value or the scan
    // reached its hard entry limit; the recovered prefix remains usable.
    bool complete = true;
    bool operator==(const SwitchSite &) const = default;
};

struct SwitchAnalysis {
    std::vector<SwitchSite> sites;
    bool complete = true;
};

// Recovers bounded x86 and AArch64 jump tables from statically based indexed indirect
// JMP, or the contiguous x86-64 LEA (RIP-relative table base), MOVSXD
// ([base + index*4]), ADD (loaded value + table base), JMP (loaded register)
// sequence. The LEA may be earlier in the same basic block when its value has
// no intervening writes, calls, unknown facts, or control-flow changes. The
// latter interprets signed 32-bit entries relative to the table base. An
// adjacent CMP of the exact selector and JA/JAE may prove an unsigned
// case count (including one-case tables) and supply a default target. The
// in-range edge may reach setup through a bounded acyclic CFG region when
// every known incoming path preserves the selector and passes that edge.
// Calls, unknown effects, alternate entries, bypasses, and cyclic proof
// regions cannot establish a cross-block bound. Guard graph construction and
// proof work share budgets across all dispatch sites in one invocation.
// RV64 also recognizes the contiguous SLLI/ADD/LD/JALR absolute-pointer form
// when a nearby AUIPC[/ADDI] definition resolves the table base. The selector
// scale is fixed to eight bytes; arbitrary register-value propagation and
// relative-offset RV64 tables remain unsupported. AArch64 also recognizes
// contiguous ADR/LDR/BR and ADRP/ADD/LDR/BR sequences
// when ADR/ADRP and ADD resolve the table base and LDR indexes 64-bit absolute
// pointers with a 64-bit register shifted by three. Every form reads
// at most 4096 entries. Targets must decode as instructions in executable,
// file-backed image bytes. Recovery is limited to recognized instruction
// patterns; it does not propagate arbitrary register values. For ELF
// relocatable objects, the signed-offset AArch64 form may resolve an otherwise
// unknown ADRP/ADD table base only from a matched explicit-addend relocation
// pair to a defined local symbol.
HEXLAB_ANALYSIS_EXPORT Result<SwitchAnalysis>
analyze_switch_tables(const Image &, const FunctionRecord &, const FunctionSnapshot &, std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<SwitchAnalysis>
analyze_switch_tables(const Image &, const ImageMetadata &, const FunctionRecord &, const FunctionSnapshot &,
                      std::stop_token);
class RelocationResolver;
HEXLAB_ANALYSIS_EXPORT Result<SwitchAnalysis>
analyze_switch_tables(const Image &, const RelocationResolver &, const FunctionRecord &, const FunctionSnapshot &,
                      std::stop_token);

} // namespace hexlab
