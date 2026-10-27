#pragma once

#include "hexlab/analysis/functions.hpp"
#include "hexlab/image/metadata.hpp"

#include <optional>
#include <string>

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
    thumb_scaled_pc_relative,
    signed_offset_from_target_base,
    unsigned_byte_offset_scaled_from_target_base
};

struct SwitchSite {
    Address dispatch{{0}, 0};
    Address table{{0}, 0};
    RegisterOperand selector{RegisterBank::gpr, 0, 0, false};
    std::uint8_t scale = 0;
    SwitchEntryEncoding entry_encoding = SwitchEntryEncoding::absolute_pointer;
    // Present when the encoded signed displacement uses a separately
    // materialized code base instead of the table address.
    std::optional<Address> target_base;
    std::vector<SwitchCase> cases;
    // Present only when an unsigned compare/branch proves a case count and
    // default destination for the dispatch. Counts are in [1, 4096]; cases may
    // contain a shorter verified prefix when complete is false.
    std::optional<std::uint32_t> case_count;
    std::optional<Address> default_target;
    // False means the table ended at an invalid/unreadable value or the scan
    // reached its hard entry limit; the recovered prefix remains usable.
    bool complete = true;
    std::optional<std::string> incomplete_reason;
    // Setup provenance is distinct from per-case pointer-slot relocations.
    enum class TableBaseSource { encoded_bytes, elf_relocation_pair } table_base_source =
        TableBaseSource::encoded_bytes;
    // ELF metadata row indices in ADRP/ADD instruction order. Present only
    // when the exact matched pair established the table address.
    std::vector<std::uint64_t> table_base_relocation_rows;
    bool operator==(const SwitchSite &) const = default;
};

struct SwitchAnalysis {
    std::vector<SwitchSite> sites;
    bool complete = true;
};

// Recovers bounded x86, AArch64, Thumb, and A32 jump tables from recognized
// indexed indirect dispatch forms. A32 LDR-PC tables require aligned ARM-mode
// targets; mixed ARM/Thumb interworking slots are not represented. x86 supports
// statically based indexed indirect JMPs and the contiguous x86-64 LEA
// (RIP-relative table base), MOVSXD
// ([base + index*4]), ADD (loaded value + table base), JMP (loaded register)
// sequence. The LEA may be earlier in the same basic block when its value has
// no intervening writes, calls, unknown facts, or control-flow changes. The
// latter interprets signed 32-bit entries relative to the table base. An
// adjacent CMP of the exact selector and JA/JAE may prove an unsigned
// case count (including one-case tables) and supply a default target. x86
// also recognizes a signed lower/upper CMP guard pair with a shared default
// and exact in-place subtraction of the lower bound before indexing; its
// inclusive span supplies the count. The
// in-range edge may reach setup through a bounded acyclic CFG region when
// every known incoming path preserves the selector and passes that edge.
// Calls, unknown effects, alternate entries, bypasses, and cyclic proof
// regions cannot establish a cross-block bound. Guard graph construction and
// proof work share budgets across all dispatch sites in one invocation.
// RV64 also recognizes the SLLI/ADD/LD/JALR absolute-pointer form when a
// nearby AUIPC[/ADDI] definition resolves the table base. Its contiguous
// AUIPC[/ADDI]/SLLI/ADD/LW/ADD/JALR form resolves signed 32-bit offsets
// relative to the table base. A proven adjacent SLTIU/BEQ guard can bound
// either table; arbitrary register-value propagation remains unsupported.
// AArch64 also recognizes contiguous ADR/LDR/BR and ADRP/ADD/LDR/BR
// absolute-pointer sequences, and a contiguous LDRSW/ADR/ADD/BR form in
// which signed entries use a separately resolved code base.
// ADR/ADRP and ADD resolve the table base and LDR indexes 64-bit absolute
// pointers with a 64-bit register shifted by three. Every form reads
// at most 4096 entries. Targets must decode as instructions in executable,
// file-backed image bytes. Recovery is limited to recognized instruction
// patterns; it does not propagate arbitrary register values. For ELF
// relocatable objects, the absolute-pointer and signed-offset AArch64 forms may resolve an otherwise
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
