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
    signed_halfword_offset_from_table,
    thumb_scaled_pc_relative,
    signed_offset_from_target_base,
    unsigned_byte_offset_scaled_from_target_base,
    a32_branch_instruction,
    unsigned_dword_offset_from_target_base,
    signed_halfword_offset_from_target_base,
    // Targets and keys came from a validated decoded switch payload rather
    // than entries interpreted by this table scanner.
    decoded_metadata,
    signed_byte_offset_from_target_base
};

struct SwitchSite {
    Address dispatch{{0}, 0};
    Address table{{0}, 0};
    RegisterOperand selector{RegisterBank::gpr, 0, 0, false};
    std::uint8_t scale = 0;
    SwitchEntryEncoding entry_encoding = SwitchEntryEncoding::absolute_pointer;
    // Present when encoded offsets use a separately materialized code base
    // instead of the table address (including unsigned dword RVA tables).
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
    enum class TableBaseSource { encoded_bytes, elf_relocation_pair, operand_relocation } table_base_source =
        TableBaseSource::encoded_bytes;
    // Metadata row indices in instruction order when a matched pair or exact
    // base-definition operand relocation established the table address.
    std::vector<std::uint64_t> table_base_relocation_rows;
    // Optional exact instruction provenance for a proven register-held base
    // and the indexed instruction consuming the selector.
    std::optional<Address> base_definition;
    std::optional<Address> selector_use;
    bool operator==(const SwitchSite &) const = default;
};

struct SwitchAnalysis {
    std::vector<SwitchSite> sites;
    bool complete = true;
};

// Recovers bounded x86, AArch64, Thumb, A32, MIPS32/MIPS64, and PPC32 jump tables from recognized
// indexed indirect dispatch forms. A32 LDR-PC tables require aligned ARM-mode
// targets; mixed ARM/Thumb interworking slots are not represented. x86 supports
// statically based indexed indirect JMPs and the contiguous x86-64 LEA
// (RIP-relative table base), MOVSXD
// ([base + index*4]), ADD (loaded value + table base), JMP (loaded register)
// sequence. The LEA may be earlier in the same basic block when its value has
// no intervening writes, calls, unknown facts, or control-flow changes. The
// latter interprets signed 32-bit entries relative to the table base. The
// x86-64 MOV to a 32-bit GPR followed by ADD to its 64-bit alias and JMP
// also supports unsigned dword offsets from the proven LEA base. Its table
// may use a checked displacement from that base. Relocation/fixup-associated
// dword slots remain unsupported for this unsigned encoding.
// An adjacent CMP of the exact selector and JA/JAE may prove an unsigned
// case count (including one-case tables) and supply a default target. x86
// also recognizes a signed lower/upper CMP guard pair with a shared default
// and exact in-place subtraction of the lower bound before indexing; its
// inclusive span supplies the count. The
// in-range edge may reach setup through a bounded acyclic CFG region when
// every known incoming path preserves the selector and passes that edge.
// Calls, unknown effects, alternate entries, bypasses, and cyclic proof
// regions cannot establish a cross-block bound. Guard graph construction and
// proof work share budgets across all dispatch sites in one invocation.
// RV32 and RV64 also recognize the XLEN-scaled SLLI/ADD/LW-or-LD/JALR
// absolute-pointer form when a nearby AUIPC[/ADDI] or LUI[/ADDI] definition
// resolves the table base. Its contiguous
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
// Thumb TBB/TBH keeps the post-instruction table address distinct from the
// word-aligned architectural PC target base when the dispatch is at 2 mod 4.
// MIPS32/64 recognize same-block indexed absolute tables; their signed-relative
// forms require a proven constant code base and four-byte entries. PPC32
// recognizes four-byte absolute tables and signed-relative four-byte entries,
// plus signed-relative halfword entries loaded with LHAX. Guarded tables report
// exact counts/defaults; without a proven guard, only a validated executable-
// entry prefix is returned and marked incomplete.
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
