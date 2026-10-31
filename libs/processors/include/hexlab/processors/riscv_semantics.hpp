#pragma once

#include "hexlab/processors/riscv.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace hexlab {

// Evaluate one RV32M or RV64M integer operation from its source-register bit
// patterns. The result is the architectural destination-register bit pattern.
// RV64 word operations return the sign-extended 32-bit result. Non-M opcodes
// and operations unavailable at the requested XLEN return no value.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_m_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs, std::uint64_t rhs) noexcept;

struct RiscvAmoResult {
    std::uint64_t rd_value = 0;
    std::uint64_t memory_value = 0;
    std::uint8_t memory_width = 32;
    bool writes_rd = false;
    bool operator==(const RiscvAmoResult &) const = default;
};

// Evaluate decoded AMO.W/AMO.D using caller-supplied old memory and rs2 bits.
// RV64 AMO.W sign-extends the old word into rd; aq/rl are retained as decoded
// metadata and do not alter this single-operation value calculation.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvAmoResult>
evaluate_riscv_amo_instruction(const RiscvInstruction &instruction, unsigned xlen,
                               std::uint64_t old_memory, std::uint64_t source_value) noexcept;

struct RiscvCsrResult {
    std::uint64_t rd_value = 0;
    std::uint64_t csr_value = 0;
    bool writes_rd = false;
    bool writes_csr = false;
    bool operator==(const RiscvCsrResult &) const = default;
};

// Evaluate decoded Zicsr register/immediate read, write, set, and clear
// operations. The caller supplies the old CSR value and register-source bits.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvCsrResult>
evaluate_riscv_csr_instruction(const RiscvInstruction &instruction, unsigned xlen,
                               std::uint64_t old_csr, std::uint64_t source_value) noexcept;

enum class RiscvPrivilegeMode : std::uint8_t { user = 0, supervisor = 1, hypervisor = 2, machine = 3 };

struct RiscvCsrPrivilegeCheck {
    RiscvPrivilegeMode minimum_privilege = RiscvPrivilegeMode::user;
    bool permitted = false;
    bool operator==(const RiscvCsrPrivilegeCheck &) const = default;
};

// Apply the CSR-address minimum-privilege convention to a validated Zicsr
// instruction. This does not check CSR existence or extension availability.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvCsrPrivilegeCheck>
check_riscv_csr_privilege(const RiscvInstruction &instruction, unsigned xlen,
                          RiscvPrivilegeMode current_privilege) noexcept;

// The user floating-point control/status state uses the low five accrued
// exception bits and the three-bit dynamic rounding mode. Values 5..7 are
// retained because software may write reserved frm encodings; consumers must
// reject them when an instruction actually requests dynamic rounding.
struct RiscvFcsrState {
    std::uint8_t fflags = 0;
    std::uint8_t frm = 0;
    bool operator==(const RiscvFcsrState &) const = default;
};

struct RiscvFcsrResult {
    std::uint64_t rd_value = 0;
    RiscvFcsrState state{};
    bool writes_rd = false;
    bool writes_state = false;
    bool operator==(const RiscvFcsrResult &) const = default;
};

// Evaluate decoded Zicsr operations against the standard fflags (0x001), frm
// (0x002), and fcsr (0x003) aliases. Reserved high bits are read as zero and
// ignored on writes. This models the register values only; privilege, extension
// enablement, and trap delivery remain caller responsibilities.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFcsrResult>
evaluate_riscv_fcsr_instruction(const RiscvInstruction &instruction, unsigned xlen,
                                RiscvFcsrState state, std::uint64_t source_value) noexcept;

// Merge exception flags from one completed operation into accrued fflags.
// Returns empty if either state or input contains bits outside the five
// architectural exception flags.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFcsrState>
accrue_riscv_fflags(RiscvFcsrState state, std::uint8_t raised_flags) noexcept;

// Resolve an instruction's encoded rounding field. Static modes 0..4 are
// returned directly; encoded mode 7 reads frm and succeeds only when frm is
// 0..4. Reserved encodings and inconsistent decoder metadata return empty.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint8_t>
resolve_riscv_rounding_mode(const RiscvInstruction &instruction,
                            std::uint8_t frm) noexcept;

// Read and write a binary32 value in an architectural FPR. FLEN=64 requires
// NaN-boxed upper bits on read (otherwise the value is canonical qNaN) and
// writes all-one upper bits; FLEN=32 uses the low word directly.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
read_riscv_f32_register_value(unsigned flen, std::uint64_t register_bits) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
write_riscv_f32_register_value(unsigned flen, std::uint64_t binary32_bits) noexcept;

// Evaluate RV32/RV64 integer branch predicates from raw GPR values. The
// instruction adapter validates decoded branch operands and treats x0 as zero.
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_riscv_branch_predicate(RiscvOpcode opcode, unsigned xlen,
                                std::uint64_t lhs, std::uint64_t rhs) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_riscv_branch_predicate_instruction(const RiscvInstruction &instruction, unsigned xlen,
                                            std::uint64_t lhs, std::uint64_t rhs) noexcept;

struct RiscvIndirectJumpResult {
    std::uint64_t target = 0;
    std::uint64_t link_value = 0;
    bool writes_link = false;
    bool operator==(const RiscvIndirectJumpResult &) const = default;
};

// Evaluate decoded JALR/c.JR/c.JALR target and PC link value. XLEN is supplied
// by the caller; target bit zero is cleared as required by JALR.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvIndirectJumpResult>
evaluate_riscv_jalr_instruction(const RiscvInstruction &instruction, unsigned xlen,
                                std::uint64_t base_value) noexcept;

struct RiscvUpperImmediateResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool writes_destination = false;
    bool operator==(const RiscvUpperImmediateResult &) const = default;
};

// Evaluate LUI/AUIPC and decoded compressed C.LUI. AUIPC uses the instruction
// address as PC; all arithmetic wraps at the requested XLEN.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvUpperImmediateResult>
evaluate_riscv_upper_immediate_instruction(const RiscvInstruction &instruction,
                                           unsigned xlen) noexcept;

// Classify the raw IEEE binary32/binary64 bit pattern for FCLASS.S/FCLASS.D.
// The one-hot result uses RISC-V's ten category bits (negative infinity
// through quiet NaN); no host floating-point operations or FFLAGS are used.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint16_t>
evaluate_riscv_fclass(RiscvOpcode opcode, std::uint64_t value) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint16_t>
evaluate_riscv_fclass_instruction(const RiscvInstruction &instruction,
                                  std::uint64_t value) noexcept;

// Evaluate scalar FSGNJ.S/D, FSGNJN.S/D, and FSGNJX.S/D on raw IEEE bit
// patterns. These bitwise operations do not interpret NaNs or raise flags.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_fsgnj_operation(RiscvOpcode opcode, std::uint64_t lhs,
                               std::uint64_t rhs) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_fsgnj_instruction(const RiscvInstruction &instruction,
                                 std::uint64_t lhs, std::uint64_t rhs) noexcept;

struct RiscvFloatMinMaxResult {
    std::uint64_t value = 0;
    std::uint8_t fflags_set = 0;
    bool operator==(const RiscvFloatMinMaxResult &) const = default;
};

// Evaluate scalar FMIN/FMAX.S/D on raw IEEE bits; fflags_set uses RISC-V
// order NX/UF/OF/DZ/NV and reports Invalid for signaling NaNs.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFloatMinMaxResult>
evaluate_riscv_float_min_max(RiscvOpcode opcode, std::uint64_t lhs,
                             std::uint64_t rhs) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFloatMinMaxResult>
evaluate_riscv_float_min_max_instruction(const RiscvInstruction &instruction,
                                         std::uint64_t lhs,
                                         std::uint64_t rhs) noexcept;

struct RiscvFloatCompareResult {
    std::uint64_t rd_value = 0; // Integer destination receives 0 or 1.
    std::uint8_t fflags_set = 0; // NV is bit 4; no other exception is raised.
    bool operator==(const RiscvFloatCompareResult &) const = default;
};

// Evaluate scalar FEQ/FLT/FLE.S/D on raw IEEE bit patterns. FEQ raises NV
// only for signaling NaNs; ordered comparisons raise NV for any NaN.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFloatCompareResult>
evaluate_riscv_float_compare(RiscvOpcode opcode, std::uint64_t lhs,
                             std::uint64_t rhs) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFloatCompareResult>
evaluate_riscv_float_compare_instruction(const RiscvInstruction &instruction,
                                         std::uint64_t lhs,
                                         std::uint64_t rhs) noexcept;

struct RiscvBitMoveResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool operator==(const RiscvBitMoveResult &) const = default;
};

// Evaluate scalar FMV.W.X/FMV.X.W and the RV64 D-width transfers as raw bits.
// The W-to-FPR form returns a NaN-boxed 64-bit register value.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvBitMoveResult>
evaluate_riscv_fmv_instruction(const RiscvInstruction &instruction,
                              unsigned xlen_bits, std::uint64_t source_bits) noexcept;

// Evaluate the scalar Zbb count operations from an XLEN-bit source value.
// Word forms are available only for RV64 and operate on the low 32 bits.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zbb_count_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t value) noexcept;

// Evaluate the remaining scalar Zbb logical, min/max, rotate, extension and
// byte-oriented operations. RV64 word rotates return sign-extended words.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zbb_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                             std::uint64_t rhs = 0) noexcept;

// Evaluate the scalar Zba address-generation instructions. RV32 supports the
// XLEN-width sh1add/sh2add/sh3add forms; RV64 additionally supports the
// unsigned-word forms and slli.uw.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zba_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                             std::uint64_t rhs) noexcept;

// Evaluate scalar Zbs single-bit operations. The index is masked to XLEN for
// register forms; immediate forms are already range-checked by the decoder.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zbs_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                             std::uint64_t bit_index) noexcept;

// Evaluate scalar Zbkb PACK/PACKH/PACKW operations on raw XLEN-bit values.
// PACKW is RV64-only and sign-extends its packed 32-bit result.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zbkb_pack_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                                  std::uint64_t rhs) noexcept;

// Evaluate the RV32/RV64 Zbc carry-less multiplication operations on raw
// register bit patterns. High and reversed forms select the architectural
// upper and middle XLEN-bit windows of the polynomial product.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zbc_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                             std::uint64_t rhs) noexcept;

// Evaluate the Zicond czero.eqz/czero.nez operations on RV32 or RV64 raw
// register bit patterns. Both operands are interpreted as XLEN-bit values.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zicond_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t value,
                                std::uint64_t condition) noexcept;

struct RiscvIntegerConversionResult {
    std::uint64_t value = 0; // destination-register bits; word results are sign-extended.
    std::uint8_t fflags_set = 0; // accrued exception bits: NX=1, UF=2, OF=4, DZ=8, NV=16.
};

// Evaluate Zfa FCVTMOD.W.D from raw IEEE-754 binary64 bits. The conversion
// truncates toward zero, takes the low 32 bits of the unbounded signed result,
// then sign-extends it. Non-finite inputs map to zero. Only RV32/RV64 are valid.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvIntegerConversionResult>
evaluate_riscv_fcvtmod_w_d(std::uint64_t source_bits, unsigned xlen) noexcept;

struct RiscvFloatingRoundResult {
    std::uint64_t value = 0; // raw binary32/binary64 destination bits.
    std::uint8_t fflags_set = 0; // accrued exception bits: NX=1, UF=2, OF=4, DZ=8, NV=16.
};

// Evaluate Zfa FROUND.S/D or FROUNDNX.S/D from raw IEEE-754 bits. The caller
// supplies the effective rounding mode after resolving dynamic frm; supported
// modes are RNE/RTZ/RDN/RUP/RMM (0..4). FROUNDNX additionally accrues NX when
// the input has a fractional part. Signaling NaNs are quieted and accrue NV.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvFloatingRoundResult>
evaluate_riscv_fround_operation(RiscvOpcode opcode, std::uint64_t source_bits,
                                std::uint8_t rounding_mode) noexcept;

struct RiscvVectorIntegerConfig {
    std::uint16_t vlen_bits = 128;
    std::uint8_t sew_bits = 8;
    std::int8_t lmul_log2 = 0; // -3 is mf8; +3 is m8.
    std::uint8_t xlen_bits = 64;
    std::uint64_t vl = 0;
    std::uint64_t vstart = 0;
    bool masked = false;
};

struct RiscvVectorConfigurationState {
    std::uint64_t vl = 0;
    std::uint64_t vtype = 0;
    std::uint64_t vstart = 0;
    bool vill = false;
    std::optional<std::uint8_t> sew_bits;
    std::optional<std::int8_t> lmul_log2;
    bool tail_agnostic = false;
    bool mask_agnostic = false;
};

struct RiscvVectorIntegerOperands {
    std::span<const std::uint64_t> vs2;
    std::span<const std::uint64_t> vs1;
    std::uint64_t scalar = 0;
    std::int64_t immediate = 0;
    std::span<const std::uint8_t> predicate_mask; // one byte per lane, zero/one
    std::span<const std::uint64_t> old_destination;
};

struct RiscvVectorIntegerResult {
    std::vector<std::uint64_t> lanes; // compare results are 0/1 mask bits
    std::uint64_t vlmax = 0;
    bool mask_result = false;
    std::uint8_t element_bits = 0; // 1 for masks, SEW for ordinary results, 2*SEW for widening.
};

// Floating vector operands are raw IEEE-754 element bit patterns. For `.vf`,
// scalar is the low SEW bits of the source F register after any XLEN-specific
// NaN unboxing performed by the caller.
struct RiscvVectorFloatingOperands {
    std::span<const std::uint64_t> vs2;
    std::span<const std::uint64_t> vs1;
    std::uint64_t scalar = 0;
    std::span<const std::uint8_t> predicate_mask;
    std::span<const std::uint64_t> old_destination;
    // Required for vfrec7 overflow cases; reserved values 5..7 are rejected.
    std::optional<std::uint8_t> frm;
};

struct RiscvVectorFloatingResult {
    std::vector<std::uint64_t> lanes; // compare results are 0/1 mask bits
    std::uint64_t vlmax = 0;
    bool mask_result = false;
    std::uint8_t element_bits = 0; // 1 for masks, SEW for vector values.
    std::uint8_t fflags_set = 0; // accrued IEEE exception bits: NX=1, UF=2, OF=4, DZ=8, NV=16.
};

struct RiscvVectorMemoryElementAccess {
    std::uint64_t lane = 0;
    std::uint64_t address = 0;
    std::uint8_t field = 0;
    bool operator==(const RiscvVectorMemoryElementAccess &) const = default;
};

struct RiscvVectorMemoryAccessPlan {
    std::uint64_t vlmax = 0;
    std::uint8_t element_bits = 0;
    std::uint8_t index_element_bits = 0;
    bool load = false;
    bool ordered = false;
    std::vector<RiscvVectorMemoryElementAccess> active_elements;
};

// Resolves the architectural vtype encoding using the caller's implementation
// VLEN and live vl/vstart values. Unsupported SEW/LMUL or vill returns empty.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorIntegerConfig>
make_riscv_vector_integer_config(std::uint16_t vlen_bits, std::uint8_t xlen_bits,
                                 std::uint64_t vl, std::uint64_t vstart,
                                 std::uint64_t encoded_vtype, bool masked);

// Evaluates one decoded vsetvli/vsetivli/vsetvl using caller-supplied source
// GPR values, implementation VLEN, and prior VL. Invalid vtype settings
// produce the architectural vill state, VL=0, and VSTART=0. Source values for
// x[rs1]/x[rs2] are ignored by forms that do not read those registers.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorConfigurationState>
evaluate_riscv_vector_configuration(const RiscvInstruction &instruction,
                                   std::uint8_t xlen_bits, std::uint16_t vlen_bits,
                                   std::uint64_t rs1_value, std::uint64_t rs2_value,
                                   std::uint64_t current_vl);

// Evaluates one RVV integer elementwise or gather/slide operation over the
// configured lane group. Input and old-destination spans must contain VLMAX
// elements. The evaluator models vstart, vl, and v0 masking; inactive, slide-up
// preserved, and tail lanes are retained from the old destination. Integer
// reductions use vs1[0] as their initial accumulator, skip masked-off lanes,
// and require vstart=0. Widening sums return double-SEW results and are
// supported through SEW=32 (64-to-128-bit results are not representable).
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorIntegerResult>
evaluate_riscv_vector_integer_operation(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                       const RiscvVectorIntegerOperands &operands);

// Evaluates bit-exact RVV reciprocal estimates, floating classification, sign
// injection, min/max, comparisons, reductions, and ordered/unordered sums for
// SEW=32 or 64. vfrec7 and both sum reductions require operands.frm to supply
// a valid rounding mode (0..4). fflags_set contains exception bits raised by
// active lanes only; callers merge these into fflags.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorFloatingResult>
evaluate_riscv_vector_floating_operation(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                         const RiscvVectorFloatingOperands &operands);

// Plans active unit-stride or strided integer vector memory elements, including
// segmented fields. The
// caller supplies the XLEN-width base/stride bit patterns and v0 predicate
// bytes when config.masked is true. Mixed EEW/SEW accesses are accepted only
// when their derived EMUL remains representable and NF*EMUL <= 8; address wrap
// is rejected. Returned entries are ordered by lane then field.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                  std::uint64_t base, std::uint64_t stride_bits,
                                  std::uint8_t element_bits,
                                  std::span<const std::uint8_t> predicate_mask = {});
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                  std::uint64_t base, std::uint64_t stride_bits,
                                  std::uint8_t element_bits,
                                  std::span<const std::uint8_t> predicate_mask,
                                  std::uint8_t segment_fields);

// Plans indexed integer vector memory accesses, including segmented fields. The data EEW is
// SEW from config; index_element_bits is the encoded index EEW. Index lanes are
// XLEN-width nonnegative byte offsets. This returns addresses only and rejects
// index registers with the wrong lane count, invalid segment EMUL, or address
// wrap. Returned entries are ordered by lane then field.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_indexed_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                          std::uint64_t base, std::uint8_t index_element_bits,
                                          std::span<const std::uint64_t> index_offsets,
                                          std::span<const std::uint8_t> predicate_mask = {});
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_indexed_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                          std::uint64_t base, std::uint8_t index_element_bits,
                                          std::span<const std::uint64_t> index_offsets,
                                          std::span<const std::uint8_t> predicate_mask,
                                          std::uint8_t segment_fields);

} // namespace hexlab
