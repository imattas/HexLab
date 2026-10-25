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

// Evaluate the scalar Zbb count operations from an XLEN-bit source value.
// Word forms are available only for RV64 and operate on the low 32 bits.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_riscv_zbb_count_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t value) noexcept;

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
};

struct RiscvVectorMemoryElementAccess {
    std::uint64_t lane = 0;
    std::uint64_t address = 0;
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
// preserved, and tail lanes are retained from the old destination.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorIntegerResult>
evaluate_riscv_vector_integer_operation(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                       const RiscvVectorIntegerOperands &operands);

// Plans active unit-stride or strided integer vector memory elements. The
// caller supplies the XLEN-width base/stride bit patterns and v0 predicate
// bytes when config.masked is true. Mixed EEW/SEW accesses are accepted only
// when their derived EMUL remains representable; address wrap is rejected.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                  std::uint64_t base, std::uint64_t stride_bits,
                                  std::uint8_t element_bits,
                                  std::span<const std::uint8_t> predicate_mask = {});

// Plans single-field indexed integer vector memory accesses. The data EEW is
// SEW from config; index_element_bits is the encoded index EEW. Index lanes are
// XLEN-width nonnegative byte offsets. This returns addresses only and rejects
// index registers with the wrong lane count or address wrap.
HEXLAB_PROCESSORS_EXPORT std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_indexed_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                          std::uint64_t base, std::uint8_t index_element_bits,
                                          std::span<const std::uint64_t> index_offsets,
                                          std::span<const std::uint8_t> predicate_mask = {});

} // namespace hexlab
