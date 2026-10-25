#include "hexlab/processors/riscv_semantics.hpp"
#include "support/checks.hpp"
#include <array>
#include <cstdint>

using namespace hexlab;
using namespace hexlab_test;

namespace {
void multiply_tests() {
    check(evaluate_riscv_m_operation(RiscvOpcode::mul, 32, 0xffffffffu, 3) == 0xfffffffdu,
          "RV32 MUL keeps the low XLEN bits");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulh, 32, 0xffffffffu, 2) == 0xffffffffu,
          "RV32 MULH uses signed high product");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulhsu, 32, 0xffffffffu, 2) == 0xffffffffu,
          "RV32 MULHSU signs only its first operand");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulhu, 32, 0xffffffffu, 2) == 1u,
          "RV32 MULHU uses unsigned high product");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulh, 64, UINT64_MAX, 2) == UINT64_MAX,
          "RV64 MULH computes signed 128-bit product high half");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulhsu, 64, UINT64_MAX, 2) == UINT64_MAX,
          "RV64 MULHSU computes mixed-sign high half");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulhu, 64, UINT64_MAX, 2) == 1,
          "RV64 MULHU computes unsigned high half");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulhu, 64, 0xfedcba9876543210ull,
                                     0x123456789abcdef0ull) == 0x121fa00ad77d7422ull,
          "RV64 MULHU combines partial products across both 64-bit operands");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulh, 64, 0x8123456789abcdefull,
                                     0x9abcdef012345678ull) == 0x322e59c5556a0bc3ull,
          "RV64 MULH adjusts the high half for two signed operands");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulhsu, 64, 0x8123456789abcdefull,
                                     0x123456789abcdef0ull) == 0xf6fa8b3175e0fb55ull,
          "RV64 MULHSU adjusts only the signed operand contribution");
    check(evaluate_riscv_m_operation(RiscvOpcode::mulw, 64, 0x80000000, 1) == 0xffffffff80000000ull,
          "RV64 MULW sign extends the low 32-bit result");
}

void divide_remainder_tests() {
    check(evaluate_riscv_m_operation(RiscvOpcode::div, 32, 0xfffffff9u, 2) == 0xfffffffdu,
          "RV32 DIV truncates signed quotient toward zero");
    check(evaluate_riscv_m_operation(RiscvOpcode::divu, 32, 0xffffffffu, 2) == 0x7fffffffu,
          "RV32 DIVU uses unsigned operands");
    check(evaluate_riscv_m_operation(RiscvOpcode::rem, 32, 0xfffffff9u, 2) == 0xffffffffu,
          "RV32 REM keeps dividend sign");
    check(evaluate_riscv_m_operation(RiscvOpcode::remu, 32, 0xffffffffu, 2) == 1,
          "RV32 REMU computes unsigned remainder");
    check(evaluate_riscv_m_operation(RiscvOpcode::div, 64, 0x8000000000000000ull, UINT64_MAX) ==
              0x8000000000000000ull,
          "RV64 signed minimum divided by minus one returns signed minimum");
    check(evaluate_riscv_m_operation(RiscvOpcode::divu, 64, 7, 0) == UINT64_MAX,
          "RV64 unsigned divide by zero returns all ones");
    check(evaluate_riscv_m_operation(RiscvOpcode::div, 64, 7, 0) == UINT64_MAX,
          "RV64 signed divide by zero returns all ones");
    check(evaluate_riscv_m_operation(RiscvOpcode::rem, 64, UINT64_MAX, 0) == UINT64_MAX,
          "RV64 remainder by zero returns the dividend");
    check(evaluate_riscv_m_operation(RiscvOpcode::rem, 64, 0x8000000000000000ull, UINT64_MAX) == 0,
          "RV64 signed minimum remainder minus one is zero");
}

void word_tests() {
    check(evaluate_riscv_m_operation(RiscvOpcode::divw, 64, 0x80000000, UINT64_MAX) == 0xffffffff80000000ull,
          "DIVW applies 32-bit signed overflow result then sign extends");
    check(evaluate_riscv_m_operation(RiscvOpcode::divuw, 64, 0x80000000, 0) == 0xffffffffffffffffull,
          "DIVUW divide by zero returns sign-extended 32-bit all ones");
    check(evaluate_riscv_m_operation(RiscvOpcode::remw, 64, 0x80000000, UINT64_MAX) == 0,
          "REMW handles signed overflow without undefined division");
    check(evaluate_riscv_m_operation(RiscvOpcode::remuw, 64, 0x80000001, 0) == 0xffffffff80000001ull,
          "REMUW divide by zero returns sign-extended low word dividend");
    check(!evaluate_riscv_m_operation(RiscvOpcode::mulw, 32, 1, 2),
          "RV64 word operations are rejected for an RV32 semantic context");
    check(!evaluate_riscv_m_operation(RiscvOpcode::add, 64, 1, 2),
          "non-M instructions do not produce an M-operation result");
}

void rv32m_decode_tests() {
    const std::uint32_t mul = 0x027302b3; // mul x5, x6, x7
    const std::array bytes{static_cast<std::byte>(mul), static_cast<std::byte>(mul >> 8),
                           static_cast<std::byte>(mul >> 16), static_cast<std::byte>(mul >> 24)};
    const auto result = decode_riscv32(bytes, {{0}, 0x1000});
    check(result.status == DecodeStatus::decoded && result.instruction && result.instruction->opcode == RiscvOpcode::mul,
          "RV32IM decodes integer multiply with typed operands");
    check(result.instruction && result.instruction->register_reads == std::vector<RiscvRegister>{{6}, {7}} &&
              result.instruction->register_writes == std::vector<RiscvRegister>{{5}},
          "RV32IM multiply exposes register effects");
    const std::uint32_t mulw = 0x02b302bb;
    const std::array word_bytes{static_cast<std::byte>(mulw), static_cast<std::byte>(mulw >> 8),
                                static_cast<std::byte>(mulw >> 16), static_cast<std::byte>(mulw >> 24)};
    check(decode_riscv32(word_bytes, {{0}, 0x1000}).status == DecodeStatus::invalid,
          "RV32 rejects RV64 word M-extension operation");
}
}

int main() {
    return run([] {
        multiply_tests();
        divide_remainder_tests();
        word_tests();
        rv32m_decode_tests();
    });
}
