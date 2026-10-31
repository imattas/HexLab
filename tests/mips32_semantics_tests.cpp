#include "hexlab/processors/mips32_semantics.hpp"
#include "hexlab/processors/decoder.hpp"

#include <array>
#include <cassert>

using namespace hexlab;

int main() {
    const auto add = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::add,
        0x3f800000u, 0x40000000u, 0);
    assert(add && add->value_bits == 0x40400000u && add->exception_bits == 0 && add->writes_destination);

    const auto tied = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::add,
        0x3f800000u, 0x33800000u, 0);
    assert(tied && tied->value_bits == 0x3f800000u && tied->exception_bits == 1);
    const auto upward = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::add,
        0x3f800000u, 0x33800000u, 2);
    assert(upward && upward->value_bits == 0x3f800001u && upward->exception_bits == 1);

    const auto subtract = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::subtract,
        0x3f800000u, 0x3f800000u, 3);
    assert(subtract && subtract->value_bits == 0x80000000u && subtract->exception_bits == 0);
    const auto multiply = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::multiply,
        0x3fc00000u, 0x40000000u, 0);
    assert(multiply && multiply->value_bits == 0x40400000u && multiply->exception_bits == 0);

    const auto enabled_inexact = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::add,
        0x3f800000u, 0x33800000u, (1u << 7) | (1u << 2) | (0x1fu << 12));
    assert(enabled_inexact && enabled_inexact->exception_taken && !enabled_inexact->writes_destination &&
           enabled_inexact->exception_bits == 1 && (enabled_inexact->fcsr_after & (1u << 12)) != 0 &&
           (enabled_inexact->fcsr_after & (1u << 2)) != 0 &&
           (enabled_inexact->fcsr_after & (0x1eu << 12)) == 0);

    const auto flushed_output = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::multiply,
        0x00800000u, 0x3f000000u, 1u << 24);
    assert(flushed_output && flushed_output->value_bits == 0 &&
           flushed_output->exception_bits == ((1u << 0) | (1u << 1)));

    const auto unsupported_special = evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation::add,
        0x7f800000u, 0x3f800000u, 0);
    assert(!unsupported_special);

    const std::uint32_t add_s_word = (0x11u << 26) | (16u << 21) | (2u << 16) |
                                     (1u << 11) | (3u << 6);
    const std::array<std::byte, 4> add_s_bytes{
        static_cast<std::byte>(add_s_word), static_cast<std::byte>(add_s_word >> 8),
        static_cast<std::byte>(add_s_word >> 16), static_cast<std::byte>(add_s_word >> 24)};
    const auto decoded_add_s = decode_mips32(ByteOrder::little, add_s_bytes, Address{{0}, 0x1000});
    assert(decoded_add_s.instruction);
    const auto bound_add = evaluate_mips32_arithmetic_s_instruction(*decoded_add_s.instruction,
        0x3f800000u, 0x40000000u, 0);
    assert(bound_add && bound_add->value_bits == 0x40400000u);
    if (decoded_add_s.instruction) {
        auto malformed = *decoded_add_s.instruction;
        malformed.register_reads.pop_back();
        assert(!evaluate_mips32_arithmetic_s_instruction(malformed, 0x3f800000u, 0x40000000u, 0));
    }

    const auto signed_product = evaluate_mips32_hilo(Mips32HiLoOperation::mult, 0xffffffffu, 2);
    assert(signed_product && *signed_product == (Mips32HiLoResult{0xffffffffu, 0xfffffffeu}));

    const auto unsigned_product = evaluate_mips32_hilo(Mips32HiLoOperation::multu, 0xffffffffu, 2);
    assert(unsigned_product && *unsigned_product == (Mips32HiLoResult{1, 0xfffffffeu}));

    const auto signed_division = evaluate_mips32_hilo(Mips32HiLoOperation::div,
                                                       static_cast<std::uint32_t>(-7), 3);
    assert(signed_division && *signed_division == (Mips32HiLoResult{0xffffffffu, 0xfffffffeu}));

    const auto unsigned_division = evaluate_mips32_hilo(Mips32HiLoOperation::divu, 0xffffffffu, 10);
    assert(unsigned_division && *unsigned_division == (Mips32HiLoResult{5, 0x19999999u}));

    assert(!evaluate_mips32_hilo(Mips32HiLoOperation::div, 1, 0));
    assert(!evaluate_mips32_hilo(Mips32HiLoOperation::divu, 1, 0));
    assert(!evaluate_mips32_hilo(Mips32HiLoOperation::div, 0x80000000u, 0xffffffffu));
}
