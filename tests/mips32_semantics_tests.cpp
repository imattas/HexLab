#include "hexlab/processors/mips32_semantics.hpp"

#include <cassert>

using namespace hexlab;

int main() {
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
