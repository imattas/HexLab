#include "hexlab/processors/mips32_semantics.hpp"

#include <bit>

namespace hexlab {

std::optional<Mips32HiLoResult> evaluate_mips32_hilo(Mips32HiLoOperation operation, std::uint32_t lhs,
                                                     std::uint32_t rhs) noexcept {
    switch (operation) {
    case Mips32HiLoOperation::mult: {
        const auto product = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lhs)) *
                             static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rhs));
        const auto bits = std::bit_cast<std::uint64_t>(product);
        return Mips32HiLoResult{static_cast<std::uint32_t>(bits >> 32), static_cast<std::uint32_t>(bits)};
    }
    case Mips32HiLoOperation::multu: {
        const auto product = static_cast<std::uint64_t>(lhs) * rhs;
        return Mips32HiLoResult{static_cast<std::uint32_t>(product >> 32), static_cast<std::uint32_t>(product)};
    }
    case Mips32HiLoOperation::div: {
        const auto dividend = std::bit_cast<std::int32_t>(lhs);
        const auto divisor = std::bit_cast<std::int32_t>(rhs);
        if (divisor == 0 || (dividend == INT32_MIN && divisor == -1))
            return {};
        const auto quotient = dividend / divisor;
        const auto remainder = dividend % divisor;
        return Mips32HiLoResult{std::bit_cast<std::uint32_t>(remainder), std::bit_cast<std::uint32_t>(quotient)};
    }
    case Mips32HiLoOperation::divu:
        if (!rhs)
            return {};
        return Mips32HiLoResult{lhs % rhs, lhs / rhs};
    }
    return {};
}

} // namespace hexlab
