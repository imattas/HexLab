#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

enum class Mips32HiLoOperation { mult, multu, div, divu };

struct Mips32HiLoResult {
    std::uint32_t hi = 0;
    std::uint32_t lo = 0;
    bool operator==(const Mips32HiLoResult &) const = default;
};

// Evaluate one MIPS32 MULT/MULTU/DIV/DIVU operation from GPR bit patterns.
// Division by zero and signed quotient overflow return no result because the
// architecture leaves those HI/LO values unpredictable/undefined.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32HiLoResult>
evaluate_mips32_hilo(Mips32HiLoOperation operation, std::uint32_t lhs, std::uint32_t rhs) noexcept;

} // namespace hexlab
