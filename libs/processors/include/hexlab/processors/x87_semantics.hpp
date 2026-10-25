#pragma once

#include "hexlab/processors/processors_export.hpp"

#include <cstdint>
#include <optional>

namespace hexlab {

// Canonical x87 80-bit extended value fields. The explicit integer bit is
// bit 63 of significand; exponent is the raw 15-bit biased field.
struct X87Binary80 {
    std::uint64_t significand = 0;
    std::uint16_t sign_exponent = 0;
    bool operator==(const X87Binary80 &) const = default;
};

enum class X87Relation : std::uint8_t { less, equal, greater, unordered };
enum class X87CompareKind : std::uint8_t { fcom, fucom, fcomi, fucomi };

struct X87CompareRequest {
    X87Binary80 left, right;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
    std::uint32_t eflags = 0;
    X87CompareKind kind = X87CompareKind::fcom;
};

struct X87CompareResult {
    X87Relation relation = X87Relation::unordered;
    std::uint16_t status_word = 0;
    std::optional<std::uint32_t> eflags;
    // False means an unmasked invalid-operation exception prevents the
    // comparison condition outputs and any instruction stack pop from retiring.
    bool completed = true;
    bool invalid_operation = false;
    bool operator==(const X87CompareResult &) const = default;
};

// Compare canonical 80-bit operands exactly without relying on host floating
// point. Noncanonical unnormal/pseudo-special encodings return no result.
HEXLAB_PROCESSORS_EXPORT std::optional<X87Relation> compare_x87_binary80(X87Binary80 left,
                                                                       X87Binary80 right) noexcept;

// Evaluate FCOM/FUCOM and FCOMI/FUCOMI condition effects. FCOM variants are
// ordered; FUCOM variants raise invalid only for signaling NaNs. The caller
// remains responsible for x87 stack tags/TOP and instruction-specific pops.
HEXLAB_PROCESSORS_EXPORT std::optional<X87CompareResult>
evaluate_x87_compare(const X87CompareRequest &request) noexcept;

} // namespace hexlab
