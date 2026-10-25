#pragma once

#include "hexlab/symbols/dwarf.hpp"

namespace hexlab::symbols {

struct EvaluatedLocationPiece {
    bool available = false;
    EvaluatedLocationKind kind = EvaluatedLocationKind::memory;
    std::uint64_t value = 0; // address, register number, or scalar value by kind
    std::uint64_t bit_size = 0;
    std::uint64_t source_bit_offset = 0;
    std::uint64_t destination_bit_offset = 0;
    bool operator==(const EvaluatedLocationPiece &) const = default;
};

struct EvaluatedLocationSequence {
    bool composite = false;
    EvaluatedLocation location; // used when composite is false
    std::vector<EvaluatedLocationPiece> pieces;
    bool operator==(const EvaluatedLocationSequence &) const = default;
};

// Evaluates ordinary expressions as a single whole-location result and
// piece/bit_piece expressions as ordered pieces. Register and memory reads
// remain caller-provided; unavailable pieces remain explicit in the result.
// Composite expressions share one evaluator operation and memory-read budget
// across all piece fragments, so adding pieces cannot multiply the work bound.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<EvaluatedLocationSequence>
evaluate_location_expression_sequence(std::span<const LocationOperation> operations,
                                      const LocationEvaluationContext &context);
HEXLAB_SYMBOLS_EXPORT hexlab::Result<EvaluatedLocationSequence>
evaluate_imported_variable_location_sequence(const ImportedVariable &variable,
                                             std::uint64_t pc,
                                             const LocationEvaluationContext &context);

} // namespace hexlab::symbols
