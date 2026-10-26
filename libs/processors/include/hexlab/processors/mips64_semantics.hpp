#pragma once

#include "hexlab/core/byte_reader.hpp"
#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

enum class Mips64MergeOperation {
    load_left_word, load_right_word, store_left_word, store_right_word,
    load_left_doubleword, load_right_doubleword, store_left_doubleword, store_right_doubleword,
};

struct Mips64MergeResult {
    // For loads this is the merged, sign-extended GPR value. For stores this is
    // the updated aligned memory word. The caller performs the actual memory
    // access after validating the touched range.
    std::uint64_t value = 0;
    // Bit i is one when numeric byte i (0 is the least-significant byte) of
    // the GPR was changed by the load. Word loads include bits 4-7 because
    // they sign-extend their result.
    std::uint64_t register_byte_mask = 0;
    // Bit i is one when address-order byte i of the aligned memory word is
    // read by a load or written by a store.
    std::uint64_t memory_byte_mask = 0;
    std::uint8_t bytes_touched = 0;
    bool writes_register = false;
    bool operator==(const Mips64MergeResult &) const = default;
};

// Evaluate one MIPS64 LWL/LWR/LDL/LDR/SWL/SWR/SDL/SDR byte-lane merge.
// address_offset is the effective address modulo the operation width;
// memory_word is the aligned 4- or 8-byte word interpreted in `order`;
// register_value is the prior GPR for a load or source GPR for a store.
// Invalid operation offsets return no result. No memory access is performed.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64MergeResult>
evaluate_mips64_merge(Mips64MergeOperation operation, ByteOrder order,
                      std::uint8_t address_offset, std::uint64_t register_value,
                      std::uint64_t memory_word) noexcept;

} // namespace hexlab
