#include "hexlab/processors/mips64_semantics.hpp"

#include <bit>

namespace hexlab {
namespace {
bool is_word(Mips64MergeOperation operation) noexcept {
    return operation == Mips64MergeOperation::load_left_word ||
           operation == Mips64MergeOperation::load_right_word ||
           operation == Mips64MergeOperation::store_left_word ||
           operation == Mips64MergeOperation::store_right_word;
}

bool is_load(Mips64MergeOperation operation) noexcept {
    return operation == Mips64MergeOperation::load_left_word ||
           operation == Mips64MergeOperation::load_right_word ||
           operation == Mips64MergeOperation::load_left_doubleword ||
           operation == Mips64MergeOperation::load_right_doubleword;
}

bool is_left(Mips64MergeOperation operation) noexcept {
    return operation == Mips64MergeOperation::load_left_word ||
           operation == Mips64MergeOperation::store_left_word ||
           operation == Mips64MergeOperation::load_left_doubleword ||
           operation == Mips64MergeOperation::store_left_doubleword;
}

unsigned shift_for(unsigned address_lane, unsigned byte_count, ByteOrder order) noexcept {
    return (order == ByteOrder::little ? address_lane : byte_count - 1 - address_lane) * 8;
}
}

std::optional<Mips64MergeResult>
evaluate_mips64_merge(Mips64MergeOperation operation, ByteOrder order,
                      std::uint8_t address_offset, std::uint64_t register_value,
                      std::uint64_t memory_word) noexcept {
    if (static_cast<unsigned>(operation) >
        static_cast<unsigned>(Mips64MergeOperation::store_right_doubleword))
        return {};
    const unsigned byte_count = is_word(operation) ? 4 : 8;
    if (address_offset >= byte_count) return {};

    const bool left = is_left(operation);
    unsigned memory_start = 0;
    unsigned register_start = 0;
    unsigned touched = 0;
    if (order == ByteOrder::little) {
        touched = left ? static_cast<unsigned>(address_offset) + 1 : byte_count - address_offset;
        memory_start = left ? 0 : address_offset;
        register_start = left ? byte_count - touched : 0;
    } else {
        touched = left ? byte_count - address_offset : static_cast<unsigned>(address_offset) + 1;
        memory_start = left ? address_offset : 0;
        register_start = left ? 0 : byte_count - touched;
    }

    Mips64MergeResult result;
    result.bytes_touched = static_cast<std::uint8_t>(touched);
    result.writes_register = is_load(operation);
    if (result.writes_register) {
        std::uint32_t merged32 = static_cast<std::uint32_t>(register_value);
        std::uint64_t merged64 = register_value;
        for (unsigned index = 0; index < touched; ++index) {
            const unsigned memory_lane = memory_start + index;
            const unsigned register_lane = register_start + index;
            const unsigned memory_shift = shift_for(memory_lane, byte_count, order);
            const unsigned register_shift = shift_for(register_lane, byte_count, order);
            const auto byte = (memory_word >> memory_shift) & UINT64_C(0xff);
            if (byte_count == 4) {
                const auto lane_mask = UINT32_C(0xff) << register_shift;
                merged32 = (merged32 & ~lane_mask) | static_cast<std::uint32_t>(byte << register_shift);
            } else {
                const auto lane_mask = UINT64_C(0xff) << register_shift;
                merged64 = (merged64 & ~lane_mask) | (byte << register_shift);
            }
            result.register_byte_mask |= UINT64_C(1) << (register_shift / 8);
            result.memory_byte_mask |= UINT64_C(1) << memory_lane;
        }
        if (byte_count == 4) {
            const auto signed_value = std::bit_cast<std::int32_t>(merged32);
            result.value = static_cast<std::uint64_t>(static_cast<std::int64_t>(signed_value));
            result.register_byte_mask |= UINT64_C(0xf0);
        } else {
            result.value = merged64;
        }
        return result;
    }

    std::uint64_t merged_memory = memory_word;
    const std::uint64_t source = byte_count == 4 ? static_cast<std::uint32_t>(register_value)
                                                  : register_value;
    for (unsigned index = 0; index < touched; ++index) {
        const unsigned memory_lane = memory_start + index;
        const unsigned register_lane = register_start + index;
        const unsigned memory_shift = shift_for(memory_lane, byte_count, order);
        const unsigned register_shift = shift_for(register_lane, byte_count, order);
        const auto lane_mask = UINT64_C(0xff) << memory_shift;
        const auto byte = (source >> register_shift) & UINT64_C(0xff);
        merged_memory = (merged_memory & ~lane_mask) | (byte << memory_shift);
        result.memory_byte_mask |= UINT64_C(1) << memory_lane;
    }
    if (byte_count == 4)
        merged_memory = (memory_word & UINT64_C(0xffffffff00000000)) |
                        static_cast<std::uint32_t>(merged_memory);
    result.value = merged_memory;
    return result;
}

} // namespace hexlab
