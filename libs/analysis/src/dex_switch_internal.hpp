#pragma once

#include "hexlab/image/image.hpp"
#include "hexlab/image/read_set.hpp"
#include "hexlab/processors/instruction.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <span>
#include <stop_token>
#include <vector>

namespace hexlab::function_detail {
inline Result<bool> populate_dex_switch_table(const Image &image, Instruction &instruction, ReadSet *reads,
                                             std::stop_token stop = {}) {
    if (instruction.context.architecture != Architecture::dex || instruction.opcode != Opcode::dex_switch ||
        !instruction.dex_switch)
        return false;
    if (instruction.dex_switch->validated)
        return true;
    const auto fail = [](ErrorCode code, const char *message) -> Result<bool> { return Error{code, message}; };
    const auto payload = instruction.dex_switch->payload;
    if (payload.space != instruction.address.space || (payload.offset & 3))
        return fail(ErrorCode::malformed, "DEX switch payload address is misaligned or in another method");
    const auto *method = image.segment_at(instruction.address);
    if (!method || !method->executable || image.segment_at(payload) != method ||
        instruction.address.offset < method->begin.offset || payload.offset < method->begin.offset)
        return fail(ErrorCode::malformed, "DEX switch payload is outside its executable method");
    const auto payload_relative = payload.offset - method->begin.offset;
    if (payload_relative > method->file_size || method->file_size - payload_relative < 4)
        return fail(ErrorCode::malformed, "DEX switch payload header has no initialized method backing");
    if (stop.stop_requested())
        return fail(ErrorCode::canceled, "DEX switch payload decode canceled");
    auto header = image.read(payload, 4);
    if (!header)
        return header.error();
    const auto note_payload_bytes = [&](std::size_t byte_size) -> Result<bool> {
        if (!reads)
            return true;
        for (std::size_t i = 0; i < byte_size; ++i) {
            if ((i & 63u) == 0 && stop.stop_requested())
                return fail(ErrorCode::canceled, "DEX switch payload dependency capture canceled");
            auto file = image.to_file_offset({payload.space, payload.offset + i});
            if (!file)
                return file.error();
            auto included = reads->include(file.value(), 1);
            if (!included)
                return included.error();
        }
        return true;
    };
    auto header_noted = note_payload_bytes(4);
    if (!header_noted)
        return header_noted.error();
    const auto u16 = [](std::span<const std::byte> bytes, std::size_t offset) {
        return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset]) |
                                          (std::uint16_t(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8));
    };
    const auto u32 = [](std::span<const std::byte> bytes, std::size_t offset) {
        return std::uint32_t(std::to_integer<std::uint8_t>(bytes[offset])) |
               (std::uint32_t(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8) |
               (std::uint32_t(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 16) |
               (std::uint32_t(std::to_integer<std::uint8_t>(bytes[offset + 3])) << 24);
    };
    const auto ident = u16(header.value(), 0);
    const auto count = static_cast<std::size_t>(u16(header.value(), 2));
    const auto expected_ident = instruction.dex_switch->packed ? 0x0100u : 0x0200u;
    if (ident != expected_ident)
        return fail(ErrorCode::malformed, "DEX switch opcode references the wrong payload kind");
    if (count > 64)
        return fail(ErrorCode::resource_limit, "DEX switch exceeds the 64-case analysis limit");
    const std::size_t header_size = instruction.dex_switch->packed ? 8 : 4;
    const std::size_t item_size = instruction.dex_switch->packed ? 4 : 8;
    if (count > (std::numeric_limits<std::size_t>::max() - header_size) / item_size)
        return fail(ErrorCode::overflow, "DEX switch payload length overflows");
    const auto byte_size = header_size + count * item_size;
    if (payload.offset > UINT32_MAX || byte_size > UINT32_MAX - payload.offset)
        return fail(ErrorCode::overflow, "DEX switch payload exceeds method address space");
    if (byte_size > method->file_size - payload_relative)
        return fail(ErrorCode::malformed, "DEX switch payload extends beyond initialized method bytes");
    if (instruction.address.offset < payload.offset + byte_size &&
        payload.offset < instruction.address.offset + instruction.byte_length())
        return fail(ErrorCode::malformed, "DEX switch payload overlaps the referring instruction");
    auto payload_noted = note_payload_bytes(byte_size);
    if (!payload_noted)
        return payload_noted.error();
    auto bytes = image.read(payload, byte_size);
    if (!bytes)
        return bytes.error();
    if (bytes.value().size() != byte_size)
        return fail(ErrorCode::malformed, "DEX switch payload is truncated");
    auto payload_source = image.to_file_offset(payload);
    if (!payload_source)
        return payload_source.error();

    std::vector<std::int32_t> keys;
    keys.reserve(count);
    std::vector<std::int32_t> targets;
    targets.reserve(count);
    if (instruction.dex_switch->packed) {
        const auto first = std::bit_cast<std::int32_t>(u32(bytes.value(), 4));
        if (count && static_cast<std::int64_t>(first) + static_cast<std::int64_t>(count - 1) > INT32_MAX)
            return fail(ErrorCode::malformed, "DEX packed-switch key range overflows signed 32 bits");
        for (std::size_t i = 0; i < count; ++i)
            keys.push_back(static_cast<std::int32_t>(static_cast<std::int64_t>(first) + i));
        for (std::size_t i = 0; i < count; ++i)
            targets.push_back(std::bit_cast<std::int32_t>(u32(bytes.value(), header_size + i * 4)));
    } else {
        for (std::size_t i = 0; i < count; ++i)
            keys.push_back(std::bit_cast<std::int32_t>(u32(bytes.value(), header_size + i * 4)));
        for (std::size_t i = 0; i < count; ++i)
            targets.push_back(std::bit_cast<std::int32_t>(u32(bytes.value(), header_size + count * 4 + i * 4)));
        if (!std::is_sorted(keys.begin(), keys.end()) ||
            std::adjacent_find(keys.begin(), keys.end()) != keys.end())
            return fail(ErrorCode::malformed, "DEX sparse-switch keys are not strictly increasing");
    }

    std::vector<DexSwitchCase> cases;
    cases.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested())
            return fail(ErrorCode::canceled, "DEX switch payload decode canceled");
        const auto delta = static_cast<std::int64_t>(targets[i]) * 2;
        std::uint64_t offset = 0;
        if (delta >= 0) {
            if (static_cast<std::uint64_t>(delta) > UINT32_MAX - instruction.address.offset)
                return fail(ErrorCode::malformed, "DEX switch case target exceeds method address space");
            offset = instruction.address.offset + static_cast<std::uint64_t>(delta);
        } else {
            const auto amount = static_cast<std::uint64_t>(-delta);
            if (amount > instruction.address.offset)
                return fail(ErrorCode::malformed, "DEX switch case target precedes method address space");
            offset = instruction.address.offset - amount;
        }
        if (offset >= payload.offset && offset - payload.offset < byte_size)
            return fail(ErrorCode::malformed, "DEX switch case targets bytes inside its payload");
        const Address case_target{instruction.address.space, offset};
        if (image.segment_at(case_target) != method || offset < method->begin.offset ||
            offset - method->begin.offset > method->file_size ||
            method->file_size - (offset - method->begin.offset) < 2 ||
            image.code_window(case_target, 2) != 2)
            return fail(ErrorCode::malformed, "DEX switch case leaves initialized executable method code");
        const auto key_offset = instruction.dex_switch->packed ? 4 : header_size + i * 4;
        const auto target_offset = instruction.dex_switch->packed ? header_size + i * 4
                                      : header_size + count * 4 + i * 4;
        auto key_source = image.to_file_offset({payload.space, payload.offset + key_offset});
        if (!key_source)
            return key_source.error();
        auto target_source = image.to_file_offset({payload.space, payload.offset + target_offset});
        if (!target_source)
            return target_source.error();
        cases.push_back({keys[i], case_target, key_source.value(), target_source.value()});
    }

    instruction.dex_switch->cases = std::move(cases);
    instruction.dex_switch->payload_source = payload_source.value();
    instruction.dex_switch->payload_bytes = static_cast<std::uint32_t>(byte_size);
    instruction.dex_switch->validated = true;
    return true;
}
} // namespace hexlab::function_detail
