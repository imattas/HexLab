#include "hexlab/firmware/intel_fit.hpp"
#include <limits>
#include <new>

namespace hexlab::firmware {
namespace {
std::uint16_t u16(std::span<const std::byte> bytes, std::size_t at) {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[at]) |
        (std::to_integer<std::uint8_t>(bytes[at + 1]) << 8));
}
std::uint32_t u24(std::span<const std::byte> bytes, std::size_t at) {
    return std::uint32_t(std::to_integer<std::uint8_t>(bytes[at])) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 1])) << 8) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 2])) << 16);
}
std::uint64_t u64(std::span<const std::byte> bytes, std::size_t at) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index)
        value |= std::uint64_t(std::to_integer<std::uint8_t>(bytes[at + index])) << (index * 8);
    return value;
}
}

Result<IntelFitTable> parse_intel_fit(std::span<const std::byte> bytes,
                                      std::uint64_t file_offset,
                                      std::stop_token stop,
                                      IntelFitLimits limits) {
    if (!limits.max_input_bytes || !limits.max_entries || !limits.max_table_bytes)
        return Error{ErrorCode::invalid_argument, "Intel FIT limits must be positive"};
    if (bytes.size() > limits.max_input_bytes)
        return Error{ErrorCode::resource_limit, "Intel FIT input exceeds configured byte limit"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Intel FIT parsing canceled"};
    if (file_offset > bytes.size())
        return Error{ErrorCode::malformed, "Intel FIT file offset is outside supplied input"};
    const auto table_bytes = bytes.subspan(static_cast<std::size_t>(file_offset));
    if (table_bytes.size() < 16) return Error{ErrorCode::malformed, "Truncated Intel FIT header entry"};
    constexpr std::uint64_t signature = UINT64_C(0x2020205f5449465f); // "_FIT_   "
    if (u64(table_bytes, 0) != signature)
        return Error{ErrorCode::malformed, "Intel FIT header signature is invalid"};
    const auto raw_type = std::to_integer<std::uint8_t>(table_bytes[14]);
    if ((raw_type & 0x7fu) != 0)
        return Error{ErrorCode::malformed, "Intel FIT first entry is not the type-0 header"};
    const auto entry_count = u24(table_bytes, 8);
    if (!entry_count || entry_count > limits.max_entries)
        return Error{ErrorCode::resource_limit, "Intel FIT entry count is zero or exceeds its limit"};
    const auto table_size = std::uint64_t{entry_count} * 16;
    if (table_size > limits.max_table_bytes)
        return Error{ErrorCode::resource_limit, "Intel FIT table exceeds configured byte limit"};
    if (table_size > table_bytes.size())
        return Error{ErrorCode::malformed, "Intel FIT table exceeds supplied input"};
    if (file_offset > UINT64_MAX - table_size)
        return Error{ErrorCode::overflow, "Intel FIT file extent overflows"};

    try {
        IntelFitTable table;
        table.file_offset = file_offset;
        table.size_bytes = table_size;
        table.declared_entry_count = entry_count;
        table.version = u16(table_bytes, 12);
        table.entries.reserve(entry_count);
        std::uint8_t previous_type = 0;
        for (std::uint32_t index = 0; index < entry_count; ++index) {
            if ((index & 0xffu) == 0 && stop.stop_requested())
                return Error{ErrorCode::canceled, "Intel FIT parsing canceled"};
            const auto at = static_cast<std::size_t>(index) * 16;
            const auto row_bytes = table_bytes.subspan(at, 16);
            const auto kind_flags = std::to_integer<std::uint8_t>(row_bytes[14]);
            IntelFitEntry entry;
            entry.index = index;
            entry.file_offset = file_offset + at;
            entry.address = u64(row_bytes, 0);
            entry.size_units = u24(row_bytes, 8);
            entry.reserved = std::to_integer<std::uint8_t>(row_bytes[11]);
            entry.version = u16(row_bytes, 12);
            entry.type = kind_flags & 0x7f;
            entry.checksum_valid = (kind_flags & 0x80) != 0;
            entry.checksum = std::to_integer<std::uint8_t>(row_bytes[15]);
            if (index && entry.type < previous_type) table.entry_types_ordered = false;
            if (index && entry.type == 0)
                return Error{ErrorCode::malformed, "Intel FIT contains a second type-0 header entry"};
            previous_type = entry.type;
            table.entries.push_back(entry);
        }
        if (table.entries.front().checksum_valid) {
            std::uint8_t sum = 0;
            for (const auto byte : table_bytes.first(static_cast<std::size_t>(table_size)))
                sum = static_cast<std::uint8_t>(sum + std::to_integer<std::uint8_t>(byte));
            table.table_checksum_valid = sum == 0;
        }
        return table;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Intel FIT entry inventory"};
    }
}
} // namespace hexlab::firmware
