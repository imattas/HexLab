#include "hexlab/core/byte_reader.hpp"

namespace hexlab {
Result<std::span<const std::byte>> ByteReader::read_bytes(std::size_t count) {
    if (count > remaining())
        return Error{ErrorCode::out_of_bounds, "Read exceeds available bytes"};
    const auto result = bytes_.subspan(position_, count);
    position_ += count;
    return result;
}
Result<std::size_t> ByteReader::seek(std::size_t position) {
    if (position > bytes_.size())
        return Error{ErrorCode::out_of_bounds, "Seek exceeds input size"};
    position_ = position;
    return position_;
}
template<class T> Result<T> ByteReader::read_unsigned(ByteOrder order) {
    const auto input = read_bytes(sizeof(T));
    if (!input) return input.error();
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        const auto index = order == ByteOrder::little ? i : sizeof(T) - i - 1;
        value |= std::to_integer<std::uint64_t>(input.value()[index]) << (i * 8);
    }
    return static_cast<T>(value);
}
Result<std::uint8_t> ByteReader::read_u8() { return read_unsigned<std::uint8_t>(ByteOrder::little); }
Result<std::uint16_t> ByteReader::read_u16(ByteOrder order) { return read_unsigned<std::uint16_t>(order); }
Result<std::uint32_t> ByteReader::read_u32(ByteOrder order) { return read_unsigned<std::uint32_t>(order); }
Result<std::uint64_t> ByteReader::read_u64(ByteOrder order) { return read_unsigned<std::uint64_t>(order); }
}
