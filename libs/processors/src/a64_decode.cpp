#include "a64_internal.hpp"
#include <algorithm>
namespace hexlab {
DecodeResult decode_a64(std::span<const std::byte> bytes, Address at) {
    if (at.offset & 3)
        return {DecodeStatus::invalid, {}, "A64 instruction address is not four-byte aligned"};
    if (bytes.size() < 4)
        return {DecodeStatus::truncated, {}, "A64 instruction requires four bytes"};
    std::uint32_t word = 0;
    for (unsigned n = 0; n < 4; ++n)
        word |= std::to_integer<std::uint32_t>(bytes[n]) << (8 * n);
    Instruction i;
    i.context = {Architecture::arm64, ExecutionMode::a64, ByteOrder::little};
    i.address = at;
    i.length = 4;
    std::copy_n(bytes.begin(), 4, i.bytes.begin());
    if (!a64_detail::flow(i, word) && !a64_detail::data(i, word) && !a64_detail::simd(i, word) &&
        !a64_detail::integer(i, word))
        return {DecodeStatus::unsupported, {}, "A64 encoding has no enabled decoder"};
    return {DecodeStatus::decoded, std::move(i), {}};
}
} // namespace hexlab

