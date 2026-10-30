#include "thumb_internal.hpp"
#include <bit>
namespace hexlab {
namespace {
bool valid_state(ThumbITState state) {
    if (!state.known)
        return !state.bits;
    if (!state.bits)
        return true;
    const auto condition = state.bits >> 4, mask = state.bits & 15;
    return mask && condition < 15 && (condition != 14 || std::popcount(static_cast<unsigned>(mask)) == 1);
}
ThumbITState next_state(ThumbITState state) {
    if (!state.known || !state.bits)
        return state;
    if (!(state.bits & 7))
        return {true, 0};
    return {true, static_cast<std::uint8_t>((state.bits & 0xe0) | ((state.bits << 1) & 31))};
}
} // namespace
DecodeResult decode_thumb(std::span<const std::byte> bytes, Address at, ThumbITState state) {
    if ((at.offset & 1) || at.offset > UINT32_MAX || !valid_state(state))
        return {DecodeStatus::invalid, {}, "Invalid Thumb address or explicit IT state"};
    if (bytes.size() < 2)
        return {DecodeStatus::truncated, {}, "Thumb instruction requires a complete halfword"};
    const auto half = [&](unsigned n) {
        return static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[n]) |
                                          (std::to_integer<unsigned>(bytes[n + 1]) << 8));
    };
    const auto first = half(0);
    const bool wide = (first & 0xf800) >= 0xe800;
    const auto length = wide ? 4u : 2u;
    if (bytes.size() < length)
        return {DecodeStatus::truncated, {}, "Thumb wide prefix requires its complete second halfword"};
    if (at.offset > UINT32_MAX - (length - 1))
        return {DecodeStatus::invalid, {}, "Thumb instruction crosses its address domain"};
    Instruction i;
    i.context = {Architecture::arm, ExecutionMode::thumb, ByteOrder::little};
    i.address = at;
    i.length = static_cast<std::uint8_t>(length);
    std::copy_n(bytes.begin(), length, i.bytes.begin());
    i.arm.emplace();
    i.arm->it_before = state;
    i.arm->it_after = next_state(state);
    i.condition = state.known ? (state.bits ? state.bits >> 4 : 14) : 255;
    i.arm->predicate = !state.known       ? ArmPredicate::unknown_it
                       : i.condition < 14 ? ArmPredicate::condition
                                          : ArmPredicate::always;
    if (i.arm->predicate == ArmPredicate::condition)
        thumb_detail::read(i, thumb_detail::flags);
    const bool decoded = thumb_detail::flow(i, first, wide ? std::optional{half(2)} : std::nullopt) ||
                         (wide ? (thumb_detail::memory_wide(i, first, half(2)) ||
                                  thumb_detail::data_wide(i, first, half(2)))
                               : (thumb_detail::memory(i, first) || thumb_detail::data(i, first)));
    if (!decoded)
        return {DecodeStatus::unsupported, {}, "Thumb encoding or incoming IT context has no enabled decoder"};
    if (state.known && state.bits && i.arm->writes_pc && (state.bits & 15) != 8)
        return {DecodeStatus::invalid, {}, "Thumb control transfer is not last in its IT block"};
    return {DecodeStatus::decoded, std::move(i), {}};
}
} // namespace hexlab
