#include "thumb_internal.hpp"
namespace hexlab::thumb_detail {
bool memory(Instruction &i, std::uint16_t h) {
    const auto rn = (h >> 3) & 7, rt = h & 7;
    if ((h & 0xf800) == 0x4800) {
        const auto offset = (h & 255) * 4;
        if (!arm32_detail::memory(i, 0xe59f0000 | (((h >> 8) & 7) << 12) | offset))
            return false;
        auto &m = std::get<ArmMemoryOperand>(i.operands[1]);
        m.resolved_address = target({i.address.space, (i.address.offset + 4) & ~UINT64_C(3)}, offset);
        return true;
    }
    if ((h & 0xf000) == 0x5000) {
        const auto op = (h >> 9) & 7, rm = (h >> 6) & 7;
        static constexpr std::uint32_t bases[]{0xe7800000, 0xe18000b0, 0xe7c00000, 0xe19000d0,
                                               0xe7900000, 0xe19000b0, 0xe7d00000, 0xe19000f0};
        return arm32_detail::memory(i, bases[op] | (rn << 16) | (rt << 12) | rm);
    }
    if ((h & 0xe000) == 0x6000) {
        const bool byte = h & 0x1000, load = h & 0x800;
        const auto offset = ((h >> 6) & 31) * (byte ? 1 : 4);
        return arm32_detail::memory(i, 0xe5800000 | (byte ? 0x400000 : 0) | (load ? 0x100000 : 0) | (rn << 16) |
                                           (rt << 12) | offset);
    }
    if ((h & 0xf000) == 0x8000) {
        const auto offset = ((h >> 6) & 31) * 2;
        return arm32_detail::memory(i, 0xe1c000b0 | ((h & 0x800) ? 0x100000 : 0) | (rn << 16) | (rt << 12) |
                                           ((offset & 0xf0) << 4) | (offset & 15));
    }
    if ((h & 0xf000) == 0x9000)
        return arm32_detail::memory(i, 0xe58d0000 | ((h & 0x800) ? 0x100000 : 0) | (((h >> 8) & 7) << 12) |
                                           ((h & 255) * 4));
    if ((h & 0xf600) == 0xb400) {
        const bool load = h & 0x800;
        const auto mask = (h & 255) | ((h & 0x100) ? (load ? 0x8000 : 0x4000) : 0);
        return arm32_detail::memory(i, (load ? 0xe8bd0000 : 0xe92d0000) | mask);
    }
    if ((h & 0xf000) == 0xc000) {
        const bool load = h & 0x800;
        const auto base = (h >> 8) & 7, mask = h & 255;
        const bool wb = !load || !(mask & (1u << base));
        return arm32_detail::memory(i, 0xe8800000 | (load ? 0x100000 : 0) | (wb ? 0x200000 : 0) | (base << 16) | mask);
    }
    return false;
}
} // namespace hexlab::thumb_detail
