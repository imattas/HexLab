#include "hexlab/loaders/loader.hpp"
#include <algorithm>
#include <array>
namespace hexlab {
Result<DetectedFormat> detect_format(const ByteStorage &storage) {
    if (storage.size() >= 4) {
        auto prefix = storage.read_at({0}, 4);
        if (!prefix) return prefix.error();
        if (prefix.value().bytes.size() != 4)
            return Error{ErrorCode::io, "Format detection source returned an incomplete read"};
        constexpr std::array<std::byte, 4> minidump_magic{
            std::byte{'M'}, std::byte{'D'}, std::byte{'M'}, std::byte{'P'}};
        if (std::equal(prefix.value().bytes.begin(), prefix.value().bytes.end(), minidump_magic.begin()))
            return DetectedFormat::minidump_candidate;
    }
    if (storage.size() >= 8) {
        auto wasm = storage.read_at({0}, 8);
        if (!wasm) return wasm.error();
        if (wasm.value().bytes.size() != 8)
            return Error{ErrorCode::io, "Format detection source returned an incomplete read"};
        constexpr std::array<std::byte, 8> magic{
            std::byte{0x00}, std::byte{0x61}, std::byte{0x73}, std::byte{0x6d},
            std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
        if (std::equal(wasm.value().bytes.begin(), wasm.value().bytes.end(), magic.begin()))
            return DetectedFormat::wasm_candidate;
        const auto &dex = wasm.value().bytes;
        if (dex[0] == std::byte{'d'} && dex[1] == std::byte{'e'} && dex[2] == std::byte{'x'} &&
            dex[3] == std::byte{'\n'} && dex[4] >= std::byte{'0'} && dex[4] <= std::byte{'9'} &&
            dex[5] >= std::byte{'0'} && dex[5] <= std::byte{'9'} && dex[6] >= std::byte{'0'} &&
            dex[6] <= std::byte{'9'} && dex[7] == std::byte{0})
            return DetectedFormat::dex_candidate;
        // Java class files and FAT_MAGIC share CAFEBABE. A plausible classfile
        // major version distinguishes classfile headers from a fat-architecture count.
        const auto major = (std::to_integer<unsigned>(dex[6]) << 8) | std::to_integer<unsigned>(dex[7]);
        if (dex[0] == std::byte{0xca} && dex[1] == std::byte{0xfe} && dex[2] == std::byte{0xba} &&
            dex[3] == std::byte{0xbe} && major >= 45 && major <= 70)
            return DetectedFormat::jvm_candidate;
    }
    if (storage.size() >= 8) {
        auto archive = storage.read_at({0}, 8);
        if (!archive)
            return archive.error();
        if (archive.value().bytes.size() != 8)
            return Error{ErrorCode::io, "Format detection source returned an incomplete read"};
        constexpr std::array<std::byte, 8> ar_magic{std::byte{'!'}, std::byte{'<'}, std::byte{'a'}, std::byte{'r'},
                                                   std::byte{'c'}, std::byte{'h'}, std::byte{'>'}, std::byte{'\n'}};
        constexpr std::array<std::byte, 8> thin_magic{std::byte{'!'}, std::byte{'<'}, std::byte{'t'}, std::byte{'h'},
                                                     std::byte{'i'}, std::byte{'n'}, std::byte{'>'}, std::byte{'\n'}};
        constexpr std::array<std::byte, 8> aix_big_magic{std::byte{'<'}, std::byte{'b'}, std::byte{'i'}, std::byte{'g'},
                                                         std::byte{'a'}, std::byte{'f'}, std::byte{'>'}, std::byte{'\n'}};
        if (std::equal(archive.value().bytes.begin(), archive.value().bytes.end(), ar_magic.begin()) ||
            std::equal(archive.value().bytes.begin(), archive.value().bytes.end(), thin_magic.begin()) ||
            std::equal(archive.value().bytes.begin(), archive.value().bytes.end(), aix_big_magic.begin()))
            return DetectedFormat::ar_candidate;
    }
    if (storage.size() < 2)
        return DetectedFormat::unknown;
    auto first = storage.read_at({0}, storage.size() >= 4 ? 4 : 2);
    if (!first)
        return first.error();
    const auto b = first.value().bytes;
    if (b.size() != (storage.size() >= 4 ? 4u : 2u))
        return Error{ErrorCode::io, "Format detection source returned an incomplete read"};
    if (b[0] == std::byte{0x4d} && b[1] == std::byte{0x5a})
        return DetectedFormat::pe_candidate;
    if (b.size() >= 4 && b[0] == std::byte{0x7f} && b[1] == std::byte{0x45} && b[2] == std::byte{0x4c} &&
        b[3] == std::byte{0x46})
        return DetectedFormat::elf_candidate;
    if (b.size() == 4) {
        std::uint32_t magic = 0;
        for (const auto byte : b)
            magic = (magic << 8) | std::to_integer<unsigned>(byte);
        if (magic == 0xfeedface || magic == 0xcefaedfe || magic == 0xfeedfacf || magic == 0xcffaedfe ||
            magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca)
            return DetectedFormat::macho_candidate;
    }
    return DetectedFormat::unknown;
}
} // namespace hexlab
