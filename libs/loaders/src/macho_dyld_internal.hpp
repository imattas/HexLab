#pragma once
#include "macho_internal.hpp"
#include <bit>
namespace hexlab::macho_detail {
class StreamReader {
    std::span<const std::byte> bytes_;
    std::stop_token stop_;

  public:
    std::size_t cursor = 0;
    StreamReader(std::span<const std::byte> bytes, std::stop_token stop) : bytes_(bytes), stop_(stop) {}
    bool end() const { return cursor == bytes_.size(); }
    std::uint8_t byte() {
        canceled(stop_);
        require(cursor < bytes_.size(), "Truncated Mach-O dyld stream operand");
        return std::to_integer<std::uint8_t>(bytes_[cursor++]);
    }
    std::uint64_t uleb() {
        std::uint64_t result = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto raw = byte();
            require(i != 9 || (raw & 0x7f) <= 1, "Mach-O dyld ULEB overflow");
            result |= std::uint64_t(raw & 0x7f) << (i * 7);
            if (!(raw & 0x80))
                return result;
        }
        throw Failure{{ErrorCode::malformed, "Mach-O dyld ULEB exceeds10 bytes"}};
    }
    std::int64_t sleb() {
        std::uint64_t result = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto raw = byte();
            const auto payload = raw & 0x7f;
            require(i != 9 || payload == 0 || payload == 0x7f, "Mach-O dyld SLEB overflow");
            if (i == 9)
                result |= std::uint64_t(payload & 1) << 63;
            else
                result |= std::uint64_t(payload) << (i * 7);
            if (!(raw & 0x80)) {
                if (i < 9 && (raw & 0x40))
                    result |= UINT64_MAX << ((i + 1) * 7);
                return std::bit_cast<std::int64_t>(result);
            }
        }
        throw Failure{{ErrorCode::malformed, "Mach-O dyld SLEB exceeds10 bytes"}};
    }
    std::string text() {
        const auto begin = cursor;
        while (byte())
            require(cursor - begin <= 65536, "Mach-O dyld symbol exceeds64KiB");
        return {reinterpret_cast<const char *>(bytes_.data() + begin), cursor - begin - 1};
    }
};
void read_exports(const Reader &, const Image &, MachOMetadata &, std::uint32_t, std::uint32_t, std::optional<Address>,
                  Budget &, std::stop_token);
void read_chained(const Reader &, const Image &, MachOMetadata &, std::uint32_t, std::uint32_t, std::optional<Address>,
                  Budget &, std::stop_token);
} // namespace hexlab::macho_detail
