#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/core/core_export.hpp"
#include <cstddef>
#include <cstdint>
#include <span>

namespace hexlab {
enum class ByteOrder { little, big };

// Borrows its input: the caller must keep the bytes alive and stable for
// the lifetime of the reader and any returned spans.
class ByteReader {
public:
    explicit ByteReader(std::span<const std::byte> bytes) noexcept : bytes_(bytes) {}
    std::size_t position() const noexcept { return position_; }
    std::size_t remaining() const noexcept { return bytes_.size() - position_; }
    HEXLAB_CORE_EXPORT Result<std::span<const std::byte>> read_bytes(std::size_t count);
    HEXLAB_CORE_EXPORT Result<std::size_t> seek(std::size_t position);
    HEXLAB_CORE_EXPORT Result<std::uint8_t> read_u8();
    HEXLAB_CORE_EXPORT Result<std::uint16_t> read_u16(ByteOrder order);
    HEXLAB_CORE_EXPORT Result<std::uint32_t> read_u32(ByteOrder order);
    HEXLAB_CORE_EXPORT Result<std::uint64_t> read_u64(ByteOrder order);
private:
    template<class T> Result<T> read_unsigned(ByteOrder order);
    std::span<const std::byte> bytes_;
    std::size_t position_ = 0;
};
}
