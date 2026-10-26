#include "elf_internal.hpp"
#include "miniz_tinfl.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace hexlab::elf_detail {
namespace {
constexpr std::uint64_t shf_compressed = 0x800;
constexpr std::uint32_t elfcompress_zlib = 1;

std::vector<std::uint8_t> copy_bytes(const ByteView &view, std::stop_token stop) {
    std::vector<std::uint8_t> result;
    result.reserve(view.bytes.size());
    for (const auto byte : view.bytes) {
        canceled(stop);
        result.push_back(std::to_integer<std::uint8_t>(byte));
    }
    return result;
}

std::uint64_t big_endian_u64(std::span<const std::uint8_t> bytes, std::size_t offset) {
    require(offset <= bytes.size() && 8 <= bytes.size() - offset,
            "Truncated GNU compressed DWARF section header");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i)
        value = (value << 8) | bytes[offset + i];
    return value;
}

std::vector<std::uint8_t> inflate_zlib(std::span<const std::uint8_t> input,
                                      std::uint64_t expected_size, Budget &budget,
                                      std::stop_token stop) {
    require(expected_size <= metadata_limit && expected_size <= std::numeric_limits<std::size_t>::max(),
            "Expanded DWARF section exceeds ELF metadata budget", ErrorCode::resource_limit);
    budget.include(expected_size);
    canceled(stop);
    std::vector<std::uint8_t> output(static_cast<std::size_t>(expected_size));
    std::uint8_t empty_output = 0;
    auto *out = output.empty() ? &empty_output : output.data();
    std::size_t input_size = input.size();
    std::size_t output_size = output.size();
    tinfl_decompressor decompressor;
    tinfl_init(&decompressor);
    const auto flags = TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32 |
                       TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    const auto status = tinfl_decompress(&decompressor, input.data(), &input_size,
        out, out, &output_size, flags);
    canceled(stop);
    require(status == TINFL_STATUS_DONE, "Malformed or truncated compressed DWARF zlib stream");
    require(input_size == input.size(), "Compressed DWARF section has trailing bytes");
    require(output_size == output.size(), "Compressed DWARF section size does not match its header");
    return output;
}
} // namespace

std::vector<std::uint8_t> read_debug_section_bytes(const ByteStorage &storage,
    const ElfMetadata &metadata, const ElfSection &section, Budget &budget, std::stop_token stop) {
    require(section.type != 8, "DWARF section is SHT_NOBITS and has no file contents", ErrorCode::unsupported);
    require(section.size <= metadata_limit && section.size <= std::numeric_limits<std::size_t>::max(),
            "DWARF section exceeds ELF metadata budget", ErrorCode::resource_limit);
    budget.include(section.size);
    Reader reader(storage, metadata.header.order, stop);
    const auto view = reader.bytes(section.offset, static_cast<std::size_t>(section.size));
    auto stored = copy_bytes(view, stop);

    const bool standard_compressed = (section.flags & shf_compressed) != 0;
    const bool gnu_compressed = section.name.starts_with(".zdebug_");
    require(!(standard_compressed && gnu_compressed),
            "DWARF section uses conflicting compression conventions");
    if (!standard_compressed && !gnu_compressed)
        return stored;

    std::size_t payload_offset = 0;
    std::uint64_t expanded_size = 0;
    if (standard_compressed) {
        const std::size_t header_size = metadata.header.is_64 ? 24 : 12;
        require(stored.size() >= header_size, "Truncated ELF compressed section header");
        const auto value = [&](std::size_t offset, std::size_t width) {
            std::uint64_t result = 0;
            for (std::size_t i = 0; i < width; ++i) {
                const auto shift = metadata.header.order == ByteOrder::little ? i : width - i - 1;
                result |= std::uint64_t(stored[offset + i]) << (8 * shift);
            }
            return result;
        };
        require(value(0, 4) == elfcompress_zlib,
                "ELF compressed DWARF uses an unsupported compression algorithm", ErrorCode::unsupported);
        std::uint64_t alignment = 0;
        if (metadata.header.is_64) {
            require(value(4, 4) == 0, "ELF64 compressed section has nonzero ch_reserved");
            expanded_size = value(8, 8);
            alignment = value(16, 8);
        } else {
            expanded_size = value(4, 4);
            alignment = value(8, 4);
        }
        require(aligned(alignment), "ELF compressed DWARF alignment is not a power of two");
        payload_offset = header_size;
    } else {
        require(stored.size() >= 12 && std::memcmp(stored.data(), "ZLIB", 4) == 0,
                "Malformed GNU compressed DWARF section header");
        expanded_size = big_endian_u64(stored, 4);
        payload_offset = 12;
    }
    return inflate_zlib(std::span<const std::uint8_t>(stored).subspan(payload_offset),
                        expanded_size, budget, stop);
}
} // namespace hexlab::elf_detail
