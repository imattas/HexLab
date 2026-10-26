#include "elf_internal.hpp"
#include "miniz_tinfl.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace hexlab::elf_detail {
namespace {
constexpr std::uint64_t shf_compressed = 0x800;
constexpr std::uint32_t elfcompress_zlib = 1;
constexpr std::size_t inflate_input_window = 64 * 1024;
constexpr std::size_t inflate_output_window = 32 * 1024;

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
    require(!input.empty(), "Malformed or truncated compressed DWARF zlib stream");
    std::vector<std::uint8_t> output(static_cast<std::size_t>(expected_size));
    std::uint8_t empty_output = 0;
    std::size_t input_offset = 0;
    std::size_t output_offset = 0;
    tinfl_decompressor decompressor;
    tinfl_init(&decompressor);
    constexpr auto base_flags = TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32 |
                                TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    for (;;) {
        canceled(stop);
        const auto input_remaining = input.size() - input_offset;
        const auto input_window = std::min(inflate_input_window, input_remaining);
        const bool more_input = input_window < input_remaining;
        const auto output_remaining = output.size() - output_offset;
        const auto output_window = output.empty() ? std::size_t{1}
            : std::min(inflate_output_window, output_remaining);
        auto *output_base = output.empty() ? &empty_output : output.data();
        auto *output_next = output_base + output_offset;
        std::size_t input_used = input_window;
        std::size_t output_written = output_window;
        const auto flags = base_flags | (more_input ? TINFL_FLAG_HAS_MORE_INPUT : 0);
        const auto status = tinfl_decompress(&decompressor, input.data() + input_offset,
            &input_used, output_base, output_next, &output_written, flags);
        require(input_used <= input_window && output_written <= output_window,
                "DWARF zlib decoder returned invalid window counts");
        input_offset += input_used;
        require(output_written <= output.size() - output_offset,
                "Compressed DWARF section exceeds its declared expanded size");
        output_offset += output_written;
        if (status == TINFL_STATUS_DONE) {
            require(input_offset == input.size(), "Compressed DWARF section has trailing bytes");
            require(output_offset == output.size(),
                    "Compressed DWARF section size does not match its header");
            break;
        }
        if (status == TINFL_STATUS_HAS_MORE_OUTPUT) {
            require(output_written != 0 || input_used != 0,
                    "DWARF zlib decoder made no progress");
            require(output_offset < output.size(),
                    "Compressed DWARF section exceeds its declared expanded size");
            continue;
        }
        if (status == TINFL_STATUS_NEEDS_MORE_INPUT) {
            require((input_used != 0 || output_written != 0) && input_offset < input.size(),
                    "Malformed or truncated compressed DWARF zlib stream");
            continue;
        }
        require(false, "Malformed or truncated compressed DWARF zlib stream");
    }
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
