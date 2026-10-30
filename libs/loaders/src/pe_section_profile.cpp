#include "hexlab/loaders/pe.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <new>

namespace hexlab {
Result<std::vector<PeSectionProfile>> analyze_pe_sections(const ByteStorage &storage,
                                                          const ImageMetadata &metadata,
                                                          std::stop_token stop) {
    if (metadata.format != "PE" && metadata.format != "PE32" && metadata.format != "PE32+")
        return Error{ErrorCode::invalid_argument, "PE section profile requires PE metadata"};
    const auto &sections = metadata.sections;
    try {
        std::vector<PeSectionProfile> result;
        result.reserve(sections.size());
        std::array<std::byte, 64 * 1024> buffer{};
        for (const auto &section : sections) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE section profile canceled"};
            PeSectionProfile profile;
            profile.name = section.name;
            profile.rva = section.rva;
            profile.virtual_size = section.virtual_size;
            profile.raw_size = section.raw_size;
            profile.characteristics = section.characteristics;
            profile.readable = (section.characteristics & 0x40000000u) != 0;
            profile.writable = (section.characteristics & 0x80000000u) != 0;
            profile.executable = (section.characteristics & 0x20000000u) != 0;
            if (section.raw_size) {
                const auto offset = section.raw_position.value;
                if (offset > storage.size() || section.raw_size > storage.size() - offset)
                    return Error{ErrorCode::malformed, "PE section raw extent exceeds input"};
                std::array<std::uint64_t, 256> counts{};
                std::uint64_t done = 0;
                while (done < section.raw_size) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE section profile canceled"};
                    const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), section.raw_size - done));
                    auto view = storage.read_at(FileOffset{offset + done}, count);
                    if (!view) return view.error();
                    if (view.value().bytes.size() != count)
                        return Error{ErrorCode::malformed, "PE section raw read returned a short extent"};
                    for (const auto byte : view.value().bytes) ++counts[std::to_integer<std::uint8_t>(byte)];
                    done += count;
                }
                double entropy = 0.0;
                const auto total = static_cast<double>(section.raw_size);
                for (const auto frequency : counts) {
                    if (!frequency) continue;
                    const auto probability = static_cast<double>(frequency) / total;
                    entropy -= probability * std::log2(probability);
                }
                profile.entropy_bits_per_byte = entropy;
            }
            result.push_back(std::move(profile));
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate PE section profile"};
    }
}
}
