#include "pe_internal.hpp"
#include <algorithm>
#include <iterator>

namespace hexlab::pe_detail {
namespace {
std::size_t relocation_width(std::uint16_t machine, std::uint16_t type) {
    if (!type)
        return 0;
    if (machine == 0x14c) {
        if (type == 1 || type == 2)
            return 2;
        if (type == 3)
            return 4;
        if (type == 4)
            return 2;
        throw Failure{{ErrorCode::unsupported, "Unsupported x86 PE base relocation type"}};
    }
    if (machine == 0x8664) {
        if (type == 3)
            return 4;
        if (type == 10)
            return 8;
        throw Failure{{ErrorCode::unsupported, "Unsupported x64 PE base relocation type"}};
    }
    if (machine == 0x1c0 || machine == 0x1c4) {
        if (type == 3)
            return 4;
        if (type == 5 || (type == 7 && machine == 0x1c4))
            return 8;
        throw Failure{{ErrorCode::unsupported, "Unsupported ARM32 PE base relocation type"}};
    }
    if (machine == 0xaa64) {
        if (type == 10)
            return 8;
        throw Failure{{ErrorCode::unsupported, "Unsupported ARM64 PE base relocation type"}};
    }
    throw Failure{{ErrorCode::unsupported, "PE base relocations require a recognized machine"}};
}

std::uint64_t read_le(std::span<const std::byte> bytes) {
    std::uint64_t value = 0;
    for (std::size_t n = 0; n < bytes.size(); ++n)
        value |= std::to_integer<std::uint64_t>(bytes[n]) << (8 * n);
    return value;
}

void write_le(std::span<std::byte> bytes, std::uint64_t value) {
    for (std::size_t n = 0; n < bytes.size(); ++n)
        bytes[n] = static_cast<std::byte>(value >> (8 * n));
}

std::uint16_t thumb_imm(std::span<const std::byte> bytes) {
    const auto first = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[0]) |
                                                  (std::to_integer<unsigned>(bytes[1]) << 8));
    const auto second = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[2]) |
                                                   (std::to_integer<unsigned>(bytes[3]) << 8));
    return static_cast<std::uint16_t>(((first & 15) << 12) | (((first >> 10) & 1) << 11) |
                                      (((second >> 12) & 7) << 8) | (second & 255));
}

void set_thumb_imm(std::span<std::byte> bytes, std::uint16_t value) {
    auto first = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[0]) |
                                            (std::to_integer<unsigned>(bytes[1]) << 8));
    auto second = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[2]) |
                                             (std::to_integer<unsigned>(bytes[3]) << 8));
    first = static_cast<std::uint16_t>((first & ~0x040fu) | ((value >> 12) & 15) | (((value >> 11) & 1) << 10));
    second = static_cast<std::uint16_t>((second & ~0x70ffu) | (((value >> 8) & 7) << 12) | (value & 255));
    bytes[0] = static_cast<std::byte>(first);
    bytes[1] = static_cast<std::byte>(first >> 8);
    bytes[2] = static_cast<std::byte>(second);
    bytes[3] = static_cast<std::byte>(second >> 8);
}

std::vector<std::byte> relocated_value(const Relocation &relocation, std::uint16_t machine,
                                       std::span<const std::byte> input, std::uint64_t delta,
                                       std::optional<std::int16_t> highadj_addend) {
    std::vector<std::byte> output(input.begin(), input.end());
    const auto type = relocation.type;
    if (machine == 0x1c0 || machine == 0x1c4) {
        if (type == 3) {
            write_le(output, static_cast<std::uint32_t>(read_le(input) + delta));
        } else if (type == 5) {
            const auto low = static_cast<std::uint32_t>(read_le(input.first(4)));
            const auto high = static_cast<std::uint32_t>(read_le(input.subspan(4, 4)));
            require((low & 0x0ff00000u) == 0x03000000u && (high & 0x0ff00000u) == 0x03400000u &&
                        ((low >> 12) & 15) == ((high >> 12) & 15),
                    "ARM_MOV32 relocation does not point at a matching MOVW/MOVT pair",
                    ErrorCode::unsupported);
            const auto low_imm = ((low >> 16) & 15) << 12 | (low & 0xfff);
            const auto high_imm = ((high >> 16) & 15) << 12 | (high & 0xfff);
            const auto value = static_cast<std::uint32_t>((high_imm << 16 | low_imm) + delta);
            const auto patch_arm = [](std::span<std::byte> word_bytes, std::uint16_t immediate) {
                auto word = static_cast<std::uint32_t>(read_le(word_bytes));
                word = (word & ~0x000f0fffu) | ((std::uint32_t{immediate} & 0xf000) << 4) | (immediate & 0xfff);
                write_le(word_bytes, word);
            };
            patch_arm(std::span(output).first(4), static_cast<std::uint16_t>(value));
            patch_arm(std::span(output).subspan(4, 4), static_cast<std::uint16_t>(value >> 16));
        } else if (type == 7) {
            const auto first = std::span<const std::byte>(input).first(4);
            const auto second = std::span<const std::byte>(input).subspan(4, 4);
            const auto hw1_low = static_cast<std::uint16_t>(std::to_integer<unsigned>(first[0]) |
                                                            (std::to_integer<unsigned>(first[1]) << 8));
            const auto hw2_low = static_cast<std::uint16_t>(std::to_integer<unsigned>(first[2]) |
                                                            (std::to_integer<unsigned>(first[3]) << 8));
            const auto hw1_high = static_cast<std::uint16_t>(std::to_integer<unsigned>(second[0]) |
                                                             (std::to_integer<unsigned>(second[1]) << 8));
            const auto hw2_high = static_cast<std::uint16_t>(std::to_integer<unsigned>(second[2]) |
                                                             (std::to_integer<unsigned>(second[3]) << 8));
            require((hw1_low & 0xfbf0u) == 0xf240u && (hw1_high & 0xfbf0u) == 0xf2c0u &&
                        ((hw2_low >> 8) & 15) == ((hw2_high >> 8) & 15),
                    "THUMB_MOV32 relocation does not point at a matching MOVW/MOVT pair",
                    ErrorCode::unsupported);
            const auto value = static_cast<std::uint32_t>((std::uint32_t{thumb_imm(second)} << 16) |
                                                         thumb_imm(first));
            const auto adjusted = static_cast<std::uint32_t>(value + delta);
            set_thumb_imm(std::span(output).first(4), static_cast<std::uint16_t>(adjusted));
            set_thumb_imm(std::span(output).subspan(4, 4), static_cast<std::uint16_t>(adjusted >> 16));
        }
        return output;
    }
    if (type == 1)
        write_le(output, static_cast<std::uint16_t>(read_le(input) + (delta >> 16)));
    else if (type == 2)
        write_le(output, static_cast<std::uint16_t>(read_le(input) + delta));
    else if (type == 4) {
        require(machine == 0x14c && highadj_addend.has_value(),
                "HIGHADJ relocation is missing its signed paired addend", ErrorCode::unsupported);
        const auto high = static_cast<std::uint32_t>(read_le(input));
        const auto adjusted = (high << 16) + static_cast<std::uint32_t>(static_cast<std::int32_t>(*highadj_addend)) +
                              static_cast<std::uint32_t>(delta) + 0x8000u;
        write_le(output, adjusted >> 16);
    }
    else if (type == 3)
        write_le(output, static_cast<std::uint32_t>(read_le(input) + delta));
    else if (type == 10)
        write_le(output, read_le(input) + delta);
    return output;
}

void rebase_address(Address &address, std::uint64_t preferred, std::uint64_t load_base) {
    require(address.offset >= preferred, "PE metadata address precedes preferred image base");
    address.offset = add(load_base, address.offset - preferred, "rebased metadata address");
}
} // namespace

Result<std::size_t> read_relocations(const Image &image, const Directory &directory, ImageMetadata &metadata,
                                     std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image, metadata, stop);
        std::vector<Relocation> records;
        std::vector<PeRelocationSource> provenance;
        std::uint64_t offset = 0;
        std::uint32_t block_index = 0;
        std::size_t entry_count = 0;
        while (offset < directory.size) {
            canceled(stop);
            if (block_index >= record_limit)
                throw Failure{{ErrorCode::resource_limit, "Relocation block budget reached"}};
            require(directory.size - offset >= 8, "Truncated relocation block header");
            const auto at = std::uint64_t{directory.location} + offset;
            require(at % 4 == 0, "Relocation block is not 32-bit aligned");
            const auto page = r.integer<std::uint32_t>(at);
            const auto size = r.integer<std::uint32_t>(at + 4);
            require(size >= 8 && size <= directory.size - offset && ((size - 8) % 2) == 0,
                    "Invalid relocation block size");
            require(page % 0x1000 == 0, "Relocation page RVA is not page-aligned");
            require(page < metadata.image_size, "Relocation page exceeds image");
            for (std::uint64_t entry = 8; entry < size; entry += 2) {
                canceled(stop);
                if (entry_count >= record_limit)
                    throw Failure{{ErrorCode::resource_limit, "Relocation entry budget reached"}};
                ++entry_count;
                const auto raw = r.integer<std::uint16_t>(at + entry);
                const auto type = static_cast<std::uint16_t>(raw >> 12);
                const auto within = static_cast<std::uint16_t>(raw & 0xfff);
                if (!type)
                    continue;
                std::optional<std::int16_t> highadj_addend;
                std::optional<PeRecordSource> addend_entry;
                if (type == 4) {
                    require(metadata.machine == 0x14c, "HIGHADJ relocation is only valid for x86 PE32",
                            ErrorCode::unsupported);
                    require(entry + 4 <= size, "HIGHADJ relocation lacks its paired addend word");
                    if (entry_count >= record_limit)
                        throw Failure{{ErrorCode::resource_limit, "Relocation entry budget reached"}};
                    ++entry_count;
                    highadj_addend = static_cast<std::int16_t>(r.integer<std::uint16_t>(at + entry + 2));
                    addend_entry = PeRecordSource{static_cast<std::uint32_t>((entry - 8) / 2 + 1),
                                                  r.sources(at + entry + 2, 2)};
                }
                const auto width = relocation_width(metadata.machine, type);
                require(within <= 0x1000 - width, "Relocation field crosses its 4-KiB page");
                const auto target = std::uint64_t{page} + within;
                const auto address = r.address(target);
                (void)r.bytes(target, width);
                if (records.size() >= record_limit)
                    throw Failure{{ErrorCode::resource_limit, "Relocation record budget reached"}};
                records.push_back({type, address, {page}, within});
                provenance.push_back({{block_index, r.sources(at, 8)},
                                      {static_cast<std::uint32_t>((entry - 8) / 2), r.sources(at + entry, 2)},
                                      highadj_addend, std::move(addend_entry)});
                if (type == 4)
                    entry += 2;
            }
            offset += size;
            ++block_index;
        }
        const auto count = records.size();
        metadata.relocations.insert(metadata.relocations.end(), std::make_move_iterator(records.begin()),
                                    std::make_move_iterator(records.end()));
        if (!metadata.pe)
            metadata.pe.emplace();
        metadata.pe->relocations.insert(metadata.pe->relocations.end(), std::make_move_iterator(provenance.begin()),
                                        std::make_move_iterator(provenance.end()));
        return count;
    });
}

Result<RebasedPeImage> apply_pe_relocations(const Image &image, ImageMetadata &metadata, std::uint64_t load_base,
                                            std::stop_token stop) {
    try {
        canceled(stop);
        const auto preferred = metadata.preferred_base;
        require(load_base != preferred, "PE rebasing was requested without a base change", ErrorCode::invalid_argument);
        require(!metadata.relocations.empty(), "PE image has no applicable base relocations", ErrorCode::unsupported);
        const auto extent = checked_add(load_base, metadata.image_size);
        require(bool(extent), "PE image extent overflows runtime address space", ErrorCode::overflow);
        if (metadata.machine == 0x14c || metadata.machine == 0x1c0 || metadata.machine == 0x1c4)
            require(extent.value() <= (UINT64_C(1) << 32), "PE32 image exceeds its 32-bit address space", ErrorCode::overflow);
        const auto delta = load_base - preferred;
        std::vector<PatchSpan> patches;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> virtual_fields;
        virtual_fields.reserve(metadata.relocations.size());
        for (std::size_t relocation_index = 0; relocation_index < metadata.relocations.size(); ++relocation_index) {
            const auto &relocation = metadata.relocations[relocation_index];
            canceled(stop);
            const auto width = relocation_width(metadata.machine, relocation.type);
            require(relocation.address.offset >= preferred, "Relocation address precedes preferred image base");
            const auto rva = relocation.address.offset - preferred;
            require(rva <= metadata.image_size && width <= metadata.image_size - rva,
                    "Relocation target exceeds image extent");
            virtual_fields.emplace_back(rva, rva + width);
            const auto original = image.read(relocation.address, width);
            if (!original)
                throw Failure{original.error()};
            std::optional<std::int16_t> highadj_addend;
            if (relocation.type == 4 && metadata.pe && relocation_index < metadata.pe->relocations.size())
                highadj_addend = metadata.pe->relocations[relocation_index].highadj_addend;
            auto replacement = relocated_value(relocation, metadata.machine, original.value(), delta, highadj_addend);
            std::size_t cursor = 0;
            while (cursor < width) {
                const auto mapped = image.to_file_offset({relocation.address.space, relocation.address.offset + cursor});
                if (!mapped)
                    throw Failure{mapped.error()};
                const auto begin = cursor;
                auto previous = mapped.value().value;
                ++cursor;
                while (cursor < width) {
                    const auto next = image.to_file_offset({relocation.address.space, relocation.address.offset + cursor});
                    if (!next)
                        throw Failure{next.error()};
                    if (next.value().value != previous + 1)
                        break;
                    previous = next.value().value;
                    ++cursor;
                }
                patches.push_back({{mapped.value().value},
                                   {original.value().begin() + static_cast<std::ptrdiff_t>(begin),
                                    original.value().begin() + static_cast<std::ptrdiff_t>(cursor)},
                                   {replacement.begin() + static_cast<std::ptrdiff_t>(begin),
                                    replacement.begin() + static_cast<std::ptrdiff_t>(cursor)}});
            }
        }
        std::sort(virtual_fields.begin(), virtual_fields.end());
        for (std::size_t n = 1; n < virtual_fields.size(); ++n)
            require(virtual_fields[n - 1].second <= virtual_fields[n].first,
                    "Overlapping PE base relocations are ambiguous");
        std::sort(patches.begin(), patches.end(), [](const auto &a, const auto &b) { return a.begin.value < b.begin.value; });
        for (std::size_t n = 1; n < patches.size(); ++n)
            require(patches[n - 1].begin.value + patches[n - 1].replacement.size() <= patches[n].begin.value,
                    "PE base relocations alias the same source bytes");

        auto layout = image.layout();
        for (auto &segment : layout.segments)
            rebase_address(segment.begin, preferred, load_base);
        for (auto &entry : layout.entries)
            rebase_address(entry, preferred, load_base);
        if (layout.execution_profile)
            for (auto &range : layout.execution_profile->ranges)
                rebase_address(range.begin, preferred, load_base);
        for (auto &record : metadata.imports) {
            rebase_address(record.thunk, preferred, load_base);
            rebase_address(record.iat, preferred, load_base);
        }
        for (auto &record : metadata.exports)
            if (record.address)
                rebase_address(*record.address, preferred, load_base);
        for (auto &record : metadata.relocations)
            rebase_address(record.address, preferred, load_base);
        return RebasedPeImage{std::move(layout), std::move(patches)};
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate rebased PE image"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Rebased PE image is too large"};
    }
}
} // namespace hexlab::pe_detail
