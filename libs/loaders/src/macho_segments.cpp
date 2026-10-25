#include "macho_internal.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <set>
namespace hexlab::macho_detail {
namespace {
std::string name(std::span<const std::byte> bytes, std::size_t offset) {
    const auto first = bytes.subspan(offset, 16);
    const auto end = std::find(first.begin(), first.end(), std::byte{0});
    return {reinterpret_cast<const char *>(first.data()), static_cast<std::size_t>(end - first.begin())};
}
bool zero_fill(std::uint32_t flags) {
    const auto type = flags & 255;
    return type == 1 || type == 0xc || type == 0x12;
}
void address_extent(std::uint64_t begin, std::uint64_t size, bool wide) {
    const auto end = add(begin, size);
    require(wide || (begin <= UINT32_MAX && end <= (UINT64_C(1) << 32)), "Mach-O extent exceeds32-bit address space");
}
} // namespace
void read_segments(const ByteStorage &storage, MachOMetadata &metadata, Budget &budget, std::stop_token stop) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    const auto &header = slice.header;
    Reader reader(storage, slice, stop);
    for (const auto &command : header.commands) {
        canceled(stop);
        if (command.command != 1 && command.command != 0x19)
            continue;
        require(command.command == (header.is_64 ? 0x19u : 1u), "Mach-O segment class differs from header class");
        const auto minimum = header.is_64 ? 72u : 56u, stride = header.is_64 ? 80u : 68u;
        require(command.size >= minimum, "Truncated Mach-O segment command");
        const auto relative = command.file_offset - slice.offset;
        const auto bytes = reader.bytes(relative, minimum);
        const auto field = [&](std::size_t at, std::size_t width = 4) { return reader.value(bytes.bytes, at, width); };
        const auto word = header.is_64 ? 8u : 4u;
        MachOSegment segment;
        segment.command_index = command.index;
        segment.name = name(bytes.bytes, 8);
        segment.address = field(24, word);
        segment.memory_size = field(header.is_64 ? 32 : 28, word);
        segment.raw_file_offset = field(header.is_64 ? 40 : 32, word);
        segment.file_size = field(header.is_64 ? 48 : 36, word);
        segment.file_offset = reader.file(segment.raw_file_offset, segment.file_size);
        segment.maximum_protection = static_cast<std::uint32_t>(field(header.is_64 ? 56 : 40));
        segment.initial_protection = static_cast<std::uint32_t>(field(header.is_64 ? 60 : 44));
        segment.section_count = static_cast<std::uint32_t>(field(header.is_64 ? 64 : 48));
        segment.flags = static_cast<std::uint32_t>(field(header.is_64 ? 68 : 52));
        require(segment.section_count <= 1048576 - metadata.sections.size(), "Mach-O section count exceeds budget",
                ErrorCode::resource_limit);
        require(segment.section_count <= (command.size - minimum) / stride, "Mach-O sections exceed segment command");
        address_extent(segment.address, segment.memory_size, header.is_64);
        require(header.file_type == 1 || segment.file_size <= segment.memory_size,
                "Mach-O file mapping exceeds VM size");
        segment.first_section = static_cast<std::uint32_t>(metadata.sections.size() + 1);
        budget.include(sizeof(MachOSegment) + segment.name.size() +
                       std::uint64_t(segment.section_count) * sizeof(MachOSection));
        const auto segment_index = static_cast<std::uint32_t>(metadata.segments.size());
        for (std::uint32_t index = 0; index < segment.section_count; ++index) {
            const auto record = add(relative + minimum, std::uint64_t(index) * stride);
            const auto raw = reader.bytes(record, stride);
            const auto value = [&](std::size_t at, std::size_t width = 4) {
                return reader.value(raw.bytes, at, width);
            };
            MachOSection section;
            section.ordinal = static_cast<std::uint32_t>(metadata.sections.size() + 1);
            section.segment_index = segment_index;
            section.record_file_offset = reader.file(record, stride).value;
            section.name = name(raw.bytes, 0);
            section.segment_name = name(raw.bytes, 16);
            section.address = value(32, word);
            section.size = value(header.is_64 ? 40 : 36, word);
            section.raw_file_offset = static_cast<std::uint32_t>(value(header.is_64 ? 48 : 40));
            section.alignment = static_cast<std::uint32_t>(value(header.is_64 ? 52 : 44));
            section.relocation_offset = static_cast<std::uint32_t>(value(header.is_64 ? 56 : 48));
            section.relocation_count = static_cast<std::uint32_t>(value(header.is_64 ? 60 : 52));
            section.flags = static_cast<std::uint32_t>(value(header.is_64 ? 64 : 56));
            section.reserved1 = static_cast<std::uint32_t>(value(header.is_64 ? 68 : 60));
            section.reserved2 = static_cast<std::uint32_t>(value(header.is_64 ? 72 : 64));
            section.reserved3 = header.is_64 ? static_cast<std::uint32_t>(value(76)) : 0;
            address_extent(section.address, section.size, header.is_64);
            require(section.alignment < (header.is_64 ? 64u : 32u),
                    "Mach-O section alignment overflows its address width");
            if (!zero_fill(section.flags))
                section.file_offset = reader.file(section.raw_file_offset, section.size);
            budget.include(section.name.size() + section.segment_name.size());
            metadata.sections.push_back(std::move(section));
        }
        metadata.segments.push_back(std::move(segment));
    }
}
void map_segments(const MachOMetadata &metadata, ImageLayout &layout, Budget &budget, std::stop_token stop) {
    const auto &header = metadata.container.slices[metadata.selected_slice].header;
    if (header.file_type == 1) {
        for (const auto &section : metadata.sections) {
            canceled(stop);
            const auto permissions = metadata.segments[section.segment_index].initial_protection;
            budget.include(sizeof(ImageDomain) + sizeof(Segment) + section.name.size());
            layout.domains.push_back({{{section.ordinal}, layout.space.width_bits, 1, header.order},
                                      {layout.architecture, layout.mode, header.order}});
            layout.segments.push_back({section.name,
                                       {{section.ordinal}, 0},
                                       section.size,
                                       {section.file_offset ? section.file_offset->value : 0},
                                       section.file_offset ? section.size : 0,
                                       bool(permissions & 1),
                                       bool(permissions & 2),
                                       bool((permissions & 4) && (section.flags & 0x80000400))});
        }
        return;
    }
    struct Piece {
        std::uint64_t begin, end, file;
        bool initialized;
        std::uint32_t permissions;
    };
    struct Event {
        std::uint64_t at;
        std::size_t piece;
        bool start;
    };
    std::vector<Piece> pieces;
    std::vector<Event> events;
    const auto insert = [&](Piece piece) {
        if (piece.begin == piece.end)
            return;
        budget.include(sizeof(Piece) + 2 * sizeof(Event));
        const auto index = pieces.size();
        pieces.push_back(piece);
        events.push_back({piece.begin, index, true});
        events.push_back({piece.end, index, false});
    };
    for (const auto &segment : metadata.segments) {
        canceled(stop);
        if (!(segment.initial_protection & 7))
            continue;
        const auto end = add(segment.address, segment.memory_size);
        if (segment.flags & 1) {
            const auto start = end - segment.file_size;
            insert({segment.address, start, 0, false, segment.initial_protection});
            insert({start, end, segment.file_offset.value, true, segment.initial_protection});
        } else {
            const auto initialized_end = add(segment.address, segment.file_size);
            insert({segment.address, initialized_end, segment.file_offset.value, true, segment.initial_protection});
            insert({initialized_end, end, 0, false, segment.initial_protection});
        }
    }
    std::sort(events.begin(), events.end(), [](const auto &a, const auto &b) { return a.at < b.at; });
    std::set<std::size_t> active;
    std::map<std::uint64_t, std::size_t> backing;
    std::array<std::size_t, 3> permissions{};
    std::size_t zeros = 0, index = 0;
    std::uint64_t previous = events.empty() ? 0 : events.front().at;
    while (index < events.size()) {
        canceled(stop);
        const auto at = events[index].at;
        if (at > previous && !active.empty()) {
            require(zeros == active.size() || (zeros == 0 && backing.size() == 1),
                    "Conflicting Mach-O segment overlap backing", ErrorCode::unsupported);
            const auto &sample = pieces[*active.begin()];
            budget.include(sizeof(Segment) + 32);
            layout.segments.push_back({"SEG" + std::to_string(layout.segments.size()),
                                       {{0}, previous},
                                       at - previous,
                                       {sample.initialized ? add(sample.file, previous - sample.begin) : 0},
                                       sample.initialized ? at - previous : 0,
                                       permissions[0] != 0,
                                       permissions[1] != 0,
                                       permissions[2] != 0});
        }
        while (index < events.size() && events[index].at == at) {
            const auto &event = events[index++];
            const auto &piece = pieces[event.piece];
            if (event.start)
                active.insert(event.piece);
            else
                active.erase(event.piece);
            if (piece.initialized) {
                const auto key = piece.file - piece.begin;
                if (event.start)
                    ++backing[key];
                else if (--backing.at(key) == 0)
                    backing.erase(key);
            } else if (event.start)
                ++zeros;
            else
                --zeros;
            for (std::size_t bit = 0; bit < 3; ++bit)
                if (piece.permissions & (1u << bit)) {
                    if (event.start)
                        ++permissions[bit];
                    else
                        --permissions[bit];
                }
        }
        previous = at;
    }
}
} // namespace hexlab::macho_detail
