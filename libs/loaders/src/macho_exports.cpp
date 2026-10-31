#include "macho_dyld_internal.hpp"
#include <set>
#include <string_view>
namespace hexlab::macho_detail {
namespace {
bool valid_utf8(std::string_view text) {
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const auto first = static_cast<unsigned char>(text[cursor++]);
        if (first < 0x80)
            continue;
        unsigned count = 0;
        std::uint32_t value = 0, minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1;
            value = first & 0x1f;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2;
            value = first & 0x0f;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3;
            value = first & 0x07;
            minimum = 0x10000;
        } else
            return false;
        if (count > text.size() - cursor)
            return false;
        for (unsigned i = 0; i < count; ++i) {
            const auto next = static_cast<unsigned char>(text[cursor++]);
            if ((next & 0xc0) != 0x80)
                return false;
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
            return false;
    }
    return true;
}
} // namespace

void read_exports(const Reader &reader, const Image &image, MachOMetadata &metadata, std::uint32_t stream_id,
                  std::uint32_t libraries, std::optional<Address> header_anchor, Budget &budget, std::stop_token stop) {
    auto &stream = metadata.dyld_streams[stream_id];
    budget.include(stream.size);
    const auto bytes = reader.bytes(stream.raw_offset, stream.size);
    struct Frame {
        std::uint64_t node;
        std::size_t cursor, prefix_before;
        std::uint8_t children, next = 0;
    };
    std::vector<Frame> stack;
    std::set<std::uint64_t> active;
    std::set<std::string> names;
    std::string prefix;
    std::uint32_t index = 0;
    std::uint64_t work = 0;
    const auto charge = [&] {
        canceled(stop);
        require(work++ < 1000000, "Mach-O export trie traversal exceeds work budget", ErrorCode::resource_limit);
    };
    const auto relative_address = [&](std::uint64_t offset) -> std::optional<Address> {
        if (!header_anchor || offset > UINT64_MAX - header_anchor->offset)
            return {};
        const Address at{header_anchor->space, header_anchor->offset + offset};
        if (!image.segment_at(at))
            return {};
        return at;
    };
    const auto push = [&](std::uint64_t offset, std::size_t prefix_before) {
        charge();
        require(offset < bytes.bytes.size(), "Mach-O export child node exceeds trie payload");
        require(active.insert(offset).second, "Cyclic Mach-O export trie");
        budget.include(sizeof(Frame) + 64);
        StreamReader input(bytes.bytes, stop);
        input.cursor = static_cast<std::size_t>(offset);
        const auto size = input.uleb();
        const auto begin = input.cursor;
        require(size <= bytes.bytes.size() - begin, "Mach-O export terminal crosses trie payload");
        if (size) {
            require(metadata.dyld_exports.size() < 1000000, "Mach-O export record count exceeds budget",
                    ErrorCode::resource_limit);
            budget.include(sizeof(MachODyldExport) + prefix.size() * 2 + 64);
            MachODyldExport row;
            row.stream = stream_id;
            row.index = index++;
            row.name = prefix;
            row.record_file_offset = add(stream.offset.value, offset);
            row.terminal_file_offset = add(stream.offset.value, begin);
            row.terminal_size = static_cast<std::uint32_t>(size);
            StreamReader terminal(bytes.bytes.subspan(begin, static_cast<std::size_t>(size)), stop);
            row.flags = terminal.uleb();
            const auto kind = row.flags & 3;
            const bool terminal_layout_known = !(row.flags & ~UINT64_C(0x1f)) && kind != 3 &&
                !((row.flags & 8) && ((row.flags & 0x10) || kind != 0));
            if (!terminal_layout_known)
                row.complete = false;
            if (terminal_layout_known && (row.flags & 8)) {
                row.library_ordinal = terminal.uleb();
                require(*row.library_ordinal != 0 && *row.library_ordinal <= libraries,
                        "Mach-O reexport library ordinal exceeds dependency list");
                row.import_name = terminal.text();
                budget.include(row.import_name->size());
                if (!valid_utf8(*row.import_name))
                    row.complete = false;
            } else if (terminal_layout_known) {
                row.value = terminal.uleb();
                if (kind == 0) {
                    row.address = relative_address(*row.value);
                    if (!row.address)
                        row.complete = false;
                } // Absolute and thread-local values are not evidence of image pointers.
                if (row.flags & 0x10) {
                    row.resolver = terminal.uleb();
                    if (kind != 0)
                        row.complete = false;
                    else {
                        row.resolver_address = relative_address(*row.resolver);
                        if (!row.resolver_address)
                            row.complete = false;
                    }
                }
            }
            if (terminal_layout_known)
                require(terminal.end(), "Trailing bytes in known Mach-O export terminal");
            if (!valid_utf8(row.name))
                row.complete = false;
            if (!names.insert(row.name).second)
                row.complete = false;
            stream.complete = stream.complete && row.complete;
            metadata.dyld_exports.push_back(std::move(row));
        }
        input.cursor = begin + static_cast<std::size_t>(size);
        const auto children = input.byte();
        stack.push_back({offset, input.cursor, prefix_before, children, 0});
    };
    push(0, 0);
    while (!stack.empty()) {
        charge();
        auto &frame = stack.back();
        if (frame.next == frame.children) {
            prefix.resize(frame.prefix_before);
            active.erase(frame.node);
            stack.pop_back();
            continue;
        }
        StreamReader input(bytes.bytes, stop);
        input.cursor = frame.cursor;
        const auto edge = input.text();
        const auto before = prefix.size();
        require(edge.size() <= 65536 - prefix.size(), "Mach-O export name exceeds64KiB");
        const auto child = input.uleb();
        frame.cursor = input.cursor;
        ++frame.next;
        prefix += edge;
        push(child, before);
    }
    metadata.dyld_complete = metadata.dyld_complete && stream.complete;
}
} // namespace hexlab::macho_detail
