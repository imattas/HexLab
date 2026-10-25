#include "macho_dyld_internal.hpp"
#include "hexlab/image/macho_mapping.hpp"
#include <algorithm>
namespace hexlab::macho_detail {
namespace {
struct State {
    std::optional<std::uint32_t> segment;
    std::uint64_t offset = 0;
    std::uint8_t type = 1, flags = 0;
    std::optional<std::int32_t> ordinal;
    std::optional<std::string> symbol;
    std::int64_t addend = 0;
};
void map_fixup(const Image &image, const MachOMetadata &metadata, MachODyldFixup &row, bool &complete) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    const auto &segment = metadata.segments[row.segment_index];
    const auto extent = row.field_size ? row.field_size : 1;
    require(row.segment_offset <= segment.memory_size && extent <= segment.memory_size - row.segment_offset,
            "Mach-O dyld fixup field exceeds declared segment");
    if (slice.header.file_type == 1) {
        complete = false;
        return;
    }
    const Address at{{0}, add(segment.address, row.segment_offset)};
    if (!row.field_size) {
        if (image.segment_at(at))
            row.place = at;
        complete = false;
        return;
    }
    row.place = at;
    bool contiguous = true;
    std::optional<FileOffset> first;
    for (std::uint64_t i = 0; i < row.field_size; ++i) {
        const Address byte{at.space, add(at.offset, i)};
        require(image.segment_at(byte) != nullptr, "Mach-O dyld fixup crosses unmapped memory");
        const auto file = image.to_file_offset(byte);
        if (!file) {
            contiguous = false;
            continue;
        }
        if (i == 0)
            first = file.value();
        else if (!first || file.value().value != add(first->value, i))
            contiguous = false;
    }
    row.file_place = contiguous ? first : std::nullopt;
}
void parse_stream(const Reader &reader, const Image &image, MachOMetadata &metadata, std::uint32_t stream_id,
                  std::uint32_t libraries, std::optional<Address> header_anchor, Budget &budget, std::stop_token stop) {
    auto &stream = metadata.dyld_streams[stream_id];
    if (!stream.size)
        return;
    if (stream.kind == MachODyldStreamKind::exports) {
        read_exports(reader, image, metadata, stream_id, libraries, header_anchor, budget, stop);
        return;
    }
    if (stream.kind == MachODyldStreamKind::chained) {
        read_chained(reader, image, metadata, stream_id, libraries, header_anchor, budget, stop);
        return;
    }
    budget.include(stream.size);
    const auto bytes = reader.bytes(stream.raw_offset, stream.size);
    StreamReader input(bytes.bytes, stop);
    const bool rebase = stream.kind == MachODyldStreamKind::rebase;
    const bool lazy = stream.kind == MachODyldStreamKind::lazy_bind;
    const bool weak = stream.kind == MachODyldStreamKind::weak_bind;
    const auto pointer = metadata.container.slices[metadata.selected_slice].header.is_64 ? 8u : 4u;
    State state;
    bool terminated = false;
    std::uint32_t operation_index = 0;
    while (!input.end()) {
        canceled(stop);
        require(metadata.dyld_operations.size() < 1000000, "Mach-O dyld operation count exceeds budget",
                ErrorCode::resource_limit);
        budget.include(sizeof(MachODyldOperation));
        const auto begin = input.cursor;
        MachODyldOperation operation;
        operation.stream = stream_id;
        operation.index = operation_index++;
        operation.record_file_offset = add(stream.offset.value, begin);
        operation.byte = input.byte();
        const auto opcode = operation.byte & 0xf0, immediate = operation.byte & 0xf;
        const auto global_operation = static_cast<std::uint32_t>(metadata.dyld_operations.size());
        const auto advance = [&](std::uint64_t amount) { state.offset = add(state.offset, amount); };
        const auto segment = [&] {
            require(immediate < metadata.segments.size(), "Mach-O dyld segment ordinal exceeds command list");
            state.segment = static_cast<std::uint32_t>(immediate);
            state.offset = input.uleb();
            operation.first = state.offset;
            require(state.offset <= metadata.segments[*state.segment].memory_size,
                    "Mach-O dyld segment offset exceeds memory");
        };
        const auto ordinal = [&](std::int64_t value) {
            require(value >= INT32_MIN && value <= INT32_MAX && (value <= 0 || value <= libraries),
                    "Mach-O dyld library ordinal exceeds dependency list");
            state.ordinal = static_cast<std::int32_t>(value);
            if (value < -3)
                stream.complete = false;
        };
        const auto emit = [&](std::uint64_t count, std::uint64_t skip) {
            require(count <= 1000000 - metadata.dyld_fixups.size(), "Mach-O dyld fixup count exceeds budget",
                    ErrorCode::resource_limit);
            require(count == 0 || (state.segment && (rebase || (state.symbol && (weak || state.ordinal)))),
                    "Mach-O dyld fixup lacks explicit segment/symbol/library state");
            for (std::uint32_t i = 0; i < count; ++i) {
                canceled(stop);
                budget.include(sizeof(MachODyldFixup) + (state.symbol ? state.symbol->size() : 0));
                MachODyldFixup row;
                row.stream = stream_id;
                row.operation = global_operation;
                row.repeat_index = i;
                row.record_file_offset = operation.record_file_offset;
                row.segment_index = *state.segment;
                row.segment_offset = state.offset;
                row.type = state.type;
                row.field_size = static_cast<std::uint8_t>(state.type == 1                      ? pointer
                                                           : state.type == 2 || state.type == 3 ? 4
                                                                                                : 0);
                row.symbol_flags = state.flags;
                row.library_ordinal = state.ordinal;
                row.addend = state.addend;
                if (state.symbol)
                    row.symbol = *state.symbol;
                map_fixup(image, metadata, row, stream.complete);
                metadata.dyld_fixups.push_back(std::move(row));
                advance(add(pointer, skip));
            }
        };
        if (opcode == 0) {
            terminated = true;
            if (lazy)
                state = State{};
        } else {
            terminated = false;
            if (rebase) {
                switch (opcode) {
                case 0x10:
                    state.type = static_cast<std::uint8_t>(immediate);
                    break;
                case 0x20:
                    segment();
                    break;
                case 0x30:
                    operation.first = input.uleb();
                    advance(*operation.first);
                    break;
                case 0x40:
                    advance(std::uint64_t(immediate) * pointer);
                    break;
                case 0x50:
                    emit(immediate, 0);
                    break;
                case 0x60:
                    operation.first = input.uleb();
                    emit(*operation.first, 0);
                    break;
                case 0x70:
                    operation.first = input.uleb();
                    emit(1, *operation.first);
                    break;
                case 0x80:
                    operation.first = input.uleb();
                    operation.second = input.uleb();
                    emit(*operation.first, *operation.second);
                    break;
                default:
                    stream.complete = false;
                    break;
                }
            } else {
                switch (opcode) {
                case 0x10:
                    ordinal(immediate);
                    break;
                case 0x20:
                    operation.first = input.uleb();
                    require(*operation.first <= INT32_MAX, "Mach-O dyld library ordinal overflow");
                    ordinal(static_cast<std::int64_t>(*operation.first));
                    break;
                case 0x30:
                    ordinal(immediate == 0 ? 0 : immediate - 16);
                    break;
                case 0x40:
                    state.flags = static_cast<std::uint8_t>(immediate);
                    state.symbol = input.text();
                    budget.include(state.symbol->size() * 2);
                    operation.symbol = state.symbol;
                    break;
                case 0x50:
                    state.type = static_cast<std::uint8_t>(immediate);
                    break;
                case 0x60:
                    operation.signed_value = input.sleb();
                    state.addend = *operation.signed_value;
                    break;
                case 0x70:
                    segment();
                    break;
                case 0x80:
                    operation.first = input.uleb();
                    advance(*operation.first);
                    break;
                case 0x90:
                    emit(1, 0);
                    break;
                case 0xa0:
                    operation.first = input.uleb();
                    emit(1, *operation.first);
                    break;
                case 0xb0:
                    emit(1, std::uint64_t(immediate) * pointer);
                    break;
                case 0xc0:
                    operation.first = input.uleb();
                    operation.second = input.uleb();
                    emit(*operation.first, *operation.second);
                    break;
                case 0xd0:
                    if (immediate == 0)
                        operation.first = input.uleb();
                    stream.complete = false;
                    break;
                default:
                    stream.complete = false;
                    break;
                }
            }
        }
        operation.encoded_size = static_cast<std::uint32_t>(input.cursor - begin);
        metadata.dyld_operations.push_back(std::move(operation));
        if (!stream.complete)
            break;
        if (terminated && !lazy)
            break;
    }
    if (stream.complete)
        require(terminated, "Mach-O dyld stream has no terminator");
    metadata.dyld_complete = metadata.dyld_complete && stream.complete;
}
} // namespace
void read_dyld(const ByteStorage &storage, const Image &image, MachOMetadata &metadata, Budget &budget,
               std::stop_token stop) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    Reader reader(storage, slice, stop);
    const auto append = [&](const MachOLoadCommand &command, MachODyldStreamKind kind, std::uint32_t offset,
                            std::uint32_t size) {
        budget.include(sizeof(MachODyldStream));
        metadata.dyld_streams.push_back({command.index, kind, offset, size, reader.file(offset, size), true});
    };
    for (const auto &command : slice.header.commands) {
        canceled(stop);
        if (command.command == 0x22 || command.command == 0x80000022) {
            require(command.size >= 48, "Truncated Mach-O dyld_info command");
            const auto bytes = reader.bytes(command.file_offset - slice.offset, 48);
            for (std::uint32_t i = 0; i < 5; ++i)
                append(command, static_cast<MachODyldStreamKind>(i),
                       static_cast<std::uint32_t>(reader.value(bytes.bytes, 8 + i * 8, 4)),
                       static_cast<std::uint32_t>(reader.value(bytes.bytes, 12 + i * 8, 4)));
        } else if (command.command == 0x80000033 || command.command == 0x80000034) {
            require(command.size >= 16, "Truncated Mach-O dyld linkedit_data command");
            const auto bytes = reader.bytes(command.file_offset - slice.offset, 16);
            append(command, command.command == 0x80000033 ? MachODyldStreamKind::exports : MachODyldStreamKind::chained,
                   static_cast<std::uint32_t>(reader.value(bytes.bytes, 8, 4)),
                   static_cast<std::uint32_t>(reader.value(bytes.bytes, 12, 4)));
        }
    }
    const auto libraries =
        static_cast<std::uint32_t>(std::count_if(metadata.libraries.begin(), metadata.libraries.end(),
                                                 [](const auto &library) { return library.ordinal.has_value(); }));
    const auto header_anchor = take(macho_header_anchor(image, slice, stop));
    for (std::uint32_t i = 0; i < metadata.dyld_streams.size(); ++i)
        parse_stream(reader, image, metadata, i, libraries, header_anchor, budget, stop);
    // File-order scalar reads keep TrackingStorage dependencies bounded even
    // for descending streams, overlapping fixups and discontiguous VM fields.
    struct ByteRequest {
        std::uint64_t file;
        std::uint32_t row;
        std::uint8_t shift;
    };
    std::vector<ByteRequest> requests;
    for (std::uint32_t i = 0; i < metadata.dyld_fixups.size(); ++i) {
        auto &row = metadata.dyld_fixups[i];
        if (!row.place || !row.field_size)
            continue;
        row.encoded_value = 0;
        for (std::uint8_t byte = 0; byte < row.field_size; ++byte) {
            canceled(stop);
            const auto file = image.to_file_offset({row.place->space, add(row.place->offset, byte)});
            if (!file)
                continue; // Canonical zero-fill contributes zero bits.
            budget.include(sizeof(ByteRequest));
            requests.push_back(
                {file.value().value, i,
                 static_cast<std::uint8_t>(slice.header.order == ByteOrder::little ? byte * 8
                                                                                   : (row.field_size - byte - 1) * 8)});
        }
    }
    std::sort(requests.begin(), requests.end(), [stop](const auto &a, const auto &b) {
        canceled(stop);
        return a.file < b.file;
    });
    for (std::size_t i = 0; i < requests.size();) {
        const auto file = requests[i].file;
        const auto raw = reader.bytes(file - slice.offset, 1);
        do {
            canceled(stop);
            const auto &request = requests[i++];
            *metadata.dyld_fixups[request.row].encoded_value |= std::to_integer<std::uint64_t>(raw.bytes[0])
                                                                << request.shift;
        } while (i < requests.size() && requests[i].file == file);
    }
}
} // namespace hexlab::macho_detail
