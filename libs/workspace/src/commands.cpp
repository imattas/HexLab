#include "project_internal.hpp"
#include <array>
#include <cstddef>
#include <map>
#include <set>
#include <tuple>
namespace hexlab {
namespace {
struct FirmwareLine {
    std::uint64_t offset = 0;
    std::string text;
};
struct FirmwareRecordEdit {
    std::size_t record_index = 0;
    std::uint64_t within_record = 0;
    std::size_t replacement_offset = 0;
    std::size_t size = 0;
};
struct FirmwareRecordLineLayout {
    std::size_t data_offset = 0;
    std::size_t checksum_offset = 0;
    std::vector<std::uint8_t> bytes;
};

int firmware_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
std::uint8_t firmware_hex_byte(std::string_view line, std::size_t offset) {
    using namespace project_detail;
    require(offset + 2 <= line.size(), "Firmware record has a truncated hexadecimal byte", ErrorCode::integrity);
    const auto high = firmware_hex_digit(line[offset]);
    const auto low = firmware_hex_digit(line[offset + 1]);
    require(high >= 0 && low >= 0, "Firmware record contains a non-hexadecimal byte", ErrorCode::integrity);
    return static_cast<std::uint8_t>((high << 4) | low);
}
char firmware_hex_char(unsigned value) {
    constexpr char digits[] = "0123456789ABCDEF";
    return digits[value & 0xfu];
}
void write_firmware_hex_byte(std::string &line, std::size_t offset, std::uint8_t value) {
    line[offset] = firmware_hex_char(value >> 4);
    line[offset + 1] = firmware_hex_char(value);
}
FirmwareRecordLineLayout parse_firmware_data_record_line(std::string_view text, bool intel_hex) {
    using namespace project_detail;
    if (!text.empty() && text.back() == '\r') text.remove_suffix(1);
    require(text.size() <= (intel_hex ? 521u : 514u),
            "Firmware data record exceeds its format limit", ErrorCode::integrity);
    FirmwareRecordLineLayout output;
    if (intel_hex) {
        require(text.size() >= 11 && text.front() == ':' && (text.size() & 1u) == 1,
                "Invalid Intel HEX data record in loaded firmware metadata", ErrorCode::integrity);
        const auto count = firmware_hex_byte(text, 1);
        require(text.size() == 11u + static_cast<std::size_t>(count) * 2,
                "Intel HEX data record length changed after loading", ErrorCode::integrity);
        output.data_offset = 9;
        output.checksum_offset = 9 + static_cast<std::size_t>(count) * 2;
        output.bytes.reserve(static_cast<std::size_t>(count) + 5);
        for (std::size_t offset = 1; offset < text.size(); offset += 2)
            output.bytes.push_back(firmware_hex_byte(text, offset));
        require(output.bytes[3] == 0, "Loaded Intel HEX row is not a data record", ErrorCode::integrity);
        unsigned sum = 0;
        for (const auto byte : output.bytes) sum += byte;
        require((sum & 0xffu) == 0, "Intel HEX record checksum changed after loading", ErrorCode::integrity);
    } else {
        require(text.size() >= 10 && text[0] == 'S' && text[1] >= '1' && text[1] <= '3' &&
                    (text.size() & 1u) == 0,
                "Invalid S-record data record in loaded firmware metadata", ErrorCode::integrity);
        const auto type = static_cast<unsigned>(text[1] - '0');
        const unsigned address_bytes = type == 1 ? 2u : type == 2 ? 3u : 4u;
        const auto count = firmware_hex_byte(text, 2);
        require(count >= address_bytes + 1 && text.size() == 4u + static_cast<std::size_t>(count) * 2,
                "S-record data record length changed after loading", ErrorCode::integrity);
        output.data_offset = 4 + static_cast<std::size_t>(address_bytes) * 2;
        output.checksum_offset = text.size() - 2;
        output.bytes.reserve(static_cast<std::size_t>(count) + 1);
        for (std::size_t offset = 2; offset < text.size(); offset += 2)
            output.bytes.push_back(firmware_hex_byte(text, offset));
        unsigned sum = 0;
        for (const auto byte : output.bytes) sum += byte;
        require((sum & 0xffu) == 0xffu, "S-record checksum changed after loading", ErrorCode::integrity);
    }
    return output;
}

std::vector<PatchSpan> regenerate_firmware_record_patches(const ProjectSnapshot &snapshot, Address address,
                                                          std::span<const std::byte> replacement,
                                                          std::stop_token stop) {
    using namespace project_detail;
    require(snapshot.loaded && snapshot.loaded->metadata.firmware,
            "Virtual-address record regeneration requires loaded firmware metadata", ErrorCode::unsupported);
    const auto &metadata = *snapshot.loaded->metadata.firmware;
    const auto records = std::span(metadata.records);
    require(!records.empty(), "Firmware image contains no patchable data records", ErrorCode::out_of_bounds);
    require(replacement.size() <= 16u * 1024u * 1024u,
            "Patch must contain 1 to 16 MiB of bytes", ErrorCode::resource_limit);
    require(!replacement.empty(), "Patch must contain 1 to 16 MiB of bytes");
    require(records.size() <= 4'000'000, "Firmware record count exceeds its parser limit", ErrorCode::resource_limit);

    std::vector<FirmwareRecordEdit> edits;
    std::uint64_t consumed = 0;
    while (consumed < replacement.size()) {
        canceled(stop);
        const auto target = take(advance(address, consumed));
        auto row = std::upper_bound(records.begin(), records.end(), target.offset,
                                    [](std::uint64_t value, const FirmwareDataRecord &record) {
                                        return value < record.address.offset;
                                    });
        require(row != records.begin(), "Firmware patch begins outside a data record", ErrorCode::out_of_bounds);
        --row;
        require(row->address.space == target.space && target.offset >= row->address.offset,
                "Firmware patch crosses an unmapped address", ErrorCode::out_of_bounds);
        const auto within = target.offset - row->address.offset;
        require(within < row->size, "Firmware patch crosses a gap between data records", ErrorCode::out_of_bounds);
        const auto amount64 = std::min<std::uint64_t>(replacement.size() - consumed, row->size - within);
        const auto amount = static_cast<std::size_t>(amount64);
        require(edits.size() < 65'536 || (!edits.empty() && edits.back().record_index == static_cast<std::size_t>(row - records.begin())),
                "Firmware patch touches more than 65,536 source records", ErrorCode::resource_limit);
        edits.push_back({static_cast<std::size_t>(row - records.begin()), within,
                         static_cast<std::size_t>(consumed), amount});
        consumed += amount;
    }

    std::map<std::uint64_t, std::size_t> lines_to_records;
    for (const auto &edit : edits) {
        const auto line = records[edit.record_index].source_line;
        require(line != 0, "Firmware record lacks source-line provenance", ErrorCode::integrity);
        require(lines_to_records.emplace(line, edit.record_index).second,
                "Firmware metadata maps multiple data records to one source line", ErrorCode::integrity);
    }
    std::map<std::uint64_t, FirmwareLine> source_lines;
    std::string current_line;
    std::uint64_t line_number = 1, line_start = 0;
    bool collect_line = lines_to_records.contains(line_number);
    const auto finish_line = [&](std::uint64_t number, std::uint64_t offset, std::string &line) {
        if (lines_to_records.contains(number)) {
            require(line.size() <= 521, "Firmware source line exceeds its format limit", ErrorCode::integrity);
            source_lines.emplace(number, FirmwareLine{offset, line});
        }
        line.clear();
    };
    for (std::uint64_t offset = 0; offset < snapshot.effective->size();) {
        canceled(stop);
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(64 * 1024, snapshot.effective->size() - offset));
        const auto view = take(snapshot.effective->read_at({offset}, count));
        require(view.bytes.size() == count, "Firmware source returned a short read", ErrorCode::io);
        for (std::size_t index = 0; index < count; ++index) {
            const auto value = static_cast<char>(std::to_integer<unsigned char>(view.bytes[index]));
            if (value == '\n') {
                finish_line(line_number, line_start, current_line);
                ++line_number;
                line_start = offset + index + 1;
                collect_line = lines_to_records.contains(line_number);
            } else if (collect_line) {
                current_line.push_back(value);
                require(current_line.size() <= 521, "Firmware source line exceeds its format limit", ErrorCode::integrity);
            }
        }
        offset += count;
    }
    if (line_start < snapshot.effective->size() || lines_to_records.contains(line_number))
        finish_line(line_number, line_start, current_line);
    require(source_lines.size() == lines_to_records.size(),
            "Firmware source lines no longer match the loaded record metadata", ErrorCode::integrity);

    std::vector<PatchSpan> output;
    output.reserve(edits.size());
    for (const auto &edit : edits) {
        canceled(stop);
        const auto &record = records[edit.record_index];
        const auto current_bytes = take(snapshot.loaded->image->storage()->read_at(
            {take(checked_add(record.packed_file_offset.value, edit.within_record))}, edit.size));
        require(current_bytes.bytes.size() == edit.size, "Packed firmware record read is incomplete", ErrorCode::io);
        const auto new_bytes = replacement.subspan(edit.replacement_offset, edit.size);
        if (std::equal(new_bytes.begin(), new_bytes.end(), current_bytes.bytes.begin())) continue;

        auto line = source_lines.at(record.source_line).text;
        auto layout = parse_firmware_data_record_line(line, metadata.intel_hex);
        const auto data_size = metadata.intel_hex
            ? static_cast<std::size_t>(layout.bytes[0])
            : static_cast<std::size_t>(layout.bytes[0] - ((line[1] == '1') ? 2 : (line[1] == '2') ? 3 : 4) - 1);
        require(data_size == record.size, "Firmware source line does not match its loaded data record", ErrorCode::integrity);
        for (std::size_t index = 0; index < edit.size; ++index) {
            const auto value = std::to_integer<std::uint8_t>(new_bytes[index]);
            const auto text_offset = layout.data_offset + static_cast<std::size_t>(edit.within_record) * 2 + index * 2;
            require(text_offset + 2 <= layout.checksum_offset,
                    "Firmware payload byte lies outside its source data field", ErrorCode::integrity);
            write_firmware_hex_byte(line, text_offset, value);
            layout.bytes[(metadata.intel_hex ? 4u : 1u + ((line[1] == '1') ? 2u : (line[1] == '2') ? 3u : 4u)) +
                         static_cast<std::size_t>(edit.within_record) + index] = value;
        }
        unsigned sum = 0;
        for (std::size_t index = 0; index + 1 < layout.bytes.size(); ++index) sum += layout.bytes[index];
        const auto checksum = metadata.intel_hex ? static_cast<std::uint8_t>(0u - sum)
                                                 : static_cast<std::uint8_t>(0xffu - (sum & 0xffu));
        write_firmware_hex_byte(line, layout.checksum_offset, checksum);

        const auto source = source_lines.at(record.source_line);
        const auto original = take(snapshot.original->read_at({source.offset}, line.size()));
        require(original.bytes.size() == line.size(), "Original firmware source line is incomplete", ErrorCode::io);
        std::vector<std::byte> replacement_line;
        replacement_line.reserve(line.size());
        for (const auto character : line) replacement_line.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
        output.push_back({{source.offset}, {original.bytes.begin(), original.bytes.end()}, std::move(replacement_line)});
    }
    return output;
}

bool valid_utf8_name(std::string_view value){
    std::size_t i=0;while(i<value.size()){
        const auto first=static_cast<unsigned char>(value[i++]);std::uint32_t cp=first;unsigned count=0;std::uint32_t minimum=0;
        if(first>=0xc2&&first<=0xdf){cp=first&31;count=1;minimum=0x80;}
        else if(first>=0xe0&&first<=0xef){cp=first&15;count=2;minimum=0x800;}
        else if(first>=0xf0&&first<=0xf4){cp=first&7;count=3;minimum=0x10000;}
        else if(first>=0x80)return false;
        if(count>value.size()-i)return false;
        for(unsigned j=0;j<count;++j){const auto next=static_cast<unsigned char>(value[i++]);if((next&0xc0)!=0x80)return false;cp=(cp<<6)|(next&63);}
        if(cp<minimum||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff)||cp==0||cp<32||(cp>=127&&cp<=159))return false;
    }return !value.empty();
}
bool same_declaration_content(const database::TypeDefinition& current,
                               const database::TypeDefinition& expected) {
    if (current.id != expected.id || current.name != expected.name || current.origin != expected.origin ||
        current.declaration_kind != expected.declaration_kind || !current.type || !expected.type) return false;
    const auto current_type = types::encode(*current.type);
    const auto expected_type = types::encode(*expected.type);
    return current_type && expected_type && current_type.value() == expected_type.value();
}
}
Result<database::StateDelta> validate_command(const ProjectSnapshot &snapshot, const ProjectCommand &command,
                                               std::stop_token stop) {
    return project_detail::guarded([&]() -> Result<database::StateDelta> {
        using namespace project_detail;
        using namespace database;
        require(bool(snapshot.state) && bool(snapshot.state->user) && bool(snapshot.original) &&
                    bool(snapshot.effective),
                "No project is open");
        require(snapshot.mode == ProjectMode::read_write, "Project is read only", ErrorCode::read_only);
        StateDelta delta;
        auto user = *snapshot.state->user;
        auto next = snapshot.state->next_entity;
        const auto allocate = [&]() {
            require(next > 0 && next < UINT64_MAX - 1, "Project entity identities are exhausted",
                    ErrorCode::resource_limit);
            return next++;
        };
        const auto change = [&]<class T>(std::vector<T> &rows, auto found, std::optional<T> after) {
            std::optional<T> before;
            if (found != rows.end())
                before = *found;
            require(before != after, "Command contains no changes");
            delta.changes.emplace_back(EntityChange<T>{before, after});
            if (found != rows.end()) {
                if (after)
                    *found = *after;
                else
                    rows.erase(found);
            } else if (after)
                rows.push_back(*after);
        };
        const auto function_change = [&](Address entry, auto update) {
            auto &rows = user.decisions.functions;
            auto found = std::find_if(rows.begin(), rows.end(), [&](auto &row) { return row.entry == entry; });
            FunctionDecision value = found == rows.end() ? FunctionDecision{allocate(), entry, false, {}} : *found;
            update(value);
            change(rows, found, std::optional{std::move(value)});
        };
        std::visit(
            [&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, Rename> || std::is_same_v<T, Comment>) {
                    check_location(snapshot, value.location, true);
                    auto &rows = user.annotations;
                    auto found = std::find_if(rows.begin(), rows.end(),
                                              [&](auto &row) { return row.location == value.location; });
                    Annotation row = found == rows.end() ? Annotation{allocate(), value.location, {}, {}} : *found;
                    if constexpr (std::is_same_v<T, Rename>) {
                        require(std::holds_alternative<Address>(value.location), "Names require a virtual address");
                        if (!value.name.empty())
                            for (auto &existing : rows)
                                if (existing.location != value.location && existing.name == value.name) {
                                    auto address = std::get_if<Address>(&existing.location);
                                    if (address && address->space == std::get<Address>(value.location).space)
                                        throw Failure{{ErrorCode::conflict, "Name already exists at address " +
                                                                                std::to_string(address->offset)}};
                                }
                        row.name = value.name;
                    } else
                        row.comment = value.text;
                    change(rows, found,
                           row.name.empty() && row.comment.empty() ? std::optional<Annotation>{}
                                                                   : std::optional{std::move(row)});
                } else if constexpr (std::is_same_v<T, BookmarkCommand>) {
                    auto &rows = user.bookmarks;
                    auto found = std::find_if(rows.begin(), rows.end(),
                                              [&](auto &row) { return row.location == value.location; });
                    if (!value.remove)
                        check_location(snapshot, value.location);
                    require(!value.remove || found != rows.end(), "No bookmark exists at this location");
                    std::optional<database::Bookmark> after;
                    if (!value.remove)
                        after = database::Bookmark{found == rows.end() ? allocate() : found->id, value.location,
                                                   value.label};
                    change(rows, found, std::move(after));
                } else if constexpr (std::is_same_v<T, SetProjectBreakpoint>) {
                    auto &rows=user.breakpoints;
                    auto found=std::find_if(rows.begin(),rows.end(),[&](const auto& row){return row.address==value.address;});
                    if(!value.remove) check_range(snapshot,value.address,1,false);
                    require(!value.remove || found!=rows.end(),"No project breakpoint exists at this address");
                    require(static_cast<unsigned>(value.kind)<=5,"Unknown project breakpoint kind");
                    require(value.size==1||value.size==2||value.size==4||value.size==8,"Project breakpoint size must be 1, 2, 4, or 8 bytes");
                    if(value.kind==ProjectBreakpointKind::software||value.kind==ProjectBreakpointKind::hardware||value.kind==ProjectBreakpointKind::execute)require(value.size==1,"Execution breakpoints have a fixed size of one byte");
                    require(value.condition.size()<=256,"Project breakpoint condition exceeds 256 bytes");
                    require(value.log_message.size()<=1024,"Project breakpoint log message exceeds 1024 bytes");
                    std::optional<ProjectBreakpoint> after;
                    if(!value.remove) after=ProjectBreakpoint{found==rows.end()?allocate():found->id,value.address,value.kind,value.enabled,value.size,value.condition,value.logpoint,value.log_message,value.ignore_count,value.one_shot};
                    change(rows,found,std::move(after));
                } else if constexpr (std::is_same_v<T, PatchBytes>) {
                    require(!value.replacement.empty() && value.replacement.size() <= 16 * 1024 * 1024,
                            "Patch must contain 1 to 16 MiB of bytes");
                    auto patches = user.patches;
                    if (auto file = std::get_if<FileOffset>(&value.location)) {
                        auto original = take(snapshot.original->read_at(*file, value.replacement.size()));
                        require(original.bytes.size() == value.replacement.size(),
                                "Original source returned a short patch read", ErrorCode::io);
                        patches.push_back({*file, {original.bytes.begin(), original.bytes.end()}, value.replacement});
                    } else {
                        const auto address = std::get<Address>(value.location);
                        check_range(snapshot, address, value.replacement.size(), false);
                        if (snapshot.loaded && snapshot.loaded->image->storage() != snapshot.effective) {
                            auto firmware_patches = regenerate_firmware_record_patches(
                                snapshot, address, value.replacement, stop);
                            patches.insert(patches.end(), std::make_move_iterator(firmware_patches.begin()),
                                           std::make_move_iterator(firmware_patches.end()));
                        } else {
                            require(bool(snapshot.loaded), "Virtual-address patches require a loaded image mapping");
                            auto &image = *snapshot.loaded->image;
                            const auto begin = take(image.to_file_offset(address));
                            uint64_t consumed = 0;
                            while (consumed < value.replacement.size()) {
                                auto cursor = take(advance(address, consumed));
                                auto segment = image.segment_at(cursor);
                                auto current = take(image.to_file_offset(cursor));
                                require(current.value == take(checked_add(begin.value, consumed)),
                                        "VA patch is not contiguous in file storage");
                                consumed += std::min<std::uint64_t>(value.replacement.size() - consumed,
                                    segment->file_size - (cursor.offset - segment->begin.offset));
                            }
                            auto original = take(snapshot.original->read_at(begin, value.replacement.size()));
                            require(original.bytes.size() == value.replacement.size(),
                                    "Original source returned a short patch read", ErrorCode::io);
                            patches.push_back({begin, {original.bytes.begin(), original.bytes.end()}, value.replacement});
                        }
                    }
                    auto normalized = take(PatchSet::create(*snapshot.original, patches));
                    std::vector<PatchSpan> after(normalized->spans().begin(), normalized->spans().end());
                    require(after != user.patches, "Patch contains no effective changes");
                    delta.changes.emplace_back(PatchChange{user.patches, after});
                    user.patches = std::move(after);
                } else if constexpr (std::is_same_v<T, DefineRegion>) {
                    check_range(snapshot, value.begin, value.size, true);
                    require(value.kind == RegionKind::code || value.kind == RegionKind::data, "Unknown decision kind");
                    if (value.kind == RegionKind::code)
                        require(decision_instruction(snapshot, value.begin).length <= value.size,
                                "Code range cuts its entry instruction");
                    auto end = take(advance(value.begin, value.size));
                    auto &rows = user.decisions.regions;
                    auto found = rows.end();
                    for (auto it = rows.begin(); it != rows.end(); ++it)
                        if (it->begin.space == value.begin.space && it->begin.offset < end.offset &&
                            value.begin.offset < it->begin.offset + it->size) {
                            require(it->begin == value.begin && it->size == value.size,
                                    "Decision overlaps an existing range; replace its full extent");
                            found = it;
                        }
                    RegionDecision row{found == rows.end() ? allocate() : found->id, value.begin, value.size,
                                       value.kind};
                    change(rows, found, std::optional{row});
                } else if constexpr (std::is_same_v<T, DefineFunction>) {
                    check_range(snapshot, value.entry, 1, false);
                    auto instruction = decision_instruction(snapshot, value.entry);
                    bool permitted = snapshot.loaded->image->segment_at(value.entry)->executable;
                    for (auto &region : user.decisions.regions)
                        if (region.begin.space == value.entry.space && value.entry.offset >= region.begin.offset &&
                            value.entry.offset - region.begin.offset < region.size) {
                            require(region.kind != RegionKind::data, "Function entry is marked as data");
                            permitted = instruction.length <= region.size - (value.entry.offset - region.begin.offset);
                        }
                    require(permitted, "Define an explicit code range before a function in non-executable bytes");
                    function_change(value.entry, [](auto &row) { row.suppressed = false; });
                } else if constexpr (std::is_same_v<T, SetFunctionChunks>) {
                    decision_instruction(snapshot, value.entry);
                    require(value.chunks.size() <= project_record_limit,
                            "Explicit function chunks exceed the project budget");
                    if (value.chunks.empty()) {
                        auto found = std::find_if(user.decisions.functions.begin(), user.decisions.functions.end(),
                                                  [&](auto &row) { return row.entry == value.entry; });
                        require(found != user.decisions.functions.end() && !found->chunks.empty(),
                                "This function has no explicit chunks to clear");
                    }
                    bool contains = false;
                    for (auto &chunk : value.chunks) {
                        require(chunk.begin.space == value.entry.space,
                                "Function chunks require the entry address space");
                        check_range(snapshot, chunk.begin, chunk.size, true);
                        contains = contains || (chunk.begin.offset <= value.entry.offset &&
                                                value.entry.offset - chunk.begin.offset < chunk.size);
                    }
                    require(value.chunks.empty() || contains, "Function chunks must include the entry");
                    function_change(value.entry, [&](auto &row) { row.chunks = value.chunks; });
                } else if constexpr (std::is_same_v<T, SuppressFunction>) {
                    check_boundary(snapshot, value.entry);
                    check_location(snapshot, value.entry);
                    bool exists = std::any_of(user.decisions.functions.begin(), user.decisions.functions.end(),
                                              [&](auto &row) { return row.entry == value.entry; });
                    if (snapshot.functions)
                        exists = exists ||
                                 std::any_of(snapshot.functions->functions.begin(), snapshot.functions->functions.end(),
                                             [&](auto &row) { return row->entry == value.entry; });
                    require(exists, "Suppression requires an established function entry");
                    function_change(value.entry, [&](auto &row) { row.suppressed = value.suppressed; });
                } else if constexpr (std::is_same_v<T, ResetFunctionOverride>) {
                    check_location(snapshot, value.entry);
                    auto &rows = user.decisions.functions;
                    auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) { return row.entry == value.entry; });
                    require(found != rows.end(), "Function has no explicit override to reset");
                    change(rows, found, std::optional<FunctionDecision>{});
                } else if constexpr (std::is_same_v<T, SetReference>) {
                    auto &rows = user.decisions.references;
                    auto found = std::find_if(rows.begin(), rows.end(), [&](auto &row) {
                        return row.source == value.source && row.target == value.target && row.kind == value.kind;
                    });
                    if (!value.remove) {
                        check_location(snapshot, value.source);
                        check_location(snapshot, value.target);
                    }
                    require(!value.remove || found != rows.end(), "Explicit reference does not exist");
                    std::optional<UserReference> after;
                    if (!value.remove)
                        after = UserReference{found == rows.end() ? allocate() : found->id, value.source, value.target,
                                              value.kind};
                    change(rows, found, std::move(after));
                } else if constexpr (std::is_same_v<T, DefineType>) {
                    require(value.type!=nullptr,"Type definition is empty");
                    require(std::none_of(user.types.begin(),user.types.end(),[&](const auto& row){return row.name==value.name;}),"Type name already exists",ErrorCode::conflict);
                    auto valid=types::encode(*value.type);require(bool(valid),"Type definition is invalid");
                    auto row=TypeDefinition{allocate(),value.name,value.type};
                    require(!value.name.empty(),"Type name is required");
                    delta.changes.emplace_back(TypeDefinitionChange{{},row});user.types.push_back(std::move(row));
                } else if constexpr (std::is_same_v<T, UpdateType>) {
                    require(value.type_id != 0, "Type definition identity is required");
                    auto found = std::find_if(user.types.begin(), user.types.end(),
                                              [&](const auto &row) { return row.id == value.type_id; });
                    require(found != user.types.end(), "Unknown type definition identity");
                    require(!value.name.empty() && value.name.size() <= 512, "Type name is required and limited to 512 bytes");
                    require(std::none_of(user.types.begin(), user.types.end(), [&](const auto &row) {
                                return row.id != value.type_id && row.name == value.name;
                            }), "Type name already exists", ErrorCode::conflict);
                    require(value.type != nullptr, "Type definition is empty");
                    auto valid = types::encode(*value.type);
                    require(bool(valid), "Type definition is invalid");
                    TypeDefinition updated{found->id, value.name, value.type, found->origin, found->declaration_kind};
                    change(user.types, found, std::optional<TypeDefinition>{std::move(updated)});
                } else if constexpr (std::is_same_v<T, AssignType>) {
                    check_location(snapshot,value.location);
                    auto& rows=user.type_assignments;
                    auto found=std::find_if(rows.begin(),rows.end(),[&](const auto& row){return row.location==Location{value.location};});
                    require(value.remove || std::any_of(user.types.begin(),user.types.end(),[&](const auto& row){return row.id==value.type_id;}),"Unknown type definition");
                    require(!value.remove || found!=rows.end(),"No type is assigned at this address");
                    std::optional<TypeAssignment> after;
                    if(!value.remove)after=TypeAssignment{found==rows.end()?allocate():found->id,value.location,value.type_id};
                    change(rows,found,std::move(after));
                } else if constexpr (std::is_same_v<T, RenameStackLocal>) {
                    require(!value.access_sites.empty() && value.access_sites.size() <= 4096,
                            "Stack-local rename requires 1 to 4096 access sites", ErrorCode::resource_limit);
                    require((value.name.empty() || valid_utf8_name(value.name)) && value.name.size() <= 1024,
                            "Stack-local name is invalid or exceeds 1024 bytes");
                    auto sites = value.access_sites;
                    std::sort(sites.begin(), sites.end(), [](Address a, Address b) {
                        return std::pair{a.space.value, a.offset} < std::pair{b.space.value, b.offset};
                    });
                    require(std::adjacent_find(sites.begin(), sites.end()) == sites.end(),
                            "Stack-local rename contains duplicate access sites");
                    require(std::all_of(sites.begin(), sites.end(), [&](Address address) {
                                return address.space == sites.front().space;
                            }), "Stack-local access sites must share one address space");
                    for (const auto address : sites) check_location(snapshot, Location{address}, true);
                    auto &rows = user.annotations;
                    for (const auto address : sites) {
                        const auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) {
                            return row.location == Location{address};
                        });
                        require(found == rows.end() || found->name.empty() ||
                                    found->name == value.expected_name,
                                "A stack-local access site has a conflicting annotation name", ErrorCode::conflict);
                    }
                    if (!value.name.empty()) for (const auto &existing : rows) {
                        const auto address = std::get_if<Address>(&existing.location);
                        if (!address || address->space != sites.front().space || existing.name != value.name ||
                            std::binary_search(sites.begin(), sites.end(), *address, [](Address a, Address b) {
                                return std::pair{a.space.value, a.offset} < std::pair{b.space.value, b.offset};
                            })) continue;
                        throw Failure{{ErrorCode::conflict, "Name already exists at address " +
                                                               std::to_string(address->offset)}};
                    }
                    for (const auto address : sites) {
                        const Location location{address};
                        auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) {
                            return row.location == location;
                        });
                        Annotation row = found == rows.end() ? Annotation{allocate(), location, {}, {}} : *found;
                        row.name = value.name;
                        change(rows, found, row.name.empty() && row.comment.empty()
                                                ? std::optional<Annotation>{}
                                                : std::optional{std::move(row)});
                    }
                } else if constexpr (std::is_same_v<T, AssignStackLocalType>) {
                    require(!value.access_sites.empty() && value.access_sites.size() <= 4096,
                            "Stack-local type assignment requires 1 to 4096 access sites", ErrorCode::resource_limit);
                    auto sites = value.access_sites;
                    std::sort(sites.begin(), sites.end(), [](Address a, Address b) {
                        return std::pair{a.space.value, a.offset} < std::pair{b.space.value, b.offset};
                    });
                    require(std::adjacent_find(sites.begin(), sites.end()) == sites.end(),
                            "Stack-local type assignment contains duplicate access sites");
                    require(std::all_of(sites.begin(), sites.end(), [&](Address address) {
                                return address.space == sites.front().space;
                            }), "Stack-local access sites must share one address space");
                    for (const auto address : sites) check_location(snapshot, Location{address});
                    require(value.remove || std::any_of(user.types.begin(), user.types.end(),
                        [&](const auto &row) { return row.id == value.type_id; }), "Unknown type definition");
                    auto &rows = user.type_assignments;
                    for (const auto address : sites) {
                        const auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) {
                            return row.location == Location{address};
                        });
                        require(found == rows.end() ||
                                    (value.expected_type_id && found->type_id == *value.expected_type_id),
                                "A stack-local access site has a conflicting type assignment", ErrorCode::conflict);
                    }
                    for (const auto address : sites) {
                        auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) {
                            return row.location == Location{address};
                        });
                        if (value.remove) {
                            if (found != rows.end()) change(rows, found, std::optional<TypeAssignment>{});
                        } else if (found == rows.end() || found->type_id != value.type_id) {
                            change(rows, found, std::optional<TypeAssignment>{TypeAssignment{
                                found == rows.end() ? allocate() : found->id, address, value.type_id}});
                        }
                    }
                } else if constexpr (std::is_same_v<T, ImportPortableTypes>) {
                    // Validate the complete graph before staging any row changes. This command
                    // is intentionally atomic because imported assignments refer to names,
                    // while destination type IDs are allocated only here.
                    std::set<std::string, std::less<>> incoming_names;
                    for (const auto &definition : value.definitions) {
                        require(definition.type != nullptr && valid_utf8_name(definition.name) && definition.name.size() <= 512,
                                "Portable type definition has an invalid name or empty type");
                        require(bool(types::encode(*definition.type)), "Portable type definition is invalid");
                        require(declaration_type_matches(definition.declaration_kind, definition.type.get()),
                                "Portable declaration kind does not match its type");
                        require(incoming_names.insert(definition.name).second, "Portable type import contains duplicate names");
                        auto found = std::find_if(user.types.begin(), user.types.end(), [&](const auto &row) { return row.name == definition.name; });
                        require((found == user.types.end() && !definition.existing_id) ||
                                    (found != user.types.end() && definition.existing_id == found->id),
                                "Portable type destination changed after import planning", ErrorCode::conflict);
                        if (definition.expected_existing)
                            require(found != user.types.end() && definition.existing_id &&
                                        definition.expected_existing->id == *definition.existing_id &&
                                        definition.expected_existing->name == definition.name &&
                                        same_declaration_content(*found, *definition.expected_existing),
                                    "Portable declaration content changed after import planning", ErrorCode::conflict);
                    }
                    for (const auto &assignment : value.assignments) {
                        check_location(snapshot, assignment.location);
                        require(!assignment.type_name.empty() &&
                                    (incoming_names.contains(assignment.type_name) || std::any_of(user.types.begin(), user.types.end(), [&](const auto &row) { return row.name == assignment.type_name; })),
                                "Portable type assignment refers to an unknown type");
                    }
                    std::map<std::string, std::uint64_t, std::less<>> imported_ids;
                    for (const auto &definition : value.definitions) {
                        auto &rows = user.types;
                        auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) { return row.name == definition.name; });
                        if (found == rows.end()) {
                            TypeDefinition row{allocate(), definition.name, definition.type, definition.origin, definition.declaration_kind};
                            delta.changes.emplace_back(TypeDefinitionChange{{}, row});
                            rows.push_back(row);
                            imported_ids.emplace(definition.name, row.id);
                        } else {
                            imported_ids.emplace(definition.name, found->id);
                            if (found->type->id() != definition.type->id() || found->origin != definition.origin || found->declaration_kind != definition.declaration_kind) {
                                TypeDefinition updated{found->id, definition.name, definition.type, definition.origin, definition.declaration_kind};
                                change(rows, found, std::optional<TypeDefinition>{std::move(updated)});
                            }
                        }
                    }
                    for (const auto &assignment : value.assignments) {
                        auto type = imported_ids.find(assignment.type_name);
                        const auto type_id = type != imported_ids.end() ? type->second :
                            std::find_if(user.types.begin(), user.types.end(), [&](const auto &row) { return row.name == assignment.type_name; })->id;
                        auto &rows = user.type_assignments;
                        auto found = std::find_if(rows.begin(), rows.end(), [&](const auto &row) { return row.location == assignment.location; });
                        if (found != rows.end() && found->type_id == type_id) continue;
                        TypeAssignment row{found == rows.end() ? allocate() : found->id, assignment.location, type_id};
                        change(rows, found, std::optional<TypeAssignment>{std::move(row)});
                    }
                } else if constexpr (std::is_same_v<T, ImportPortableDebugVariables>) {
                    require(!value.variables.empty(), "Portable debug-variable import is empty");
                    require(value.variables.size() <= project_record_limit,
                            "Portable debug-variable import exceeds the row limit", ErrorCode::resource_limit);
                    using OriginKey = std::tuple<std::string, std::string, std::uint64_t, std::uint64_t>;
                    std::set<OriginKey> origins;
                    for (const auto &incoming : value.variables) {
                        require(valid_utf8_name(incoming.name) && incoming.name.size() <= 1024,
                                "Portable debug variable has an invalid name");
                        require(valid_utf8_name(incoming.origin.source_id) && incoming.origin.source_id.size() <= 1024 &&
                                    valid_utf8_name(incoming.origin.section) && incoming.origin.section.size() <= 256 &&
                                    incoming.origin.record_size > 0,
                                "Portable debug variable has an invalid source origin");
                        const OriginKey key{incoming.origin.source_id, incoming.origin.section,
                                            incoming.origin.unit_offset, incoming.origin.record_offset};
                        require(origins.insert(key).second, "Portable debug-variable import contains duplicate origins");
                        check_location(snapshot, Location{incoming.function_entry});
                        require(std::any_of(user.decisions.functions.begin(), user.decisions.functions.end(),
                                    [&](const auto &function) { return function.entry == incoming.function_entry; }),
                                "Portable debug variable references an unknown function");
                        if (incoming.address) check_location(snapshot, Location{*incoming.address});
                        require(incoming.location_expression.size() <= 65536 &&
                                    incoming.location_operations.size() <= 4096 &&
                                    incoming.location_ranges.size() <= 4096,
                                "Portable debug-variable location exceeds its storage budget", ErrorCode::resource_limit);
                        require(!(incoming.address && !incoming.location_expression.empty()) &&
                                    (!incoming.cfa_offset || (!incoming.address && !incoming.location_expression.empty())),
                                "Portable debug variable has conflicting location forms");
                        for (const auto &operation : incoming.location_operations)
                            require(operation.kind <= 20 && (operation.kind != 16 || operation.second_unsigned_operand <= 9) &&
                                        !incoming.location_expression.empty() &&
                                        operation.expression_offset < incoming.location_expression.size(),
                                    "Portable debug variable has an invalid location operation");
                        std::size_t range_expression_bytes = 0, range_operations = 0, range_payload = 4;
                        bool default_range_seen = false;
                        for (const auto &range : incoming.location_ranges) {
                            const bool is_default = range.begin == UINT64_MAX && range.end == UINT64_MAX;
                            require((range.begin < range.end || is_default) && (!is_default || !default_range_seen),
                                    "Portable debug variable has an invalid or duplicate default range");
                            default_range_seen = default_range_seen || is_default;
                            require(range.expression.size() <= 65536 - range_expression_bytes &&
                                        range.operations.size() <= 4096 - range_operations,
                                    "Portable debug-variable ranges exceed their aggregate budget", ErrorCode::resource_limit);
                            range_expression_bytes += range.expression.size();
                            range_operations += range.operations.size();
                            require(range_payload <= 1048576 - 24 &&
                                        range.expression.size() <= 1048576 - range_payload - 24 &&
                                        range.operations.size() * 29 <=
                                            1048576 - range_payload - 24 - range.expression.size(),
                                    "Portable debug-variable range payload exceeds its budget", ErrorCode::resource_limit);
                            range_payload += 24 + range.expression.size() + range.operations.size() * 29;
                            if (!is_default) {
                                const Address begin{incoming.function_entry.space, range.begin};
                                auto last = advance(begin, range.end - range.begin - 1);
                                require(bool(last), "Portable debug-variable range overflows");
                                check_location(snapshot, Location{begin});
                                check_location(snapshot, Location{last.value()});
                            }
                            for (const auto &operation : range.operations)
                                require(operation.kind <= 20 && (operation.kind != 16 || operation.second_unsigned_operand <= 9) &&
                                            !range.expression.empty() &&
                                            operation.expression_offset < range.expression.size(),
                                        "Portable debug variable has an invalid ranged operation");
                        }
                    }
                    for (const auto &incoming : value.variables) {
                        std::optional<std::uint64_t> type_id;
                        if (incoming.type_name) {
                            require(valid_utf8_name(*incoming.type_name) && incoming.type_name->size() <= 512,
                                    "Portable debug variable has an invalid type name");
                            const auto found = std::find_if(user.types.begin(), user.types.end(),
                                [&](const auto &type) { return type.name == *incoming.type_name; });
                            require(found != user.types.end(), "Portable debug variable refers to an unknown type");
                            type_id = found->id;
                        }
                        const OriginKey key{incoming.origin.source_id, incoming.origin.section,
                                            incoming.origin.unit_offset, incoming.origin.record_offset};
                        auto found = std::find_if(user.debug_variables.begin(), user.debug_variables.end(),
                            [&](const auto &row) {
                                return OriginKey{row.origin.source_id, row.origin.section,
                                                 row.origin.unit_offset, row.origin.record_offset} == key;
                            });
                        require((incoming.expected_absent && !incoming.expected_existing && found == user.debug_variables.end()) ||
                                    (incoming.expected_existing && !incoming.expected_absent && found != user.debug_variables.end() &&
                                     *found == *incoming.expected_existing),
                                "Portable debug-variable destination changed after import planning", ErrorCode::conflict);
                        DebugVariable row;
                        row.id = found == user.debug_variables.end() ? allocate() : found->id;
                        row.function_entry = incoming.function_entry;
                        row.name = incoming.name;
                        row.type_id = type_id;
                        row.is_parameter = incoming.is_parameter;
                        row.scope_offset = incoming.scope_offset;
                        if (incoming.address) row.address = incoming.address->offset;
                        row.location_expression = incoming.location_expression;
                        row.location_operations = incoming.location_operations;
                        row.origin = incoming.origin;
                        row.cfa_offset = incoming.cfa_offset;
                        row.location_ranges = incoming.location_ranges;
                        if (found != user.debug_variables.end() && *found == row) continue;
                        change(user.debug_variables, found, std::optional<DebugVariable>{std::move(row)});
                    }
                } else if constexpr (std::is_same_v<T, ImportSymbols>) {
                    auto candidates=importable_symbols(snapshot);std::size_t imported=0;
                    for(const auto& candidate:candidates){
                        auto& rows=user.annotations;
                        auto found=std::find_if(rows.begin(),rows.end(),[&](const auto& row){return row.location==Location{candidate.address};});
                        Annotation row=found==rows.end()?Annotation{allocate(),candidate.address,{}, {}}:*found;
                        if(!row.name.empty())continue;
                        const bool duplicate=std::any_of(rows.begin(),rows.end(),[&](const auto& existing){auto address=std::get_if<Address>(&existing.location);return existing.location!=Location{candidate.address} && address && address->space==candidate.address.space && existing.name==candidate.name;});
                        if(duplicate)continue;
                        row.name=candidate.name;change(rows,found,std::optional{std::move(row)});++imported;
                    }
                    require(imported!=0,"No new importable symbols were found");
                } else if constexpr (std::is_same_v<T, ImportDwarfInfo>) {
                    require(snapshot.loaded && snapshot.loaded->metadata.elf &&
                                snapshot.loaded->metadata.elf->dwarf_info.has_value(),
                            "This project has no supported ELF DWARF type/symbol information",
                            ErrorCode::unsupported);
                    const auto &dwarf = *snapshot.loaded->metadata.elf->dwarf_info;
                    std::set<std::string, std::less<>> names;
                    for (const auto &row : user.types) names.insert(row.name);
                    std::size_t imported = 0;
                    const auto add_type = [&](std::string name, types::TypePtr type,
                                              std::optional<database::DwarfSourceOrigin> origin = {}) -> std::optional<std::uint64_t> {
                        if (name.empty() || name.size() > 512 || !type) return {};
                        auto existing=std::find_if(user.types.begin(),user.types.end(),[&](const auto& row){return row.name==name;});
                        if(existing!=user.types.end()){
                            if(existing->type->id()!=type->id())return {};
                            if(existing->origin==origin)return existing->id;
                            if(existing->origin||!origin)return {};
                            TypeDefinition updated{existing->id,existing->name,existing->type,origin,existing->declaration_kind};
                            change(user.types,existing,std::optional<TypeDefinition>{std::move(updated)});
                            ++imported;return existing->id;
                        }
                        if(!names.insert(name).second)return {};
                        auto valid = types::encode(*type);
                        if (!valid) { names.erase(name); return {}; }
                        const auto id = allocate();
                        TypeDefinition row{id, std::move(name), std::move(type), std::move(origin)};
                        delta.changes.emplace_back(TypeDefinitionChange{{}, row});
                        user.types.push_back(std::move(row));
                        ++imported;
                        return id;
                    };
                    for (const auto &type : dwarf.types)
                        if (!type.source_name.empty()) add_type(type.source_name, type.type,
                            database::DwarfSourceOrigin{type.origin.source_id,type.origin.section,type.origin.unit_offset,type.origin.record_offset,type.origin.record_size});
                    for (const auto &symbol : dwarf.symbols) {
                        if (symbol.kind != symbols::SymbolKind::function || !symbol.type ||
                            symbol.type->kind() != types::Kind::function || symbol.name.empty()) continue;
                        const Address address{{0}, symbol.address};
                        if (snapshot.loaded->image->segment_at(address)) {
                            auto &annotations = user.annotations;
                            auto found = std::find_if(annotations.begin(), annotations.end(),
                                [&](const auto &row) { return row.location == Location{address}; });
                            Annotation annotation = found == annotations.end()
                                ? Annotation{allocate(), address, {}, {}} : *found;
                            if (annotation.name.empty()) {
                                const bool duplicate = std::any_of(annotations.begin(), annotations.end(),
                                    [&](const auto &row) {
                                        const auto other = std::get_if<Address>(&row.location);
                                        return row.location != Location{address} && other &&
                                               other->space == address.space && row.name == symbol.name;
                                    });
                                if (!duplicate) {
                                    annotation.name = symbol.name;
                                    change(annotations, found, std::optional{std::move(annotation)});
                                    ++imported;
                                }
                            }
                            if (const auto *segment = snapshot.loaded->image->segment_at(address);
                                segment && segment->executable) {
                                try {
                                    decision_instruction(snapshot, address);
                                    function_change(address, [](auto &row) { row.suppressed = false; });
                                    ++imported;
                                } catch (const Failure &) {
                                    // Keep symbol/type evidence if optimized or unusual code makes the
                                    // declared entry unusable as an instruction boundary.
                                }
                            }
                            const auto prototype_name = symbol.name + "_prototype";
                            auto prototype_id = add_type(prototype_name, symbol.type,
                                database::DwarfSourceOrigin{symbol.origin.source_id,symbol.origin.section,symbol.origin.unit_offset,symbol.origin.record_offset,symbol.origin.record_size});
                            if (prototype_id) {
                                auto &assignments = user.type_assignments;
                                auto assigned = std::find_if(assignments.begin(), assignments.end(),
                                    [&](const auto &row) { return row.location == Location{address}; });
                                if (assigned == assignments.end()) {
                                    TypeAssignment row{allocate(), address, *prototype_id};
                                    delta.changes.emplace_back(TypeAssignmentChange{{}, row});
                                    assignments.push_back(std::move(row));
                                    ++imported;
                                }
                            }
                        }
                    }
                    using ScopeKey=std::tuple<std::string,std::string,std::uint64_t,std::uint64_t>;
                    std::map<ScopeKey,Address> function_by_die;
                    std::set<ScopeKey> imported_variable_dies;
                    std::map<std::uint64_t,std::uint64_t> project_type_ids;
                    for(const auto& row:user.debug_variables)imported_variable_dies.emplace(row.origin.source_id,row.origin.section,row.origin.unit_offset,row.origin.record_offset);
                    for(const auto& type:user.types)project_type_ids.emplace(type.type->id(),type.id);
                    for(const auto& symbol:dwarf.symbols){
                        if(symbol.kind!=symbols::SymbolKind::function)continue;
                        const Address entry{{0},symbol.address};
                        if(!snapshot.loaded->image->segment_at(entry))continue;
                        const auto owner=std::find_if(user.decisions.functions.begin(),user.decisions.functions.end(),[&](const auto& row){return row.entry==entry;});
                        if(owner==user.decisions.functions.end())continue;
                        function_by_die.emplace(ScopeKey{symbol.origin.source_id,symbol.origin.section,symbol.origin.unit_offset,symbol.origin.record_offset},entry);
                    }
                    for(const auto& variable:dwarf.variables){
                        if(variable.name.size()>1024 || !valid_utf8_name(variable.name) || user.debug_variables.size()>=database::project_record_limit)continue;
                        const ScopeKey scope{variable.origin.source_id,variable.origin.section,variable.origin.unit_offset,variable.scope_offset};
                        const auto function=function_by_die.find(scope);
                        if(function==function_by_die.end())continue;
                        if(!imported_variable_dies.insert(ScopeKey{variable.origin.source_id,variable.origin.section,variable.origin.unit_offset,variable.origin.record_offset}).second)continue;
                        DebugVariable row;row.id=allocate();row.function_entry=function->second;row.name=variable.name;row.is_parameter=variable.is_parameter;row.scope_offset=variable.scope_offset;row.address=variable.address;row.cfa_offset=variable.cfa_offset;row.location_expression=variable.location_expression;
                        row.origin={variable.origin.source_id,variable.origin.section,variable.origin.unit_offset,variable.origin.record_offset,variable.origin.record_size};
                        const auto persist_operation = [](const symbols::LocationOperation &operation) {
                            auto value = operation.unsigned_operand;
                            auto second = operation.second_unsigned_operand;
                            if (operation.kind == symbols::LocationOperationKind::implicit_value) {
                                second = operation.block_operand.size() > 8 ? 9 : operation.block_operand.size();
                                value = 0;
                                if (operation.block_operand.size() <= 8)
                                    for (std::size_t i = 0; i < operation.block_operand.size(); ++i)
                                        value |= static_cast<std::uint64_t>(operation.block_operand[i]) << (i * 8);
                            }
                            return database::DebugLocationOperation{static_cast<std::uint8_t>(operation.kind), value,
                                operation.signed_operand, operation.expression_offset, second};
                        };
                        row.location_operations.reserve(variable.location_operations.size());
                        for(const auto& operation:variable.location_operations)row.location_operations.push_back(persist_operation(operation));
                        row.location_ranges.reserve(variable.location_ranges.size());
                        for(const auto& range:variable.location_ranges){database::DebugLocationRange imported_range;imported_range.begin=range.begin;imported_range.end=range.end;imported_range.expression=range.expression;for(const auto& operation:range.operations)imported_range.operations.push_back(persist_operation(operation));row.location_ranges.push_back(std::move(imported_range));}
                        if(const auto named_type=project_type_ids.find(variable.type->id());named_type!=project_type_ids.end())row.type_id=named_type->second;
                        delta.changes.emplace_back(DebugVariableChange{{},row});user.debug_variables.push_back(std::move(row));++imported;
                    }
                    require(imported != 0, "No new DWARF types, names, prototypes, or scoped variables were found");
                }
            },
            command);
        auto valid = validate_user_state(user);
        if (!valid)
            return Error{ErrorCode::invalid_argument, valid.error().message};
        return delta;
    });
}
CommandAvailability command_availability(const ProjectSnapshot &snapshot, const ProjectCommand &command) {
    auto validation = validate_command(snapshot, command);
    return validation ? CommandAvailability{true, {}} : CommandAvailability{false, validation.error().message};
}
} // namespace hexlab
