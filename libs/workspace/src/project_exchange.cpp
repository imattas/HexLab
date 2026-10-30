#include "hexlab/workspace/project_exchange.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <tuple>

namespace hexlab {
namespace {
constexpr std::size_t max_exchange_bytes = 16u * 1024u * 1024u;
constexpr std::size_t max_records = 100000;
constexpr std::size_t max_text = 1024 * 1024;
struct PortableLocation { std::uint8_t kind; std::uint64_t offset; auto operator<=>(const PortableLocation &) const = default; };
struct AnnotationRow { PortableLocation location; std::string name, comment; };
struct BookmarkRow { PortableLocation location; std::string label; };
struct ReferenceRow { PortableLocation source, target; std::uint8_t kind; auto operator<=>(const ReferenceRow &) const = default; };
struct RegionRow { PortableLocation begin; std::uint64_t size; std::uint8_t kind; auto operator<=>(const RegionRow &) const = default; };
struct FunctionRow { PortableLocation entry; bool suppressed; std::vector<std::pair<PortableLocation, std::uint64_t>> chunks; auto operator<=>(const FunctionRow &) const = default; };
struct TypeRow { std::string name; std::vector<std::byte> encoded; std::optional<database::DwarfSourceOrigin> origin; database::DeclarationKind declaration_kind=database::DeclarationKind::type; };
struct TypeAssignmentRow { PortableLocation location; std::string type_name; auto operator<=>(const TypeAssignmentRow &) const = default; };
struct PortableDebugRange {
    std::uint64_t begin=0, size=0;
    bool is_default=false;
    std::vector<std::uint8_t> expression;
    std::vector<database::DebugLocationOperation> operations;
};
struct DebugVariableRow {
    PortableLocation function_entry;
    std::string name;
    bool is_parameter=false;
    std::uint64_t scope_offset=0;
    std::optional<PortableLocation> address;
    std::optional<std::string> type_name;
    std::vector<std::uint8_t> expression;
    std::vector<database::DebugLocationOperation> operations;
    database::DwarfSourceOrigin origin;
    std::optional<std::int64_t> cfa_offset;
    std::vector<PortableDebugRange> ranges;
};
struct ProjectBreakpointRow {
    PortableLocation location;
    std::uint8_t kind=0, size=1;
    bool enabled=true;
    std::string condition;
    bool logpoint=false;
    std::string log_message;
    std::uint64_t ignore_count=0;
    bool one_shot=false;
};
struct PatchRow { std::uint64_t offset=0; std::vector<std::byte> original, replacement; };
struct Bundle { database::InputIdentity input; std::uint64_t version=0; std::vector<AnnotationRow> annotations; std::vector<BookmarkRow> bookmarks; std::vector<ReferenceRow> references; std::vector<RegionRow> regions; std::vector<FunctionRow> functions; std::vector<TypeRow> types; std::vector<TypeAssignmentRow> type_assignments; std::vector<DebugVariableRow> debug_variables; std::vector<ProjectBreakpointRow> project_breakpoints; std::vector<PatchRow> patches; };
Error invalid(std::string message, ErrorCode code = ErrorCode::invalid_argument) { return {code, std::move(message)}; }
bool valid_utf8(std::string_view text) {
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i]);
        if (first < 0x80) { ++i; continue; }
        unsigned length = first >= 0xc2 && first <= 0xdf ? 2 : first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
        if (!length || text.size() - i < length) return false;
        std::uint32_t code = first & (length == 2 ? 0x1f : length == 3 ? 0x0f : 0x07);
        for (unsigned n = 1; n < length; ++n) {
            const auto next = static_cast<unsigned char>(text[i + n]);
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 0x3f);
        }
        if ((length == 2 && code < 0x80) || (length == 3 && code < 0x800) ||
            (length == 4 && code < 0x10000) || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
        i += length;
    }
    return true;
}
bool write_number(std::vector<std::byte> &out, std::uint64_t value, unsigned bytes, std::size_t maximum) {
    if (out.size() > maximum || bytes > maximum - out.size()) return false;
    for (unsigned n = 0; n < bytes; ++n) out.push_back(std::byte(value >> (n * 8)));
    return true;
}
bool write_text(std::vector<std::byte> &out, std::string_view value, std::size_t maximum) {
    if (value.size() > max_text || out.size() > maximum || value.size() > maximum - out.size() || 4 > maximum - out.size() - value.size()) return false;
    if (!write_number(out, value.size(), 4, maximum)) return false;
    for (unsigned char c : value) out.push_back(std::byte(c));
    return true;
}
bool write_blob(std::vector<std::byte> &out, std::span<const std::byte> value, std::size_t maximum) {
    if (value.size() > max_text || value.size() > UINT32_MAX || out.size() > maximum || 4 > maximum - out.size() || value.size() > maximum - out.size() - 4) return false;
    if (!write_number(out, value.size(), 4, maximum)) return false;
    out.insert(out.end(), value.begin(), value.end());
    return true;
}
class Reader {
public:
    explicit Reader(std::span<const std::byte> bytes) : bytes_(bytes) {}
    bool number(unsigned count, std::uint64_t &value) {
        if (count > bytes_.size() - position_) return false;
        value = 0;
        for (unsigned n = 0; n < count; ++n) value |= std::uint64_t(std::to_integer<unsigned char>(bytes_[position_++])) << (n * 8);
        return true;
    }
    bool text(std::string &value) {
        std::uint64_t size = 0;
        if (!number(4, size) || size > max_text || size > bytes_.size() - position_) return false;
        value.assign(reinterpret_cast<const char *>(bytes_.data() + position_), static_cast<std::size_t>(size));
        position_ += static_cast<std::size_t>(size);
        return true;
    }
    bool raw(std::span<std::byte> value) {
        if (value.size() > bytes_.size() - position_) return false;
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(position_), value.size(), value.begin());
        position_ += value.size();
        return true;
    }
    bool blob(std::vector<std::byte> &value) {
        std::uint64_t size = 0;
        if (!number(4, size) || size > max_text || size > bytes_.size() - position_) return false;
        value.resize(static_cast<std::size_t>(size));
        return raw(value);
    }
    std::size_t position() const { return position_; }
private:
    std::span<const std::byte> bytes_;
    std::size_t position_ = 0;
};
Result<PortableLocation> portable(const ProjectSnapshot &project, Location location) {
    if (const auto *file = std::get_if<FileOffset>(&location)) {
        if (file->value >= project.state->input.size) return invalid("Exchange file location is outside source input");
        return PortableLocation{0, file->value};
    }
    const auto &address = std::get<Address>(location);
    if (!project.loaded || !project.loaded->image) return invalid("Project mapping is unavailable");
    if (project.loaded->metadata.firmware)
        return invalid("Virtual firmware locations have no source file offset for exchange", ErrorCode::unsupported);
    auto file = project.loaded->image->to_file_offset(address);
    if (!file) return invalid("Exchange address does not map to a unique source file offset");
    return PortableLocation{1, file.value().value};
}
Result<Location> local(const ProjectSnapshot &project, PortableLocation location) {
    if (location.offset >= project.state->input.size) return invalid("Exchange location exceeds source input");
    if (location.kind == 0) return Location{FileOffset{location.offset}};
    if (location.kind != 1 || !project.loaded || !project.loaded->image) return invalid("Invalid or unmappable exchange location");
    if (project.loaded->metadata.firmware)
        return invalid("Virtual firmware locations have no source file offset for exchange", ErrorCode::unsupported);
    auto address = project.loaded->image->to_address({location.offset});
    if (!address) return invalid("Exchange virtual location is not mapped by the destination project");
    return Location{address.value()};
}
Result<PortableLocation> portable_range(const ProjectSnapshot &project, Address begin, std::uint64_t size) {
    if (!size) return invalid("Exchange decision range is empty");
    auto last = advance(begin, size - 1);
    if (!last) return last.error();
    auto first_file = portable(project, Location{begin}); if (!first_file) return first_file.error();
    auto last_file = portable(project, Location{last.value()}); if (!last_file) return last_file.error();
    if (last_file.value().kind != 1 || last_file.value().offset < first_file.value().offset ||
        last_file.value().offset - first_file.value().offset != size - 1)
        return invalid("Exchange decision range is not contiguous in source bytes");
    return first_file.value();
}
Result<Address> local_range(const ProjectSnapshot &project, PortableLocation begin, std::uint64_t size) {
    if (!size) return invalid("Exchange decision range is empty");
    auto address = local(project, begin); if (!address) return address.error();
    auto first = std::get_if<Address>(&address.value());
    if (!first) return invalid("Exchange decision range is not virtual");
    auto last_location = local(project, {begin.kind, begin.offset + size - 1});
    if (!last_location) return last_location.error();
    auto last = std::get_if<Address>(&last_location.value());
    auto expected = advance(*first, size - 1);
    if (!last || !expected || *last != expected.value()) return invalid("Exchange decision range is not contiguous in destination mapping");
    return *first;
}
bool location_write(std::vector<std::byte> &out, PortableLocation value, std::size_t maximum) {
    return write_number(out, value.kind, 1, maximum) && write_number(out, value.offset, 8, maximum);
}
bool location_read(Reader &reader, PortableLocation &value) {
    std::uint64_t kind = 0;
    return reader.number(1, kind) && (value.kind = static_cast<std::uint8_t>(kind), kind <= 1) && reader.number(8, value.offset);
}
bool operations_write(std::vector<std::byte> &out,
                      const std::vector<database::DebugLocationOperation> &operations,
                      std::size_t maximum) {
    if (operations.size() > 4096 || !write_number(out, operations.size(), 4, maximum)) return false;
    for (const auto &operation : operations) {
        if (operation.kind > 20 || (operation.kind == 16 && operation.second_unsigned_operand > 9) ||
            !write_number(out, operation.kind, 1, maximum) ||
            !write_number(out, operation.unsigned_operand, 8, maximum) ||
            !write_number(out, static_cast<std::uint64_t>(operation.signed_operand), 8, maximum) ||
            !write_number(out, operation.expression_offset, 4, maximum) ||
            !write_number(out, operation.second_unsigned_operand, 8, maximum)) return false;
    }
    return true;
}
bool operations_read(Reader &reader, std::vector<database::DebugLocationOperation> &operations,
                     std::size_t expression_size) {
    std::uint64_t count=0;
    if (!reader.number(4, count) || count > 4096) return false;
    operations.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t n=0; n<count; ++n) {
        std::uint64_t kind=0, unsigned_operand=0, signed_operand=0, expression_offset=0, second_unsigned_operand=0;
        if (!reader.number(1,kind) || kind>20 || !reader.number(8,unsigned_operand) ||
            !reader.number(8,signed_operand) || !reader.number(4,expression_offset) ||
            expression_offset>UINT32_MAX || !reader.number(8,second_unsigned_operand) ||
            expression_size==0 || expression_offset>=expression_size || (kind==16 && second_unsigned_operand>9)) return false;
        operations.push_back({static_cast<std::uint8_t>(kind),unsigned_operand,
                              std::bit_cast<std::int64_t>(signed_operand),
                              static_cast<std::uint32_t>(expression_offset),second_unsigned_operand});
    }
    return true;
}
bool bytes_write(std::vector<std::byte> &out, const std::vector<std::uint8_t> &bytes,
                 std::size_t maximum, std::size_t limit) {
    if (bytes.size()>limit) return false;
    return write_blob(out,std::as_bytes(std::span(bytes)),maximum);
}
bool bytes_read(Reader &reader, std::vector<std::uint8_t> &bytes, std::size_t limit) {
    std::vector<std::byte> encoded;
    if (!reader.blob(encoded) || encoded.size()>limit) return false;
    bytes.reserve(encoded.size());
    for (const auto value : encoded) bytes.push_back(std::to_integer<std::uint8_t>(value));
    return true;
}
bool debug_variable_write(std::vector<std::byte> &out, const DebugVariableRow &row,
                          std::size_t maximum) {
    if (row.name.empty() || row.name.size()>1024 || row.origin.source_id.empty() ||
        row.origin.source_id.size()>1024 || row.origin.section.empty() || row.origin.section.size()>256 ||
        !row.origin.record_size || row.expression.size()>65536 || row.operations.size()>4096 ||
        row.ranges.size()>4096) return false;
    if (!location_write(out,row.function_entry,maximum) || !write_text(out,row.name,maximum) ||
        !write_number(out,row.is_parameter,1,maximum) || !write_number(out,row.scope_offset,8,maximum) ||
        !write_number(out,row.type_name.has_value(),1,maximum) ||
        (row.type_name && !write_text(out,*row.type_name,maximum)) ||
        !write_number(out,row.address.has_value(),1,maximum) ||
        (row.address && !location_write(out,*row.address,maximum)) ||
        !bytes_write(out,row.expression,maximum,65536) ||
        !operations_write(out,row.operations,maximum) ||
        !write_text(out,row.origin.source_id,maximum) || !write_text(out,row.origin.section,maximum) ||
        !write_number(out,row.origin.unit_offset,8,maximum) ||
        !write_number(out,row.origin.record_offset,8,maximum) ||
        !write_number(out,row.origin.record_size,8,maximum) ||
        !write_number(out,row.cfa_offset.has_value(),1,maximum) ||
        (row.cfa_offset && !write_number(out,static_cast<std::uint64_t>(*row.cfa_offset),8,maximum)) ||
        !write_number(out,row.ranges.size(),4,maximum)) return false;
    std::size_t expression_total=0, operation_total=0, payload=4;
    bool default_seen=false;
    for (const auto &range : row.ranges) {
        if (range.is_default) {
            if (default_seen || range.begin || range.size) return false;
            default_seen=true;
        } else if (!range.size) return false;
        if (!write_number(out,range.is_default?UINT64_MAX:range.begin,8,maximum) ||
            !write_number(out,range.is_default?UINT64_MAX:range.size,8,maximum)) return false;
        // Range operation/expression payload is serialized through a bounded temporary;
        // database storage caps the aggregate encoded range payload at one MiB.
        std::vector<std::byte> body;
        if (!bytes_write(body,range.expression,1048576,65536) ||
            !operations_write(body,range.operations,1048576)) return false;
        if (range.expression.size()>65536-expression_total ||
            range.operations.size()>4096-operation_total ||
            body.size()>1048576-payload || 16>1048576-payload-body.size()) return false;
        expression_total+=range.expression.size(); operation_total+=range.operations.size(); payload+=16+body.size();
        if (out.size()>maximum || body.size()>maximum-out.size()) return false;
        out.insert(out.end(),body.begin(),body.end());
    }
    return true;
}
bool debug_variable_read(Reader &reader, DebugVariableRow &row) {
    std::uint64_t is_parameter=0, scope_offset=0, type_present=0, address_present=0,
                  cfa_present=0, cfa_value=0, range_count=0;
    if (!location_read(reader,row.function_entry) || row.function_entry.kind!=1 ||
        !reader.text(row.name) || row.name.empty() || row.name.size()>1024 || !valid_utf8(row.name) ||
        !reader.number(1,is_parameter) || is_parameter>1 || !reader.number(8,scope_offset) ||
        !reader.number(1,type_present) || type_present>1) return false;
    row.is_parameter=is_parameter!=0; row.scope_offset=scope_offset;
    if (type_present) { std::string name; if (!reader.text(name) || name.empty() || name.size()>512 || !valid_utf8(name)) return false; row.type_name=std::move(name); }
    if (!reader.number(1,address_present) || address_present>1) return false;
    if (address_present) { PortableLocation address{}; if (!location_read(reader,address) || address.kind!=1) return false; row.address=address; }
    if (!bytes_read(reader,row.expression,65536) || !operations_read(reader,row.operations,row.expression.size()) ||
        !reader.text(row.origin.source_id) || row.origin.source_id.empty() || row.origin.source_id.size()>1024 ||
        !valid_utf8(row.origin.source_id) || row.origin.source_id.find('\0')!=std::string::npos ||
        !reader.text(row.origin.section) || row.origin.section.empty() || row.origin.section.size()>256 ||
        !valid_utf8(row.origin.section) || row.origin.section.find('\0')!=std::string::npos ||
        !reader.number(8,row.origin.unit_offset) || !reader.number(8,row.origin.record_offset) ||
        !reader.number(8,row.origin.record_size) || !row.origin.record_size ||
        !reader.number(1,cfa_present) || cfa_present>1) return false;
    if (cfa_present) { if (!reader.number(8,cfa_value)) return false; row.cfa_offset=std::bit_cast<std::int64_t>(cfa_value); }
    if (!reader.number(4,range_count) || range_count>4096) return false;
    row.ranges.reserve(static_cast<std::size_t>(range_count));
    std::size_t expression_total=0, operation_total=0, payload=4; bool default_seen=false;
    for (std::uint64_t n=0;n<range_count;++n) {
        PortableDebugRange range{}; std::uint64_t begin=0,size=0;
        if (!reader.number(8,begin) || !reader.number(8,size)) return false;
        range.is_default=begin==UINT64_MAX && size==UINT64_MAX;
        if (range.is_default) { if (default_seen) return false; default_seen=true; }
        else if (begin==UINT64_MAX || size==UINT64_MAX || !size) return false;
        range.begin=range.is_default?0:begin; range.size=range.is_default?0:size;
        const auto before=reader.position();
        if (!bytes_read(reader,range.expression,65536) || !operations_read(reader,range.operations,range.expression.size())) return false;
        const auto body_size=16+reader.position()-before;
        if (range.expression.size()>65536-expression_total || range.operations.size()>4096-operation_total ||
            body_size>1048576-payload) return false;
        expression_total+=range.expression.size(); operation_total+=range.operations.size(); payload+=body_size;
        row.ranges.push_back(std::move(range));
    }
    return !(row.address && !row.expression.empty()) &&
           (!row.cfa_offset || (!row.address && !row.expression.empty()));
}
Result<Bundle> parse(const ProjectSnapshot &project, std::span<const std::byte> bytes, std::size_t maximum) {
    if (bytes.size() > maximum) return invalid("Exchange input exceeds configured byte limit", ErrorCode::resource_limit);
    if (bytes.size() < 60) return invalid("Truncated exchange header");
    Reader reader(bytes);
    std::array<std::byte, 4> magic{};
    if (!reader.raw(magic) || magic != std::array{std::byte{'H'}, std::byte{'X'}, std::byte{'E'}, std::byte{'X'}}) return invalid("Unknown exchange magic");
    std::uint64_t version = 0, reserved = 0, input_size = 0, annotation_count = 0, bookmark_count = 0, reference_count = 0, region_count = 0, function_count = 0, type_count = 0, assignment_count = 0, debug_variable_count = 0, project_breakpoint_count = 0, patch_count = 0;
    if (!reader.number(2, version) || !reader.number(2, reserved) || !reader.number(8, input_size)) return invalid("Truncated exchange header");
    Bundle bundle; bundle.version=version;
    if (!reader.raw(bundle.input.sha256)) return invalid("Truncated exchange identity");
    if (!reader.number(4, annotation_count) || !reader.number(4, bookmark_count) || !reader.number(4, reference_count)) return invalid("Truncated exchange counts");
    if (version == 2 && (!reader.number(4, region_count) || !reader.number(4, function_count))) return invalid("Truncated exchange counts");
    if ((version >= 3 && version <= 5) && (!reader.number(4, region_count) || !reader.number(4, function_count) || !reader.number(4, type_count) || !reader.number(4, assignment_count))) return invalid("Truncated exchange counts");
    if (version == 6 && (!reader.number(4, region_count) || !reader.number(4, function_count) ||
                         !reader.number(4, type_count) || !reader.number(4, assignment_count) ||
                         !reader.number(4, debug_variable_count))) return invalid("Truncated exchange counts");
    if (version == 7 && (!reader.number(4, region_count) || !reader.number(4, function_count) ||
                         !reader.number(4, type_count) || !reader.number(4, assignment_count) ||
                         !reader.number(4, debug_variable_count) || !reader.number(4, project_breakpoint_count))) return invalid("Truncated exchange counts");
    if ((version == 8 || version == 9) && (!reader.number(4, region_count) || !reader.number(4, function_count) ||
                         !reader.number(4, type_count) || !reader.number(4, assignment_count) ||
                         !reader.number(4, debug_variable_count) || !reader.number(4, project_breakpoint_count) ||
                         !reader.number(4, patch_count))) return invalid("Truncated exchange counts");
    if (version != 1 && version != 2 && version != 3 && version != 4 && version != 5 && version != 6 && version != 7 && version != 8 && version != 9) return invalid("Unsupported project exchange version");
    if (reserved != 0) return invalid("Nonzero reserved exchange header bits");
    bundle.input.size = input_size;
    if (bundle.input != project.state->input) return invalid("Exchange belongs to different original input bytes", ErrorCode::conflict);
    if (annotation_count + bookmark_count + reference_count + region_count + function_count + type_count + assignment_count + debug_variable_count + project_breakpoint_count + patch_count > max_records) return invalid("Exchange row count exceeds limit", ErrorCode::resource_limit);
    bundle.annotations.reserve(static_cast<std::size_t>(annotation_count));
    bundle.bookmarks.reserve(static_cast<std::size_t>(bookmark_count));
    bundle.references.reserve(static_cast<std::size_t>(reference_count));
    bundle.regions.reserve(static_cast<std::size_t>(region_count)); bundle.functions.reserve(static_cast<std::size_t>(function_count));
    bundle.types.reserve(static_cast<std::size_t>(type_count)); bundle.type_assignments.reserve(static_cast<std::size_t>(assignment_count));
    bundle.debug_variables.reserve(static_cast<std::size_t>(debug_variable_count));
    bundle.project_breakpoints.reserve(static_cast<std::size_t>(project_breakpoint_count));
    bundle.patches.reserve(static_cast<std::size_t>(patch_count));
    for (std::uint64_t n = 0; n < annotation_count; ++n) {
        AnnotationRow row{};
        if (!location_read(reader, row.location) || !reader.text(row.name) || !reader.text(row.comment)) return invalid("Malformed annotation exchange row");
        if ((row.name.empty() && row.comment.empty()) || (row.location.kind == 0 && !row.name.empty()) ||
            !valid_utf8(row.name) || !valid_utf8(row.comment)) return invalid("Invalid annotation exchange row");
        bundle.annotations.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < bookmark_count; ++n) {
        BookmarkRow row{};
        if (!location_read(reader, row.location) || !reader.text(row.label) || row.label.empty() || !valid_utf8(row.label)) return invalid("Malformed bookmark exchange row");
        bundle.bookmarks.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < reference_count; ++n) {
        ReferenceRow row{}; std::uint64_t kind = 0;
        if (!location_read(reader, row.source) || !location_read(reader, row.target) || !reader.number(1, kind) || kind > 6) return invalid("Malformed reference exchange row");
        row.kind = static_cast<std::uint8_t>(kind); bundle.references.push_back(row);
    }
    for (std::uint64_t n = 0; n < region_count; ++n) {
        RegionRow row{}; std::uint64_t size = 0, kind = 0;
        if (!location_read(reader, row.begin) || !reader.number(8, size) || !reader.number(1, kind) || !size || kind > 1) return invalid("Malformed region exchange row");
        row.size = size; row.kind = static_cast<std::uint8_t>(kind); bundle.regions.push_back(row);
    }
    std::uint64_t total_chunks = 0;
    for (std::uint64_t n = 0; n < function_count; ++n) {
        FunctionRow row{}; std::uint64_t suppressed = 0, chunks = 0;
        if (!location_read(reader, row.entry) || row.entry.kind != 1 || !reader.number(1, suppressed) || suppressed > 1 || !reader.number(4, chunks)) return invalid("Malformed function exchange row");
        if (chunks > max_records - total_chunks) return invalid("Exchange chunk count exceeds limit", ErrorCode::resource_limit);
        total_chunks += chunks;
        row.suppressed = suppressed != 0; row.chunks.reserve(static_cast<std::size_t>(chunks));
        for (std::uint64_t c = 0; c < chunks; ++c) { PortableLocation begin{}; std::uint64_t size = 0; if (!location_read(reader, begin) || begin.kind != 1 || !reader.number(8, size) || !size) return invalid("Malformed function chunk exchange row"); row.chunks.emplace_back(begin, size); }
        if (!std::is_sorted(row.chunks.begin(), row.chunks.end()) || std::adjacent_find(row.chunks.begin(), row.chunks.end()) != row.chunks.end()) return invalid("Function chunks are not canonical");
        bundle.functions.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < type_count; ++n) {
        TypeRow row{};
        if (!reader.text(row.name) || row.name.empty() || row.name.size() > 512 || !valid_utf8(row.name) || !reader.blob(row.encoded)) return invalid("Malformed type definition exchange row");
        const auto decoded_type = types::decode(row.encoded);
        if (!decoded_type) return invalid("Invalid portable type definition");
        if(version>=4){std::uint64_t present=0;if(!reader.number(1,present)||present>1)return invalid("Malformed type source-origin flag");if(present){database::DwarfSourceOrigin origin;if(!reader.text(origin.source_id)||origin.source_id.empty()||origin.source_id.size()>1024||!valid_utf8(origin.source_id)||origin.source_id.find('\0')!=std::string::npos||!reader.text(origin.section)||origin.section.empty()||origin.section.size()>256||!valid_utf8(origin.section)||origin.section.find('\0')!=std::string::npos||!reader.number(8,origin.unit_offset)||!reader.number(8,origin.record_offset)||!reader.number(8,origin.record_size)||!origin.record_size)return invalid("Malformed type source origin");row.origin=std::move(origin);}}
        if(version>=5){std::uint64_t kind=0;if(!reader.number(1,kind)||kind>static_cast<unsigned>(database::DeclarationKind::function))return invalid("Malformed declaration kind");row.declaration_kind=static_cast<database::DeclarationKind>(kind);}
        if(!database::declaration_type_matches(row.declaration_kind,decoded_type.value().get()))return invalid("Declaration kind does not match its type");
        bundle.types.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < assignment_count; ++n) {
        TypeAssignmentRow row{};
        if (!location_read(reader, row.location) || row.location.kind != 1 || !reader.text(row.type_name) || row.type_name.empty() || !valid_utf8(row.type_name)) return invalid("Malformed type assignment exchange row");
        bundle.type_assignments.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < debug_variable_count; ++n) {
        DebugVariableRow row{};
        if (!debug_variable_read(reader,row)) return invalid("Malformed debug-variable exchange row");
        bundle.debug_variables.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < project_breakpoint_count; ++n) {
        ProjectBreakpointRow row{};
        std::uint64_t kind=0, size=0, enabled=0, logpoint=0, one_shot=0;
        if (!location_read(reader,row.location) || row.location.kind!=1 ||
            !reader.number(1,kind) || kind>static_cast<unsigned>(database::ProjectBreakpointKind::access) ||
            !reader.number(1,size) || !reader.number(1,enabled) || enabled>1 ||
            !reader.text(row.condition) || row.condition.size()>256 || !valid_utf8(row.condition) || row.condition.find('\0')!=std::string::npos ||
            !reader.number(1,logpoint) || logpoint>1 || !reader.text(row.log_message) ||
            row.log_message.size()>1024 || !valid_utf8(row.log_message) || row.log_message.find('\0')!=std::string::npos ||
            !reader.number(8,row.ignore_count) || (version >= 9 && (!reader.number(1,one_shot) || one_shot>1))) return invalid("Malformed project-breakpoint exchange row");
        row.kind=static_cast<std::uint8_t>(kind); row.size=static_cast<std::uint8_t>(size);
        row.enabled=enabled!=0; row.logpoint=logpoint!=0; row.one_shot=one_shot!=0;
        const auto breakpoint_kind=static_cast<database::ProjectBreakpointKind>(kind);
        if ((row.size!=1 && row.size!=2 && row.size!=4 && row.size!=8) ||
            ((breakpoint_kind==database::ProjectBreakpointKind::software ||
              breakpoint_kind==database::ProjectBreakpointKind::hardware ||
              breakpoint_kind==database::ProjectBreakpointKind::execute) && row.size!=1))
            return invalid("Invalid project-breakpoint size");
        bundle.project_breakpoints.push_back(std::move(row));
    }
    for (std::uint64_t n = 0; n < patch_count; ++n) {
        PatchRow row{};
        if (!reader.number(8, row.offset) || !reader.blob(row.original) || !reader.blob(row.replacement) ||
            row.original.empty() || row.original.size() != row.replacement.size() ||
            std::equal(row.original.begin(), row.original.end(), row.replacement.begin()))
            return invalid("Malformed byte-patch exchange row");
        for (std::size_t i = 0; i < row.original.size(); ++i)
            if (row.original[i] == row.replacement[i]) return invalid("Byte-patch row contains a no-op byte");
        bundle.patches.push_back(std::move(row));
    }
    if (reader.position() != bytes.size()) return invalid("Trailing bytes after project exchange records");
    for (auto &row : bundle.annotations) if (row.location.offset >= input_size) return invalid("Annotation exchange offset exceeds input");
    for (auto &row : bundle.bookmarks) if (row.location.offset >= input_size) return invalid("Bookmark exchange offset exceeds input");
    for (auto &row : bundle.project_breakpoints) if (row.location.offset >= input_size) return invalid("Project-breakpoint exchange offset exceeds input");
    for (const auto &row : bundle.patches) {
        if (row.offset >= input_size || row.original.size() > input_size - row.offset)
            return invalid("Byte-patch exchange range exceeds input");
        if (!project.original) return invalid("Original input is unavailable for patch validation");
        auto original = project.original->read_at({row.offset}, row.original.size());
        if (!original || original.value().bytes.size() != row.original.size() ||
            !std::equal(row.original.begin(), row.original.end(), original.value().bytes.begin()))
            return invalid("Byte-patch original bytes do not match the input identity");
    }
    for (auto &row : bundle.references) if (row.source.offset >= input_size || row.target.offset >= input_size) return invalid("Reference exchange offset exceeds input");
    for (auto &row : bundle.regions) if (row.begin.kind != 1 || row.begin.offset >= input_size || row.size > input_size - row.begin.offset) return invalid("Region exchange range exceeds input");
    for (auto &row : bundle.functions) {
        if (row.entry.offset >= input_size) return invalid("Function exchange entry exceeds input");
        bool contains_entry = false;
        for (auto &[begin, size] : row.chunks) {
            if (begin.offset >= input_size || size > input_size - begin.offset) return invalid("Function chunk exchange range exceeds input");
            contains_entry = contains_entry || (row.entry.offset >= begin.offset && row.entry.offset - begin.offset < size);
        }
        if (!row.chunks.empty() && !contains_entry) return invalid("Function chunks do not contain their entry");
    }
    for (const auto &row : bundle.type_assignments) {
        if (row.location.offset >= input_size) return invalid("Type assignment exchange offset exceeds input");
        if (std::none_of(bundle.types.begin(), bundle.types.end(), [&](const auto &type) { return type.name == row.type_name; })) return invalid("Type assignment references a missing type definition");
    }
    for (const auto &row : bundle.debug_variables) {
        if (row.function_entry.offset >= input_size) return invalid("Debug-variable function entry exceeds input");
        if (row.address && row.address->offset >= input_size) return invalid("Debug-variable address exceeds input");
        if (row.type_name && std::none_of(bundle.types.begin(), bundle.types.end(),
                [&](const auto &type) { return type.name == *row.type_name; }))
            return invalid("Debug variable references a missing type definition");
        if (std::none_of(bundle.functions.begin(), bundle.functions.end(),
                [&](const auto &function) { return function.entry.offset == row.function_entry.offset; }))
            return invalid("Debug variable references a missing function decision");
        for (const auto &range : row.ranges)
            if (!range.is_default && (range.begin >= input_size || range.size > input_size-range.begin))
                return invalid("Debug-variable location range exceeds input");
    }
    if (!std::is_sorted(bundle.annotations.begin(), bundle.annotations.end(), [](const auto &a, const auto &b) { return a.location < b.location; }) ||
        !std::is_sorted(bundle.bookmarks.begin(), bundle.bookmarks.end(), [](const auto &a, const auto &b) { return a.location < b.location; }) ||
        !std::is_sorted(bundle.references.begin(), bundle.references.end()) || !std::is_sorted(bundle.regions.begin(), bundle.regions.end()) || !std::is_sorted(bundle.functions.begin(), bundle.functions.end()) ||
        !std::is_sorted(bundle.types.begin(), bundle.types.end(), [](const auto &a, const auto &b) { return a.name < b.name; }) || !std::is_sorted(bundle.type_assignments.begin(), bundle.type_assignments.end()) ||
        !std::is_sorted(bundle.debug_variables.begin(), bundle.debug_variables.end(), [](const auto &a,const auto &b) {
            return std::tie(a.origin.source_id,a.origin.section,a.origin.unit_offset,a.origin.record_offset) <
                   std::tie(b.origin.source_id,b.origin.section,b.origin.unit_offset,b.origin.record_offset);
        }) || !std::is_sorted(bundle.project_breakpoints.begin(),bundle.project_breakpoints.end(),[](const auto &a,const auto &b){return a.location<b.location;}) ||
        !std::is_sorted(bundle.patches.begin(), bundle.patches.end(), [](const auto &a, const auto &b) { return a.offset < b.offset; })) return invalid("Exchange records are not in canonical order");
    if (std::adjacent_find(bundle.annotations.begin(), bundle.annotations.end(), [](const auto &a, const auto &b) { return a.location == b.location; }) != bundle.annotations.end() ||
        std::adjacent_find(bundle.bookmarks.begin(), bundle.bookmarks.end(), [](const auto &a, const auto &b) { return a.location == b.location; }) != bundle.bookmarks.end() ||
        std::adjacent_find(bundle.references.begin(), bundle.references.end()) != bundle.references.end() || std::adjacent_find(bundle.regions.begin(), bundle.regions.end(), [](const auto&a,const auto&b){return a.begin==b.begin;}) != bundle.regions.end() || std::adjacent_find(bundle.functions.begin(), bundle.functions.end(), [](const auto&a,const auto&b){return a.entry==b.entry;}) != bundle.functions.end() ||
        std::adjacent_find(bundle.types.begin(), bundle.types.end(), [](const auto &a, const auto &b) { return a.name == b.name; }) != bundle.types.end() || std::adjacent_find(bundle.type_assignments.begin(), bundle.type_assignments.end(), [](const auto &a, const auto &b) { return a.location == b.location; }) != bundle.type_assignments.end() ||
        std::adjacent_find(bundle.debug_variables.begin(), bundle.debug_variables.end(), [](const auto &a,const auto &b) {
            return a.origin.source_id==b.origin.source_id && a.origin.section==b.origin.section &&
                   a.origin.unit_offset==b.origin.unit_offset && a.origin.record_offset==b.origin.record_offset;
        }) != bundle.debug_variables.end() ||
        std::adjacent_find(bundle.project_breakpoints.begin(),bundle.project_breakpoints.end(),[](const auto &a,const auto &b){return a.location==b.location;}) != bundle.project_breakpoints.end()) return invalid("Duplicate exchange records");
    for (std::size_t n = 1; n < bundle.patches.size(); ++n) {
        const auto &previous = bundle.patches[n - 1];
        if (previous.offset > UINT64_MAX - previous.original.size() ||
            previous.offset + previous.original.size() >= bundle.patches[n].offset)
            return invalid("Byte-patch exchange rows overlap or are not canonical");
    }
    return bundle;
}
} // namespace

Result<std::vector<std::byte>> export_project_exchange(const ProjectSnapshot &project, std::size_t max_bytes) {
    max_bytes = std::min(max_bytes, max_exchange_bytes);
    if (!project.state || !project.state->user || !project.state->input.size) return invalid("No project input is available");
    const auto &user = *project.state->user;
    const auto rows = user.annotations.size() + user.bookmarks.size() + user.decisions.references.size() + user.decisions.regions.size() + user.decisions.functions.size() + user.types.size() + user.type_assignments.size() + user.debug_variables.size() + user.breakpoints.size() + user.patches.size();
    if (rows > max_records) return invalid("Project user rows exceed exchange limit", ErrorCode::resource_limit);
    std::vector<AnnotationRow> annotations; std::vector<BookmarkRow> bookmarks; std::vector<ReferenceRow> references; std::vector<RegionRow> regions; std::vector<FunctionRow> functions;
    std::vector<TypeRow> type_rows; std::vector<TypeAssignmentRow> assignments; std::vector<DebugVariableRow> debug_variables; std::vector<ProjectBreakpointRow> project_breakpoints; std::vector<PatchRow> patches;
    for (const auto &row : user.annotations) {
        auto at = portable(project, row.location); if (!at) return at.error();
        if ((row.name.empty() && row.comment.empty()) || (at.value().kind == 0 && !row.name.empty()) ||
            !valid_utf8(row.name) || !valid_utf8(row.comment))
            return invalid("Project contains an invalid annotation for portable exchange");
        annotations.push_back({at.value(), row.name, row.comment});
    }
    for (const auto &row : user.bookmarks) {
        auto at = portable(project, row.location); if (!at) return at.error();
        if (row.label.empty() || !valid_utf8(row.label))
            return invalid("Project contains an invalid bookmark for portable exchange");
        bookmarks.push_back({at.value(), row.label});
    }
    for (const auto &row : user.decisions.references) {
        if (row.kind > UserReferenceKind::address) return invalid("Project contains an invalid reference kind");
        auto from = portable(project, row.source); if (!from) return from.error();
        auto to = portable(project, row.target); if (!to) return to.error();
        references.push_back({from.value(), to.value(), static_cast<std::uint8_t>(row.kind)});
    }
    for (const auto &row : user.decisions.regions) {
        if (row.kind > RegionKind::data) return invalid("Project contains an invalid region kind");
        auto begin = portable_range(project, row.begin, row.size); if (!begin) return begin.error();
        regions.push_back({begin.value(), row.size, static_cast<std::uint8_t>(row.kind)});
    }
    std::size_t total_function_chunks = 0;
    for (const auto &row : user.decisions.functions) {
        if (row.chunks.size() > max_records - total_function_chunks)
            return invalid("Project function chunks exceed exchange limit", ErrorCode::resource_limit);
        total_function_chunks += row.chunks.size();
        auto entry = portable(project, Location{row.entry}); if (!entry) return entry.error();
        FunctionRow value{entry.value(), row.suppressed, {}};
        for (const auto &chunk : row.chunks) { auto begin = portable_range(project, chunk.begin, chunk.size); if (!begin) return begin.error(); value.chunks.emplace_back(begin.value(), chunk.size); }
        std::sort(value.chunks.begin(), value.chunks.end());
        if (std::adjacent_find(value.chunks.begin(), value.chunks.end()) != value.chunks.end())
            return invalid("Duplicate function chunks map to one portable range");
        if (!value.chunks.empty() && std::none_of(value.chunks.begin(), value.chunks.end(), [&](const auto &chunk) {
                return value.entry.offset >= chunk.first.offset && value.entry.offset - chunk.first.offset < chunk.second;
            })) return invalid("Project function chunks do not contain their entry");
        functions.push_back(std::move(value));
    }
    for (const auto &row : user.types) {
        if (!database::declaration_type_matches(row.declaration_kind,row.type.get())) return invalid("Project contains an invalid declaration type");
        if (row.name.empty() || row.name.size() > 512 || !valid_utf8(row.name)) return invalid("Project contains a type name outside the portable limit");
        if(row.origin&&(row.origin->source_id.empty()||row.origin->source_id.size()>1024||row.origin->source_id.find('\0')!=std::string::npos||!valid_utf8(row.origin->source_id)||row.origin->section.empty()||row.origin->section.size()>256||row.origin->section.find('\0')!=std::string::npos||!valid_utf8(row.origin->section)||!row.origin->record_size))return invalid("Project contains an invalid DWARF type origin");
        auto encoded = types::encode(*row.type); if (!encoded) return encoded.error(); type_rows.push_back({row.name, std::move(encoded.value()),row.origin,row.declaration_kind});
    }
    for (const auto &row : user.type_assignments) { if (!std::holds_alternative<Address>(row.location)) return invalid("Portable type assignments require a virtual address"); auto found = std::find_if(user.types.begin(), user.types.end(), [&](const auto &type) { return type.id == row.type_id; }); if (found == user.types.end()) return invalid("Type assignment refers to a missing project type"); auto at = portable(project, row.location); if (!at) return at.error(); assignments.push_back({at.value(), found->name}); }
    for (const auto &row : user.debug_variables) {
        if (row.name.empty() || row.name.size()>1024 || !valid_utf8(row.name) ||
            row.origin.source_id.empty() || row.origin.source_id.size()>1024 ||
            row.origin.source_id.find('\0')!=std::string::npos || !valid_utf8(row.origin.source_id) ||
            row.origin.section.empty() || row.origin.section.size()>256 ||
            row.origin.section.find('\0')!=std::string::npos || !valid_utf8(row.origin.section) ||
            !row.origin.record_size || row.location_expression.size()>65536 ||
            row.location_operations.size()>4096 || row.location_ranges.size()>4096)
            return invalid("Project contains an invalid or oversized debug variable");
        auto entry=portable(project,Location{row.function_entry}); if(!entry)return entry.error();
        if(entry.value().kind!=1)return invalid("Debug-variable function entry is not virtual");
        DebugVariableRow value{}; value.function_entry=entry.value(); value.name=row.name;
        value.is_parameter=row.is_parameter; value.scope_offset=row.scope_offset;
        value.expression=row.location_expression; value.operations=row.location_operations;
        value.origin=row.origin; value.cfa_offset=row.cfa_offset;
        if(row.type_id){
            auto type=std::find_if(user.types.begin(),user.types.end(),[&](const auto &candidate){return candidate.id==*row.type_id;});
            if(type==user.types.end())return invalid("Debug variable references a missing project type");
            value.type_name=type->name;
        }
        if(row.address){auto at=portable(project,Location{Address{row.function_entry.space,*row.address}});if(!at)return at.error();if(at.value().kind!=1)return invalid("Debug-variable address is not virtual");value.address=at.value();}
        if(row.address&&!row.location_expression.empty())return invalid("Debug variable has both direct-address and expression locations");
        if(row.cfa_offset&&(!row.location_expression.size()||row.address))return invalid("Debug variable has an invalid CFA location");
        for(const auto &operation:row.location_operations)
            if(operation.kind>20 || (operation.kind==16 && operation.second_unsigned_operand>9) ||
                row.location_expression.empty() || operation.expression_offset>=row.location_expression.size())
                return invalid("Debug variable contains an invalid decoded location operation");
        std::size_t expression_total=0,operation_total=0,payload=4;bool default_seen=false;
        for(const auto &range:row.location_ranges){
            if(range.begin==UINT64_MAX&&range.end==UINT64_MAX){
                if(default_seen)return invalid("Debug variable contains duplicate default location ranges");
                default_seen=true;value.ranges.push_back({0,0,true,range.expression,range.operations});
            }else{
                if(range.begin>=range.end)return invalid("Debug variable contains an empty or reversed location range");
                const auto size=range.end-range.begin;
                auto begin=portable_range(project,Address{row.function_entry.space,range.begin},size);if(!begin)return begin.error();
                value.ranges.push_back({begin.value().offset,size,false,range.expression,range.operations});
            }
            if(range.expression.size()>65536-expression_total || range.operations.size()>4096-operation_total)
                return invalid("Debug-variable location lists exceed their aggregate budget",ErrorCode::resource_limit);
            expression_total+=range.expression.size();operation_total+=range.operations.size();
            const auto encoded=24+range.expression.size()+range.operations.size()*29;
            if(encoded>1048576-payload)return invalid("Debug-variable location lists exceed their encoded budget",ErrorCode::resource_limit);
            payload+=encoded;
            for(const auto &operation:range.operations)
                if(operation.kind>20||(operation.kind==16&&operation.second_unsigned_operand>9)||
                    range.expression.empty()||operation.expression_offset>=range.expression.size())
                    return invalid("Debug variable contains an invalid ranged location operation");
        }
        debug_variables.push_back(std::move(value));
    }
    for (const auto &row : debug_variables)
        if (std::none_of(functions.begin(), functions.end(), [&](const auto &function) {
                return function.entry.offset == row.function_entry.offset;
            })) return invalid("Debug variable references a function missing from portable metadata");
    for (const auto &row : user.breakpoints) {
        if (row.kind>database::ProjectBreakpointKind::access || row.condition.size()>256 ||
            row.condition.find('\0')!=std::string::npos || !valid_utf8(row.condition) ||
            row.log_message.size()>1024 || row.log_message.find('\0')!=std::string::npos || !valid_utf8(row.log_message) ||
            (row.size!=1 && row.size!=2 && row.size!=4 && row.size!=8) ||
            ((row.kind==database::ProjectBreakpointKind::software || row.kind==database::ProjectBreakpointKind::hardware ||
              row.kind==database::ProjectBreakpointKind::execute) && row.size!=1))
            return invalid("Project contains an invalid project breakpoint");
        auto at=portable(project,Location{row.address}); if(!at)return at.error();
        if(at.value().kind!=1)return invalid("Project breakpoint is not a virtual address");
        project_breakpoints.push_back({at.value(),static_cast<std::uint8_t>(row.kind),row.size,row.enabled,
                                       row.condition,row.logpoint,row.log_message,row.ignore_count,row.one_shot});
    }
    std::size_t patch_payload_bytes = 0;
    if (!user.patches.empty() && !project.original)
        return invalid("Original input is unavailable for patch export validation");
    for (const auto &row : user.patches) {
        if (row.original.empty() || row.original.size() > max_text ||
            row.original.size() != row.replacement.size() ||
            row.begin.value >= project.state->input.size ||
            row.original.size() > project.state->input.size - row.begin.value ||
            std::equal(row.original.begin(), row.original.end(), row.replacement.begin()))
            return invalid("Project contains an invalid patch span");
        auto original = project.original->read_at(row.begin, row.original.size());
        if (!original || original.value().bytes.size() != row.original.size())
            return invalid("Cannot read original input bytes for patch export validation", ErrorCode::io);
        if (!std::equal(row.original.begin(), row.original.end(), original.value().bytes.begin()))
            return invalid("Project patch original bytes do not match the source input");
        if (row.original.size() > (max_bytes > patch_payload_bytes + 16 ? (max_bytes - patch_payload_bytes - 16) / 2 : 0))
            return invalid("Project patches exceed the exchange byte limit", ErrorCode::resource_limit);
        patch_payload_bytes += 16 + row.original.size() * 2;
        for (std::size_t i = 0; i < row.original.size(); ++i)
            if (row.original[i] == row.replacement[i]) return invalid("Project patch span contains a no-op byte");
        patches.push_back({row.begin.value, row.original, row.replacement});
    }
    auto by_location = [](const auto &a, const auto &b) { return a.location < b.location; };
    std::sort(annotations.begin(), annotations.end(), by_location); std::sort(bookmarks.begin(), bookmarks.end(), by_location); std::sort(references.begin(), references.end());
    std::sort(regions.begin(), regions.end()); std::sort(functions.begin(), functions.end());
    std::sort(type_rows.begin(), type_rows.end(), [](const auto &a, const auto &b) { return a.name < b.name; }); std::sort(assignments.begin(), assignments.end());
    std::sort(debug_variables.begin(),debug_variables.end(),[](const auto &a,const auto &b){return std::tie(a.origin.source_id,a.origin.section,a.origin.unit_offset,a.origin.record_offset)<std::tie(b.origin.source_id,b.origin.section,b.origin.unit_offset,b.origin.record_offset);});
    std::sort(project_breakpoints.begin(),project_breakpoints.end(),by_location);
    std::sort(patches.begin(), patches.end(), [](const auto &a, const auto &b) { return a.offset < b.offset; });
    for (std::size_t n = 1; n < annotations.size(); ++n) if (annotations[n-1].location == annotations[n].location) return invalid("Multiple annotations map to one portable location");
    for (std::size_t n = 1; n < bookmarks.size(); ++n) if (bookmarks[n-1].location == bookmarks[n].location) return invalid("Multiple bookmarks map to one portable location");
    for (std::size_t n = 1; n < references.size(); ++n) if (references[n-1] == references[n]) return invalid("Multiple references map to one portable row");
    for (std::size_t n = 1; n < regions.size(); ++n) if (regions[n-1].begin == regions[n].begin) return invalid("Multiple regions map to one portable location");
    for (std::size_t n = 1; n < functions.size(); ++n) if (functions[n-1].entry == functions[n].entry) return invalid("Multiple function decisions map to one portable entry");
    for (std::size_t n = 1; n < type_rows.size(); ++n) if (type_rows[n-1].name == type_rows[n].name) return invalid("Duplicate portable type names");
    for (std::size_t n = 1; n < assignments.size(); ++n) if (assignments[n-1].location == assignments[n].location) return invalid("Multiple type assignments map to one portable location");
    for (std::size_t n = 1; n < debug_variables.size(); ++n) if (std::tie(debug_variables[n-1].origin.source_id,debug_variables[n-1].origin.section,debug_variables[n-1].origin.unit_offset,debug_variables[n-1].origin.record_offset)==std::tie(debug_variables[n].origin.source_id,debug_variables[n].origin.section,debug_variables[n].origin.unit_offset,debug_variables[n].origin.record_offset)) return invalid("Multiple debug variables share one portable source origin");
    for (std::size_t n = 1; n < project_breakpoints.size(); ++n) if (project_breakpoints[n-1].location==project_breakpoints[n].location) return invalid("Multiple project breakpoints map to one portable location");
    for (std::size_t n = 1; n < patches.size(); ++n)
        if (patches[n-1].offset + patches[n-1].original.size() >= patches[n].offset)
            return invalid("Project patch spans overlap or are not canonical");
    std::vector<std::byte> out; out.reserve(56);
    for (auto b : {std::byte{'H'}, std::byte{'X'}, std::byte{'E'}, std::byte{'X'}}) out.push_back(b);
    auto num = [&](std::uint64_t v, unsigned size) { return write_number(out, v, size, max_bytes); };
    if (!num(9, 2) || !num(0, 2) || !num(project.state->input.size, 8)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    out.insert(out.end(), project.state->input.sha256.begin(), project.state->input.sha256.end());
    if (!num(annotations.size(), 4) || !num(bookmarks.size(), 4) || !num(references.size(), 4) || !num(regions.size(), 4) || !num(functions.size(), 4) || !num(type_rows.size(), 4) || !num(assignments.size(), 4) || !num(debug_variables.size(),4) || !num(project_breakpoints.size(),4) || !num(patches.size(),4)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    for (const auto &row : annotations) if (!location_write(out, row.location, max_bytes) || !write_text(out, row.name, max_bytes) || !write_text(out, row.comment, max_bytes)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    for (const auto &row : bookmarks) if (!location_write(out, row.location, max_bytes) || !write_text(out, row.label, max_bytes)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    for (const auto &row : references) if (!location_write(out, row.source, max_bytes) || !location_write(out, row.target, max_bytes) || !num(row.kind, 1)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    for (const auto &row : regions) if (!location_write(out, row.begin, max_bytes) || !num(row.size, 8) || !num(row.kind, 1)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    for (const auto &row : functions) { if (!location_write(out, row.entry, max_bytes) || !num(row.suppressed, 1) || !num(row.chunks.size(), 4)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit); for (const auto &[begin, size] : row.chunks) if (!location_write(out, begin, max_bytes) || !num(size, 8)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit); }
    for (const auto &row : type_rows) { if (!write_text(out, row.name, max_bytes) || !write_blob(out, row.encoded, max_bytes) || !write_number(out,row.origin.has_value(),1,max_bytes)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit); if(row.origin&&(!write_text(out,row.origin->source_id,max_bytes)||!write_text(out,row.origin->section,max_bytes)||!write_number(out,row.origin->unit_offset,8,max_bytes)||!write_number(out,row.origin->record_offset,8,max_bytes)||!write_number(out,row.origin->record_size,8,max_bytes)))return invalid("Exchange output exceeds configured limit",ErrorCode::resource_limit); if(!num(static_cast<unsigned>(row.declaration_kind),1))return invalid("Exchange output exceeds configured limit",ErrorCode::resource_limit); }
    for (const auto &row : assignments) if (!location_write(out, row.location, max_bytes) || !write_text(out, row.type_name, max_bytes)) return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    for (const auto &row : debug_variables) if(!debug_variable_write(out,row,max_bytes))return invalid("Exchange output exceeds configured limit",ErrorCode::resource_limit);
    for (const auto &row : project_breakpoints)
        if (!location_write(out,row.location,max_bytes) || !num(row.kind,1) || !num(row.size,1) ||
            !num(row.enabled,1) || !write_text(out,row.condition,max_bytes) || !num(row.logpoint,1) ||
            !write_text(out,row.log_message,max_bytes) || !num(row.ignore_count,8) || !num(row.one_shot,1))
            return invalid("Exchange output exceeds configured limit",ErrorCode::resource_limit);
    for (const auto &row : patches)
        if (!num(row.offset, 8) || !write_blob(out, row.original, max_bytes) ||
            !write_blob(out, row.replacement, max_bytes))
            return invalid("Exchange output exceeds configured limit", ErrorCode::resource_limit);
    return out;
}
Result<ExchangeImport> import_project_exchange(const ProjectSnapshot &project, std::span<const std::byte> bytes,
                                               ExchangeConflictPolicy policy, std::size_t max_bytes) {
    max_bytes = std::min(max_bytes, max_exchange_bytes);
    if (!project.state || !project.state->user) return invalid("No project is open");
    if (policy != ExchangeConflictPolicy::fail && policy != ExchangeConflictPolicy::skip && policy != ExchangeConflictPolicy::replace) return invalid("Unknown exchange conflict policy");
    auto parsed = parse(project, bytes, max_bytes); if (!parsed) return parsed.error();
    const auto &user = *project.state->user; ExchangeImport result;
    auto conflict = [&](bool same) -> Result<bool> { if (same) { ++result.skipped; return false; } if (policy == ExchangeConflictPolicy::skip) { ++result.skipped; return false; } if (policy == ExchangeConflictPolicy::fail) return invalid("Project exchange conflicts with an existing user row", ErrorCode::conflict); return true; };
    for (const auto &row : parsed.value().annotations) {
        auto at = local(project, row.location); if (!at) return at.error();
        auto existing = std::find_if(user.annotations.begin(), user.annotations.end(), [&](const auto &item) { return item.location == at.value(); });
        if (existing != user.annotations.end() && (existing->name != row.name || existing->comment != row.comment)) {
            result.conflicts.push_back({ExchangeRecordKind::annotation, at.value(), {},
                                        policy == ExchangeConflictPolicy::replace ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing});
            auto replace = conflict(false); if (!replace) return replace.error(); if (!replace.value()) continue;
        }
        if (existing != user.annotations.end() && existing->name == row.name && existing->comment == row.comment) { ++result.skipped; continue; }
        if (!row.name.empty()) result.commands.emplace_back(Rename{at.value(), row.name});
        else if (existing != user.annotations.end() && !existing->name.empty()) result.commands.emplace_back(Rename{at.value(), {}});
        if (!row.comment.empty()) result.commands.emplace_back(Comment{at.value(), row.comment});
        else if (existing != user.annotations.end() && !existing->comment.empty()) result.commands.emplace_back(Comment{at.value(), {}});
        ++result.annotations;
    }
    for (const auto &row : parsed.value().bookmarks) {
        auto at = local(project, row.location); if (!at) return at.error();
        auto existing = std::find_if(user.bookmarks.begin(), user.bookmarks.end(), [&](const auto &item) { return item.location == at.value(); });
        if (existing != user.bookmarks.end() && existing->label != row.label) {
            result.conflicts.push_back({ExchangeRecordKind::bookmark, at.value(), {},
                                        policy == ExchangeConflictPolicy::replace ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing});
            auto replace = conflict(false); if (!replace) return replace.error(); if (!replace.value()) continue;
        }
        if (existing != user.bookmarks.end() && existing->label == row.label) { ++result.skipped; continue; }
        result.commands.emplace_back(BookmarkCommand{at.value(), row.label, false}); ++result.bookmarks;
    }
    std::vector<std::tuple<Location, Location, UserReferenceKind>> merged_references;
    merged_references.reserve(user.decisions.references.size() + parsed.value().references.size());
    for (const auto &item : user.decisions.references) merged_references.emplace_back(item.source, item.target, item.kind);
    for (const auto &row : parsed.value().references) {
        auto source = local(project, row.source); if (!source) return source.error(); auto target = local(project, row.target); if (!target) return target.error();
        const auto kind = static_cast<UserReferenceKind>(row.kind);
        auto existing = std::find_if(user.decisions.references.begin(), user.decisions.references.end(), [&](const auto &item) { return item.source == source.value() && item.target == target.value() && item.kind == kind; });
        if (existing != user.decisions.references.end()) { ++result.skipped; continue; }
        // References form a set rather than a single-valued slot. Multiple targets for
        // one source are meaningful, so retain both and expose that merge decision.
        auto alternate = std::find_if(merged_references.begin(), merged_references.end(), [&](const auto &item) {
            return std::get<0>(item) == source.value() && std::get<2>(item) == kind && std::get<1>(item) != target.value();
        });
        if (alternate != merged_references.end()) {
            result.conflicts.push_back({ExchangeRecordKind::reference, source.value(), target.value(), ExchangeConflictResolution::preserved_both});
        }
        result.commands.emplace_back(SetReference{source.value(), target.value(), kind, false});
        merged_references.emplace_back(source.value(), target.value(), kind);
        ++result.references;
    }
    for (const auto &row : parsed.value().regions) {
        auto begin = local_range(project, row.begin, row.size); if (!begin) return begin.error();
        const auto kind = static_cast<RegionKind>(row.kind);
        auto existing = std::find_if(user.decisions.regions.begin(), user.decisions.regions.end(), [&](const auto &item) { return item.begin == begin.value(); });
        if (existing != user.decisions.regions.end() && existing->size == row.size && existing->kind == kind) { ++result.skipped; continue; }
        if (existing != user.decisions.regions.end()) {
            result.conflicts.push_back({ExchangeRecordKind::region, begin.value(), {},
                                        policy == ExchangeConflictPolicy::replace ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing});
            auto replace = conflict(false); if (!replace) return replace.error(); if (!replace.value()) continue;
        }
        result.commands.emplace_back(DefineRegion{begin.value(), row.size, kind}); ++result.regions;
    }
    for (const auto &row : parsed.value().functions) {
        auto entry = local(project, row.entry); if (!entry) return entry.error();
        const auto *address = std::get_if<Address>(&entry.value()); if (!address) return invalid("Function entry is not a virtual address");
        std::vector<DecisionRange> chunks;
        for (const auto &[portable_begin, size] : row.chunks) { auto begin = local_range(project, portable_begin, size); if (!begin) return begin.error(); chunks.push_back({begin.value(), size}); }
        auto existing = std::find_if(user.decisions.functions.begin(), user.decisions.functions.end(), [&](const auto &item) { return item.entry == *address; });
        if (existing != user.decisions.functions.end() && existing->suppressed == row.suppressed && existing->chunks == chunks) { ++result.skipped; continue; }
        if (existing != user.decisions.functions.end()) {
            result.conflicts.push_back({ExchangeRecordKind::function, *address, {},
                                        policy == ExchangeConflictPolicy::replace ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing});
            auto replace = conflict(false); if (!replace) return replace.error(); if (!replace.value()) continue;
        }
        if (existing == user.decisions.functions.end() || existing->suppressed != row.suppressed) {
            if (row.suppressed) result.commands.emplace_back(SuppressFunction{*address, true});
            else result.commands.emplace_back(DefineFunction{*address});
        }
        // Empty is meaningful when replacing a destination function with explicit
        // chunks: it clears that destination-only override.  For a new function,
        // the absence of a chunk command already represents an empty chunk list.
        if ((existing == user.decisions.functions.end() && !chunks.empty()) ||
            (existing != user.decisions.functions.end() && existing->chunks != chunks))
            result.commands.emplace_back(SetFunctionChunks{*address, std::move(chunks)});
        ++result.functions;
    }
    ImportPortableTypes imported_types;
    for (const auto &row : parsed.value().types) {
        auto incoming = types::decode(row.encoded); if (!incoming) return invalid("Invalid portable type definition");
        auto existing = std::find_if(user.types.begin(), user.types.end(), [&](const auto &item) { return item.name == row.name; });
        if (existing == user.types.end()) {
            imported_types.definitions.push_back({row.name, incoming.value(), {}, row.origin, row.declaration_kind});
            ++result.type_definitions;
            continue;
        }
        auto current = types::encode(*existing->type);
        if (!current) return current.error();
        const auto incoming_origin=parsed.value().version>=4?row.origin:existing->origin;
        const auto incoming_kind=parsed.value().version>=5?row.declaration_kind:existing->declaration_kind;
        if (current.value() == row.encoded && existing->origin==incoming_origin && existing->declaration_kind==incoming_kind) { ++result.skipped; continue; }
        result.conflicts.push_back({ExchangeRecordKind::type_definition, FileOffset{}, {},
                                    policy == ExchangeConflictPolicy::replace ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing});
        auto replace = conflict(false); if (!replace) return replace.error(); if (!replace.value()) continue;
        PortableTypeDefinition replacement{row.name, incoming.value(), existing->id, incoming_origin, incoming_kind};
        replacement.expected_existing = *existing;
        imported_types.definitions.push_back(std::move(replacement));
        ++result.type_definitions;
    }
    // A type assignment is a single-valued address slot. The portable type name
    // resolves against the local definition after applying the selected type policy.
    for (const auto &row : parsed.value().type_assignments) {
        auto at = local(project, row.location); if (!at) return at.error();
        auto address = std::get_if<Address>(&at.value());
        if (!address) return invalid("Type assignment location is not a virtual address");
        auto existing_assignment = std::find_if(user.type_assignments.begin(), user.type_assignments.end(), [&](const auto &item) { return item.location == Location{*address}; });
        auto named = std::find_if(user.types.begin(), user.types.end(), [&](const auto &item) { return item.name == row.type_name; });
        const bool type_added = std::any_of(imported_types.definitions.begin(), imported_types.definitions.end(), [&](const auto &item) { return item.name == row.type_name && !item.existing_id; });
        if (existing_assignment != user.type_assignments.end() && named != user.types.end() && existing_assignment->type_id == named->id) {
            ++result.skipped;
            continue;
        }
        if (existing_assignment != user.type_assignments.end()) {
            result.conflicts.push_back({ExchangeRecordKind::type_assignment, Location{*address}, {},
                                        policy == ExchangeConflictPolicy::replace ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing});
            auto replace = conflict(false); if (!replace) return replace.error(); if (!replace.value()) continue;
        }
        if (named == user.types.end() && !type_added) return invalid("Imported type assignment has no destination type");
        imported_types.assignments.push_back({*address, row.type_name});
        ++result.type_assignments;
    }
    if (!imported_types.definitions.empty() || !imported_types.assignments.empty())
        result.commands.emplace_back(std::move(imported_types));
    ImportPortableDebugVariables imported_variables;
    imported_variables.variables.reserve(parsed.value().debug_variables.size());
    using OriginKey = std::tuple<std::string,std::string,std::uint64_t,std::uint64_t>;
    for (const auto &row : parsed.value().debug_variables) {
        auto entry_location=local(project,row.function_entry); if(!entry_location)return entry_location.error();
        const auto *entry=std::get_if<Address>(&entry_location.value());
        if(!entry)return invalid("Debug-variable function entry is not virtual");
        PortableDebugVariable variable{};
        variable.function_entry=*entry; variable.name=row.name; variable.type_name=row.type_name;
        variable.is_parameter=row.is_parameter; variable.scope_offset=row.scope_offset;
        variable.location_expression=row.expression; variable.location_operations=row.operations;
        variable.origin=row.origin; variable.cfa_offset=row.cfa_offset;
        if(row.address){
            auto address=local(project,*row.address); if(!address)return address.error();
            const auto *mapped=std::get_if<Address>(&address.value());
            if(!mapped)return invalid("Debug-variable direct address is not virtual");
            variable.address=*mapped;
        }
        variable.location_ranges.reserve(row.ranges.size());
        for(const auto &range:row.ranges){
            database::DebugLocationRange mapped{};
            if(range.is_default){mapped.begin=UINT64_MAX;mapped.end=UINT64_MAX;}
            else {
                auto begin=local_range(project,{1,range.begin},range.size); if(!begin)return begin.error();
                auto end=advance(begin.value(),range.size); if(!end)return invalid("Debug-variable PC range overflows destination mapping");
                mapped.begin=begin.value().offset; mapped.end=end.value().offset;
            }
            mapped.expression=range.expression;
            mapped.operations=range.operations;
            variable.location_ranges.push_back(mapped);
        }
        const OriginKey origin_key{row.origin.source_id,row.origin.section,row.origin.unit_offset,row.origin.record_offset};
        auto existing=std::find_if(user.debug_variables.begin(),user.debug_variables.end(),[&](const auto &item){
            return OriginKey{item.origin.source_id,item.origin.section,item.origin.unit_offset,item.origin.record_offset}==origin_key;
        });
        auto existing_type_name=[&]() -> std::optional<std::string> {
            if(existing==user.debug_variables.end() || !existing->type_id)return {};
            auto found=std::find_if(user.types.begin(),user.types.end(),[&](const auto &type){return type.id==*existing->type_id;});
            return found==user.types.end()?std::nullopt:std::optional<std::string>{found->name};
        };
        bool same=false;
        if(existing!=user.debug_variables.end()){
            same=existing->function_entry==variable.function_entry && existing->name==variable.name &&
                existing_type_name()==variable.type_name && existing->is_parameter==variable.is_parameter &&
                existing->scope_offset==variable.scope_offset && existing->address==(variable.address?std::optional<std::uint64_t>{variable.address->offset}:std::nullopt) &&
                existing->location_expression==variable.location_expression && existing->location_operations==variable.location_operations &&
                existing->origin==variable.origin && existing->cfa_offset==variable.cfa_offset &&
                existing->location_ranges==variable.location_ranges;
            if(!same){
                result.conflicts.push_back({ExchangeRecordKind::debug_variable,Location{*entry},{},
                    policy==ExchangeConflictPolicy::replace?ExchangeConflictResolution::imported:ExchangeConflictResolution::kept_existing});
                auto replace=conflict(false); if(!replace)return replace.error(); if(!replace.value())continue;
                variable.expected_existing=*existing;
            }else {++result.skipped;continue;}
        }else variable.expected_absent=true;
        imported_variables.variables.push_back(std::move(variable));
        ++result.debug_variables;
    }
    if(!imported_variables.variables.empty())
        result.commands.emplace_back(std::move(imported_variables));
    for (const auto &row : parsed.value().project_breakpoints) {
        auto location=local(project,row.location); if(!location)return location.error();
        const auto *address=std::get_if<Address>(&location.value());
        if(!address)return invalid("Imported project breakpoint is not a virtual address");
        const auto kind=static_cast<database::ProjectBreakpointKind>(row.kind);
        auto existing=std::find_if(user.breakpoints.begin(),user.breakpoints.end(),[&](const auto &item){return item.address==*address;});
        const bool same=existing!=user.breakpoints.end() && existing->kind==kind && existing->size==row.size &&
            existing->enabled==row.enabled && existing->condition==row.condition &&
            existing->logpoint==row.logpoint && existing->log_message==row.log_message &&
            existing->ignore_count==row.ignore_count && existing->one_shot==row.one_shot;
        if(same){++result.skipped;continue;}
        if(existing!=user.breakpoints.end()){
            result.conflicts.push_back({ExchangeRecordKind::project_breakpoint,Location{*address}, {},
                policy==ExchangeConflictPolicy::replace?ExchangeConflictResolution::imported:ExchangeConflictResolution::kept_existing});
            auto replace=conflict(false); if(!replace)return replace.error(); if(!replace.value())continue;
        }
        result.commands.emplace_back(SetProjectBreakpoint{*address,kind,row.size,row.enabled,false,
                                                          row.condition,row.logpoint,row.log_message,
                                                          row.ignore_count,row.one_shot});
        ++result.project_breakpoints;
    }
    for (const auto &row : parsed.value().patches) {
        const auto effective = project.effective;
        if (!effective) return invalid("Effective input is unavailable for patch conflict analysis");
        auto current = effective->read_at({row.offset}, row.replacement.size());
        if (!current || current.value().bytes.size() != row.replacement.size())
            return invalid("Cannot read current bytes for patch conflict analysis", ErrorCode::io);
        if (std::equal(current.value().bytes.begin(), current.value().bytes.end(), row.replacement.begin())) {
            ++result.skipped;
            continue;
        }
        std::optional<std::uint64_t> first_conflict;
        for (std::size_t i = 0; i < row.original.size(); ++i) {
            if (current.value().bytes[i] != row.original[i] &&
                current.value().bytes[i] != row.replacement[i]) {
                first_conflict = row.offset + i;
                break;
            }
        }
        if (first_conflict) {
            const auto resolution = policy == ExchangeConflictPolicy::replace
                ? ExchangeConflictResolution::imported : ExchangeConflictResolution::kept_existing;
            result.conflicts.push_back({ExchangeRecordKind::patch, Location{FileOffset{*first_conflict}}, {}, resolution});
            auto replace = conflict(false);
            if (!replace) return replace.error();
            if (!replace.value()) continue;
        }
        result.commands.emplace_back(PatchBytes{Location{FileOffset{row.offset}}, row.replacement});
        ++result.patches;
    }
    return result;
}
} // namespace hexlab
