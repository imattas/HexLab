#include "hexlab/types/pdb.hpp"
#include <algorithm>
#include <iterator>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <string>

namespace hexlab::types {
namespace {
constexpr std::size_t superblock_size = 56;
constexpr std::uint32_t absent_stream = 0xffffffffu;
constexpr std::uint64_t max_directory_size = 64ull * 1024 * 1024;
constexpr std::uint64_t max_stream_data = 256ull * 1024 * 1024;
constexpr std::uint32_t max_type_records = 2'000'000;
constexpr std::uint32_t max_function_parameters = 4096;
constexpr std::uint64_t max_type_server_stream_bytes = 512ull * 1024 * 1024;
struct Failure { Error error; };
[[noreturn]] void fail(ErrorCode code, const char *message) { throw Failure{{code, message}}; }
void require(bool condition, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!condition) fail(code, message);
}
void check_cancel(std::stop_token stop) {
    if (stop.stop_requested()) fail(ErrorCode::canceled, "PDB parsing canceled");
}
std::uint32_t u32(std::span<const std::byte> bytes, std::size_t at) {
    require(at <= bytes.size() && 4 <= bytes.size() - at, "Truncated MSF integer");
    return std::to_integer<std::uint32_t>(bytes[at]) |
        (std::to_integer<std::uint32_t>(bytes[at + 1]) << 8) |
        (std::to_integer<std::uint32_t>(bytes[at + 2]) << 16) |
        (std::to_integer<std::uint32_t>(bytes[at + 3]) << 24);
}
std::uint64_t checked_mul(std::uint64_t a, std::uint64_t b, const char *message) {
    if (a && b > std::numeric_limits<std::uint64_t>::max() / a)
        fail(ErrorCode::overflow, message);
    return a * b;
}
std::uint64_t type_server_stream_bytes(const PdbDatabase &database) {
    std::uint64_t total = 0;
    for (const auto &stream : database.streams) {
        if (!stream) continue;
        require(stream->size() <= max_type_server_stream_bytes - total,
                "Resolved PDB type-server stream data exceeds the aggregate import budget",
                ErrorCode::resource_limit);
        total += stream->size();
    }
    return total;
}
}

Result<PdbTypeStream> parse_pdb_types(const PdbDatabase &database, std::stop_token stop) {
    try {
        require(database.streams.size() > 2 && database.streams[2].has_value(), "PDB TPI stream is absent", ErrorCode::unsupported);
        const auto bytes = std::span<const std::byte>(*database.streams[2]);
        require(bytes.size() >= 56, "Truncated PDB TPI header");
        const auto header_size = u32(bytes, 4), begin = u32(bytes, 8), end = u32(bytes, 12), record_bytes = u32(bytes, 16);
        require(header_size >= 56 && header_size <= bytes.size(), "Invalid PDB TPI header size");
        require(begin >= 0x1000 && end >= begin && end - begin <= max_type_records,
                "Invalid PDB TPI type-index range", ErrorCode::resource_limit);
        require(record_bytes == bytes.size() - header_size, "PDB TPI record extent does not match stream");
        PdbTypeStream result; result.type_index_begin = begin; result.type_index_end = end;
        result.records.reserve(end - begin);
        std::size_t pos = header_size;
        const std::size_t data_end = bytes.size();
        auto read_name = [&](std::size_t &at, std::size_t limit) {
            std::string value;
            while (at < limit && bytes[at] != std::byte{0}) {
                require(value.size() < 4096, "CodeView type name exceeds limit", ErrorCode::resource_limit);
                value.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[at++])));
            }
            require(at < limit, "Unterminated CodeView type name"); ++at; return value;
        };
        auto numeric = [&](std::size_t &at, std::size_t limit, bool nonnegative = false) -> std::uint64_t {
            require(at + 2 <= limit, "Truncated CodeView numeric leaf");
            auto kind = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[at]) | (std::to_integer<unsigned>(bytes[at+1]) << 8)); at += 2;
            if (kind < 0x8000) return kind;
            std::size_t width = kind == 0x8000 ? 1 : (kind == 0x8001 || kind == 0x8002) ? 2 :
                (kind == 0x8003 || kind == 0x8004) ? 4 : (kind == 0x8009 || kind == 0x800a) ? 8 : 0;
            require(width && at + width <= limit, "Unsupported or truncated CodeView numeric leaf", ErrorCode::unsupported);
            std::uint64_t value = 0; for (std::size_t i=0;i<width;++i) value |= std::uint64_t(std::to_integer<unsigned>(bytes[at++])) << (8*i);
            const bool signed_leaf = kind == 0x8000 || kind == 0x8001 || kind == 0x8003 || kind == 0x8009;
            const bool negative = signed_leaf && (value & (std::uint64_t{1} << (width * 8 - 1)));
            require(!nonnegative || !negative, "CodeView offset/index must be nonnegative");
            if (signed_leaf && width < 8 && (value & (std::uint64_t{1} << (width * 8 - 1))))
                value |= (~std::uint64_t{0}) << (width * 8);
            return value;
        };
        for (std::uint32_t ix = begin; ix < end; ++ix) {
            check_cancel(stop);
            require(pos + 4 <= data_end, "Truncated CodeView type record");
            const auto length = std::uint16_t(std::to_integer<unsigned>(bytes[pos]) | (std::to_integer<unsigned>(bytes[pos+1]) << 8));
            const auto leaf = std::uint16_t(std::to_integer<unsigned>(bytes[pos+2]) | (std::to_integer<unsigned>(bytes[pos+3]) << 8));
            require(length >= 2 && std::uint64_t(pos) + 2 + length <= data_end, "Invalid CodeView type record length");
            const auto limit = pos + 2 + length; std::size_t at = pos + 4;
            CodeViewTypeRecord rec; rec.index = ix; rec.leaf = leaf;
            rec.record_offset = static_cast<std::uint32_t>(pos);
            rec.record_size = static_cast<std::uint32_t>(limit - pos);
            auto r16 = [&]() { require(at+2<=limit,"Truncated CodeView type field"); auto x=std::uint16_t(std::to_integer<unsigned>(bytes[at])|(std::to_integer<unsigned>(bytes[at+1])<<8)); at+=2; return x; };
            auto r32 = [&]() { auto x=u32(bytes,at); require(at+4<=limit,"Truncated CodeView type field"); at+=4; return x; };
            switch (leaf) {
            case 0x000a: { // LF_VTSHAPE: packed four-bit virtual-function entry kinds.
                rec.kind = CodeViewTypeKind::vftable_shape;
                const auto count = r16();
                const auto byte_count = (static_cast<std::size_t>(count) + 1) / 2;
                require(byte_count <= limit - at, "Truncated CodeView LF_VTSHAPE record");
                rec.vftable_slot_kinds.reserve(count);
                for (std::size_t i = 0; i < byte_count; ++i) {
                    const auto packed = std::to_integer<std::uint8_t>(bytes[at++]);
                    rec.vftable_slot_kinds.push_back(packed & 0x0f);
                    if (rec.vftable_slot_kinds.size() < count)
                        rec.vftable_slot_kinds.push_back(packed >> 4);
                }
                const auto padding = limit - at;
                require(padding <= 3, "CodeView LF_VTSHAPE has unexpected trailing bytes");
                for (std::size_t i = 0; i < padding; ++i)
                    require(std::to_integer<unsigned>(bytes[at + i]) == 0xf0u + padding - i,
                            "CodeView LF_VTSHAPE has invalid trailing padding");
                at = limit;
                break;
            }
            case 0x1002: { // LF_POINTER: referent plus packed pointer attributes.
                rec.kind=CodeViewTypeKind::pointer;
                rec.referenced_type=r32();
                const auto attributes=r32();
                rec.pointer_kind=static_cast<std::uint8_t>(attributes & 0x1f);
                rec.pointer_mode=static_cast<std::uint8_t>((attributes >> 5) & 0x07);
                rec.size=(attributes >> 13) & 0xff;
                // Preserve documented option bits plus the unused high bits so
                // the importer rejects flags it cannot represent. CodeView's
                // pointer-size byte is extracted separately at bits 13..20.
                rec.pointer_options=attributes & 0xfff81f00;
                if (attributes & 0x00000200) rec.qualifier_bits |= 2; // volatile
                if (attributes & 0x00000400) rec.qualifier_bits |= 1; // const
                if (attributes & 0x00001000) rec.qualifier_bits |= 4; // restrict
                break;
            }
            case 0x1001: { // LF_MODIFIER
                rec.kind=CodeViewTypeKind::modifier;
                rec.referenced_type=r32();
                const auto modifiers=r16();
                if (modifiers & 0x0001) rec.qualifier_bits |= 1; // const
                if (modifiers & 0x0002) rec.qualifier_bits |= 2; // volatile
                // Unaligned and reserved modifier bits are retained as unsupported flags.
                rec.pointer_options=modifiers & ~std::uint32_t{3};
                break;
            }
            case 0x1205: { // LF_BITFIELD: integral storage type, width and LSB-relative position.
                rec.kind=CodeViewTypeKind::bitfield;
                rec.referenced_type=r32();
                require(at + 2 <= limit, "Truncated CodeView LF_BITFIELD record");
                rec.bitfield_width=static_cast<std::uint8_t>(std::to_integer<unsigned>(bytes[at++]));
                rec.bitfield_position=static_cast<std::uint8_t>(std::to_integer<unsigned>(bytes[at++]));
                break;
            }
            case 0x1008: { // LF_PROCEDURE
                rec.kind = CodeViewTypeKind::procedure;
                require(at + 12 <= limit, "Truncated CodeView LF_PROCEDURE record");
                rec.referenced_type = r32();
                rec.calling_convention = static_cast<std::uint8_t>(std::to_integer<unsigned>(bytes[at++]));
                rec.function_options = static_cast<std::uint8_t>(std::to_integer<unsigned>(bytes[at++]));
                rec.parameter_count = r16();
                rec.field_list = r32(); // LF_ARGLIST type index.
                require(rec.parameter_count <= max_function_parameters,
                        "CodeView procedure has too many parameters", ErrorCode::resource_limit);
                break;
            }
            case 0x1009: { // LF_MFUNCTION
                rec.kind = CodeViewTypeKind::member_function;
                require(at + 24 <= limit, "Truncated CodeView LF_MFUNCTION record");
                rec.referenced_type = r32(); // Return type.
                rec.member_class_type = r32();
                rec.member_this_type = r32();
                rec.calling_convention = static_cast<std::uint8_t>(std::to_integer<unsigned>(bytes[at++]));
                rec.function_options = static_cast<std::uint8_t>(std::to_integer<unsigned>(bytes[at++]));
                rec.parameter_count = r16();
                rec.field_list = r32(); // LF_ARGLIST type index.
                rec.this_adjustment = static_cast<std::int32_t>(r32());
                require(rec.parameter_count <= max_function_parameters,
                        "CodeView member function has too many parameters", ErrorCode::resource_limit);
                break;
            }
            case 0x1201: { // LF_ARGLIST
                rec.kind = CodeViewTypeKind::argument_list;
                require(at + 4 <= limit, "Truncated CodeView LF_ARGLIST record");
                const auto count = r32();
                require(count <= max_function_parameters,
                        "CodeView argument list exceeds the parameter limit", ErrorCode::resource_limit);
                require(count <= (limit - at) / 4, "Truncated CodeView LF_ARGLIST record");
                rec.fields.reserve(count);
                for (std::uint32_t i = 0; i < count; ++i) {
                    CodeViewField argument;
                    argument.type = r32();
                    rec.fields.push_back(std::move(argument));
                }
                break;
            }
            case 0x1503: { // LF_ARRAY
                rec.kind=CodeViewTypeKind::array; rec.referenced_type=r32(); rec.underlying_type=r32(); rec.size=numeric(at,limit); rec.name=read_name(at,limit); break;
            }
            case 0x1516: { // LF_STRIDED_ARRAY: LF_ARRAY fields plus element byte stride.
                rec.kind = CodeViewTypeKind::strided_array;
                rec.referenced_type = r32();
                rec.underlying_type = r32();
                rec.size = numeric(at, limit);
                rec.array_stride = numeric(at, limit, true);
                rec.name = read_name(at, limit);
                require(rec.array_stride != 0, "CodeView LF_STRIDED_ARRAY has zero stride");
                break;
            }
            case 0x151b: { // LF_VECTOR: scalar lane type, count, byte extent, and name.
                rec.kind = CodeViewTypeKind::vector;
                rec.referenced_type = r32();
                rec.element_count = r32();
                rec.size = numeric(at, limit, true);
                rec.name = read_name(at, limit);
                require(rec.element_count >= 2, "CodeView LF_VECTOR has fewer than two lanes");
                require(rec.size != 0, "CodeView LF_VECTOR has zero byte extent");
                {
                    const auto padding = limit - at;
                    require(padding <= 3, "CodeView LF_VECTOR has unexpected trailing bytes");
                    for (std::size_t i = 0; i < padding; ++i)
                        require(std::to_integer<unsigned>(bytes[at + i]) == 0xf0u + padding - i,
                                "CodeView LF_VECTOR has invalid trailing padding");
                    at = limit;
                }
                break;
            }
            case 0x1504: case 0x1505: case 0x1519: { // class/structure/interface
                const auto count=r16(); const auto properties=r16(); rec.field_list=r32(); rec.derivation_list=r32(); rec.vtable_shape=r32(); rec.size=numeric(at,limit); rec.name=read_name(at,limit);
                if (properties & 0x0200) {
                    rec.unique_name=read_name(at,limit);
                    require(!rec.unique_name.empty(), "CodeView aggregate unique name is empty");
                }
                rec.kind=leaf == 0x1504 ? CodeViewTypeKind::class_type : CodeViewTypeKind::structure;
                rec.forward_declaration=(properties & 0x0080) != 0; (void)count; break;
            }
            case 0x151d: { // LF_VFTABLE: one table pointer plus ordered raw slot names.
                rec.kind = CodeViewTypeKind::vftable;
                require(at + 16 <= limit, "Truncated CodeView LF_VFTABLE header");
                rec.vftable_complete_class_type = r32();
                rec.vftable_overridden_type = r32();
                rec.vftable_vfptr_offset = r32();
                const auto names_size = r32();
                require(names_size <= limit - at, "CodeView LF_VFTABLE names exceed record bounds");
                const auto names_end = at + names_size;
                while (at < names_end) {
                    require(rec.vftable_names.size() < 100'001,
                            "CodeView LF_VFTABLE has too many names", ErrorCode::resource_limit);
                    rec.vftable_names.push_back(read_name(at, names_end));
                }
                require(at == names_end && !rec.vftable_names.empty() &&
                        !rec.vftable_names.front().empty(),
                        "CodeView LF_VFTABLE has no vftable name");
                const auto padding = limit - at;
                require(padding <= 3, "CodeView LF_VFTABLE has unexpected trailing bytes");
                for (std::size_t i = 0; i < padding; ++i)
                    require(std::to_integer<unsigned>(bytes[at + i]) == 0xf0u + padding - i,
                            "CodeView LF_VFTABLE has invalid trailing padding");
                at = limit;
                break;
            }
            case 0x1506: { // LF_UNION
                (void)r16(); const auto properties=r16(); rec.field_list=r32(); rec.size=numeric(at,limit); rec.name=read_name(at,limit);
                if (properties & 0x0200) {
                    rec.unique_name=read_name(at,limit);
                    require(!rec.unique_name.empty(), "CodeView union unique name is empty");
                }
                rec.kind=CodeViewTypeKind::union_type; break;
            }
            case 0x1507: { // LF_ENUM
                (void)r16(); const auto properties=r16(); rec.underlying_type=r32(); rec.field_list=r32(); rec.name=read_name(at,limit);
                if (properties & 0x0200) {
                    rec.unique_name=read_name(at,limit);
                    require(!rec.unique_name.empty(), "CodeView enum unique name is empty");
                }
                rec.kind=CodeViewTypeKind::enumeration; break;
            }
            case 0x1203: { // LF_FIELDLIST, data members, enumerators and continuations
                rec.kind=CodeViewTypeKind::field_list;
                while (at+2<=limit) {
                    if (std::to_integer<unsigned>(bytes[at]) >= 0xf0 && std::to_integer<unsigned>(bytes[at]) <= 0xff) {
                        const auto padding = std::to_integer<unsigned>(bytes[at++]) & 0x0f;
                        if (!padding) break;
                        require(padding - 1 <= limit - at, "Truncated CodeView field-list padding"); at += padding - 1; continue;
                    }
                    auto member= r16();
                    CodeViewField f; f.leaf=member;
                    f.record_offset = static_cast<std::uint32_t>(at - 2);
                    if (member==0x150d) { f.attributes=r16(); f.type=r32(); f.offset=numeric(at,limit); f.name=read_name(at,limit); }
                    else if (member==0x1400 || member==0x151a) { // LF_BCLASS / LF_BINTERFACE
                        // Both describe a fixed-offset base. Keep the original leaf
                        // so interface-base provenance survives graph expansion.
                        f.attributes=r16(); f.type=r32(); f.offset=numeric(at,limit,member==0x151a);
                    }
                    else if (member==0x1401 || member==0x1402) { // LF_VBCLASS / LF_IVBCLASS
                        require(limit - at >= 10, "Truncated CodeView virtual-base header");
                        f.attributes=r16(); f.type=r32(); f.auxiliary_type=r32();
                        f.offset=numeric(at,limit,true); // vbptr byte offset within the class
                        f.value=numeric(at,limit,true); // entry index, not a byte offset
                    }
                    else if (member==0x150e) { // LF_STMEMBER: static data member has no object offset.
                        f.attributes=r16(); f.type=r32(); f.name=read_name(at,limit);
                    }
                    else if (member==0x150f) { // LF_METHOD: overloaded method set.
                        f.value=r16(); f.type=r32(); f.name=read_name(at,limit);
                    }
                    else if (member==0x150c) { // LF_FRIENDFCN: function type and friend name.
                        require(r16() == 0, "CodeView LF_FRIENDFCN has nonzero reserved padding");
                        f.type=r32(); f.name=read_name(at,limit);
                    }
                    else if (member==0x140a) { // LF_FRIENDCLS: friend class type.
                        require(r16() == 0, "CodeView LF_FRIENDCLS has nonzero reserved padding");
                        f.type=r32();
                    }
                    else if (member==0x1511) { // LF_ONEMETHOD.
                        f.attributes=r16(); f.type=r32();
                        const auto property = (f.attributes >> 2) & 7;
                        if (property == 4 || property == 6) f.value=r32(); // introducing virtual slot offset
                        f.name=read_name(at,limit);
                    }
                    else if (member==0x1409) { // LF_VFUNCTAB: type of the implicit vfptr.
                        f.type=r32();
                    }
                    else if (member==0x140c) { // LF_VFUNCOFF: vfptr at a nonzero class byte offset.
                        f.type=r32(); f.value=r32();
                    }
                    else if (member==0x1510) { // LF_NESTTYPE: nested type declaration.
                        (void)r16(); f.type=r32(); f.name=read_name(at,limit);
                    }
                    else if (member==0x1512) { // LF_NESTTYPEEX: nested type with access attributes.
                        f.attributes=r16(); f.type=r32(); f.name=read_name(at,limit);
                    }
                    else if (member==0x1502) { f.attributes=r16(); f.value=numeric(at,limit); f.name=read_name(at,limit); }
                    else if (member==0x1404) { // LF_INDEX continuation
                        (void)r16(); rec.field_list_continuations.push_back(r32());
                        continue;
                    }
                    else { rec.fields.push_back({member}); break; }
                    rec.fields.push_back(std::move(f));
                }
                break;
            }
            case 0x1206: { // LF_METHODLIST: bounded overload entries.
                rec.kind=CodeViewTypeKind::method_list;
                while (at < limit) {
                    if (std::to_integer<unsigned>(bytes[at]) >= 0xf0 &&
                        std::to_integer<unsigned>(bytes[at]) <= 0xff) {
                        const auto padding = std::to_integer<unsigned>(bytes[at++]) & 0x0f;
                        require(padding != 0 && padding - 1 <= limit - at,
                                "Invalid CodeView method-list padding");
                        for (unsigned i = 1; i < padding; ++i)
                            require(std::to_integer<unsigned>(bytes[at + i - 1]) == 0xf0u + padding - i,
                                    "Invalid CodeView method-list padding");
                        at += padding - 1;
                        continue;
                    }
                    require(at + 8 <= limit, "Truncated CodeView LF_METHODLIST entry");
                    CodeViewField method; method.leaf=0x1511; method.attributes=r16();
                    require(r16() == 0, "CodeView LF_METHODLIST has nonzero reserved padding");
                    method.type=r32();
                    const auto property = (method.attributes >> 2) & 7;
                    if (property == 4 || property == 6) method.value=r32();
                    rec.fields.push_back(std::move(method));
                }
                break;
            }
            case 0x1515: { // LF_TYPESERVER2: referenced indices stay in the server TPI namespace.
                rec.kind=CodeViewTypeKind::type_server;
                require(at + 20 <= limit, "Truncated LF_TYPESERVER2 identity");
                std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(at), 16, rec.type_server_guid.begin()); at += 16;
                rec.type_server_age=r32(); rec.name=read_name(at,limit); break;
            }            case 0x150a: { // LF_ALIAS
                rec.kind=CodeViewTypeKind::typedef_type; rec.referenced_type=r32(); rec.name=read_name(at,limit); break;
            }
            default: rec.kind=CodeViewTypeKind::unsupported; break;
            }
            // Simple type indices encode primitive types directly below 0x1000.
            if (rec.kind==CodeViewTypeKind::unsupported && leaf < 0x1000) rec.kind=CodeViewTypeKind::primitive;
            result.records.push_back(std::move(rec)); pos=limit;
        }
        require(pos == data_end, "PDB TPI stream has trailing type bytes");
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit,"PDB TPI data exceeds available memory"}; }
}

static Result<PdbIdStream> parse_pdb_ids_impl(const PdbDatabase &database,
        std::span<const std::uint32_t> requested_indices, bool retain_all, std::stop_token stop) {
    try {
        require(retain_all || (std::is_sorted(requested_indices.begin(), requested_indices.end()) &&
                std::adjacent_find(requested_indices.begin(), requested_indices.end()) == requested_indices.end()),
                "Requested PDB IPI indices must be sorted and unique", ErrorCode::invalid_argument);
        require(database.streams.size() > 4 && database.streams[4].has_value(),
                "PDB IPI stream is absent", ErrorCode::unsupported);
        const auto bytes = std::span<const std::byte>(*database.streams[4]);
        require(bytes.size() >= 56, "Truncated PDB IPI header");
        const auto header_size = u32(bytes, 4), begin = u32(bytes, 8), end = u32(bytes, 12),
                   record_bytes = u32(bytes, 16);
        require(header_size >= 56 && header_size <= bytes.size(), "Invalid PDB IPI header size");
        require(begin >= 0x1000 && end >= begin && end - begin <= max_type_records,
                "Invalid PDB IPI type-index range", ErrorCode::resource_limit);
        require(record_bytes == bytes.size() - header_size, "PDB IPI record extent does not match stream");

        PdbIdStream result;
        result.type_index_begin = begin;
        result.type_index_end = end;
        result.records.reserve(retain_all ? end - begin : std::min<std::size_t>(end - begin, requested_indices.size()));
        const auto record_count = end - begin;
        std::uint32_t decoded_records = 0;
        std::size_t pos = header_size;
        while (decoded_records < record_count) {
            check_cancel(stop);
            if (pos + 4 > bytes.size())
                throw Failure{{ErrorCode::malformed, "Truncated PDB IPI record header at stream offset " + std::to_string(pos)}};
            const auto length = static_cast<std::uint16_t>(
                std::to_integer<unsigned>(bytes[pos]) | (std::to_integer<unsigned>(bytes[pos + 1]) << 8));
            const auto leaf = static_cast<std::uint16_t>(
                std::to_integer<unsigned>(bytes[pos + 2]) | (std::to_integer<unsigned>(bytes[pos + 3]) << 8));
            if (length < 2 || std::uint64_t(pos) + 2 + length > bytes.size())
                throw Failure{{ErrorCode::malformed, "Invalid PDB IPI record length at stream offset " + std::to_string(pos)}};
            const auto limit = pos + 2 + length;
            std::size_t at = pos + 4;
            const auto index = begin + decoded_records;
            const bool retain = retain_all || std::binary_search(requested_indices.begin(),
                                                                  requested_indices.end(), index);
            CodeViewIdRecord record;
            record.index = index;
            record.leaf = leaf;
            record.record_offset = static_cast<std::uint32_t>(pos);
            record.record_size = static_cast<std::uint32_t>(limit - pos);
            const auto read_index = [&]() -> std::uint32_t {
                if (at > limit || limit - at < 4)
                    throw Failure{{ErrorCode::malformed, "Truncated PDB IPI type index at stream offset " + std::to_string(pos)}};
                const auto value = u32(bytes, at);
                at += 4;
                return value;
            };
            const auto read_name = [&]() {
                std::string name;
                std::size_t name_size = 0;
                while (at < limit && bytes[at] != std::byte{0}) {
                    if (name_size >= 4096)
                        throw Failure{{ErrorCode::resource_limit, "PDB IPI function name exceeds 4096 bytes at stream offset " + std::to_string(pos)}};
                    if (retain) name.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[at])));
                    ++name_size;
                    ++at;
                }
                if (at == limit)
                    throw Failure{{ErrorCode::malformed, "Unterminated PDB IPI function name at stream offset " + std::to_string(pos)}};
                ++at;
                return name;
            };
            const auto read_id_list = [&](std::uint32_t count) {
                if (count > max_type_records || count > (limit - at) / 4)
                    throw Failure{{ErrorCode::malformed, "Invalid PDB IPI reference count at stream offset " + std::to_string(pos)}};
                if (retain) {
                    record.references.reserve(count);
                    for (std::uint32_t i = 0; i < count; ++i) record.references.push_back(read_index());
                } else {
                    at += static_cast<std::size_t>(count) * 4;
                }
            };
            switch (leaf) {
            case 0x1601: // LF_FUNC_ID: parent ID, TPI function type, name.
                record.kind = CodeViewIdKind::function;
                record.parent_scope = read_index();
                record.function_type = read_index();
                record.name = read_name();
                break;
            case 0x1602: // LF_MFUNC_ID: TPI class, TPI member-function type, name.
                record.kind = CodeViewIdKind::member_function;
                record.class_type = read_index();
                record.function_type = read_index();
                record.name = read_name();
                break;
            case 0x1603: { // LF_BUILDINFO: count and IPI argument IDs.
                record.kind = CodeViewIdKind::build_info;
                if (at > limit || limit - at < 2)
                    throw Failure{{ErrorCode::malformed, "Truncated PDB LF_BUILDINFO count at stream offset " + std::to_string(pos)}};
                const auto count = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[at]) |
                    (std::to_integer<unsigned>(bytes[at + 1]) << 8));
                at += 2;
                if (count > 5)
                    throw Failure{{ErrorCode::malformed, "PDB LF_BUILDINFO count exceeds the CodeView field limit at stream offset " + std::to_string(pos)}};
                read_id_list(count);
                break;
            }
            case 0x1604: { // LF_SUBSTR_LIST: count and IPI string IDs.
                record.kind = CodeViewIdKind::substring_list;
                const auto count = read_index();
                read_id_list(count);
                break;
            }
            case 0x1605: // LF_STRING_ID: parent string-list ID and string.
                record.kind = CodeViewIdKind::string_id;
                record.parent_string_id = read_index();
                record.name = read_name();
                break;
            case 0x1606: // LF_UDT_SRC_LINE: TPI UDT, source string ID, line.
            case 0x1607: // LF_UDT_MOD_SRC_LINE adds a module index.
                record.kind = leaf == 0x1606 ? CodeViewIdKind::udt_source_line : CodeViewIdKind::udt_module_source_line;
                record.related_type = read_index();
                record.source_file_id = read_index();
                record.line_number = read_index();
                if (leaf == 0x1607) {
                    if (at > limit || limit - at < 2)
                        throw Failure{{ErrorCode::malformed, "Truncated PDB LF_UDT_MOD_SRC_LINE module index at stream offset " + std::to_string(pos)}};
                    record.module_index = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[at]) |
                        (std::to_integer<unsigned>(bytes[at + 1]) << 8));
                    at += 2;
                }
                break;
            default:
                record.kind = CodeViewIdKind::unsupported;
                break; // Keep the unknown leaf and its exact stream extent.
            }
            if (retain) result.records.push_back(std::move(record));
            ++decoded_records;
            pos = limit;
        }
        if (pos != bytes.size())
            throw Failure{{ErrorCode::malformed, "PDB IPI stream has trailing bytes at stream offset " + std::to_string(pos)}};
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB IPI data exceeds available memory"}; }
}

Result<PdbIdStream> parse_pdb_ids(const PdbDatabase &database, std::stop_token stop) {
    return parse_pdb_ids_impl(database, {}, true, stop);
}

Result<PdbIdStream> parse_pdb_ids(const PdbDatabase &database,
        std::span<const std::uint32_t> requested_indices, std::stop_token stop) {
    return parse_pdb_ids_impl(database, requested_indices, false, stop);
}

Result<PdbTypeServerSet> resolve_pdb_type_servers(const PdbDatabase &database,
        const PdbTypeServerResolver &resolver, std::size_t max_servers, std::stop_token stop) {
    try {
        require(static_cast<bool>(resolver), "PDB type-server resolver is empty", ErrorCode::invalid_argument);
        require(max_servers > 0 && max_servers <= 255, "PDB type-server resolver bound is invalid", ErrorCode::resource_limit);
        auto parsed = parse_pdb_types(database, stop); if (!parsed) return parsed.error();
        PdbTypeServerSet result;
        struct Pending { PdbTypeServerRequest request; std::size_t depth = 0; };
        std::vector<Pending> pending;
        for (const auto &record : parsed.value().records)
            if (record.kind == CodeViewTypeKind::type_server)
                pending.push_back({{record.type_server_guid, record.type_server_age, record.name}, 1});
        const auto same_identity = [](const PdbTypeServerRequest &a, const PdbTypeServerRequest &b) {
            return a.guid == b.guid && a.age == b.age;
        };
        std::vector<PdbTypeServerRequest> known;
        known.push_back({database.info.guid, database.info.age, {}}); // Prevent resolving cycles back to the root.
        std::uint64_t server_bytes = 0;
        std::size_t next_namespace = 1;
        std::size_t cursor = 0;
        constexpr std::size_t max_depth = 32;
        while (cursor < pending.size()) {
            check_cancel(stop);
            auto item = std::move(pending[cursor++]);
            require(item.depth <= max_depth, "PDB LF_TYPESERVER2 nesting exceeds depth limit", ErrorCode::resource_limit);
            const auto identity = std::find_if(known.begin(), known.end(), [&](const auto &entry) {
                return same_identity(entry, item.request);
            });
            if (identity != known.end()) {
                if (!identity->path.empty())
                    require(identity->path == item.request.path, "Conflicting paths for one PDB type-server identity");
                continue;
            }
            require(result.namespaces.size() < max_servers, "PDB type-server count exceeds caller limit", ErrorCode::resource_limit);
            require(next_namespace <= 255, "PDB type-server namespace selector overflow", ErrorCode::resource_limit);
            auto loaded = resolver(item.request); if (!loaded) return loaded.error();
            require(loaded.value().info.guid == item.request.guid && loaded.value().info.age == item.request.age,
                    "Resolved PDB type-server GUID+age does not match LF_TYPESERVER2", ErrorCode::integrity);
            const auto bytes = type_server_stream_bytes(loaded.value());
            require(bytes <= max_type_server_stream_bytes - server_bytes,
                    "Resolved PDB type-server stream data exceeds the aggregate import budget", ErrorCode::resource_limit);
            server_bytes += bytes;
            auto types = parse_pdb_types(loaded.value(), stop); if (!types) return types.error();
            const auto assigned_index = static_cast<std::uint8_t>(next_namespace++);
            known.push_back(item.request);
            result.namespaces.push_back({std::move(item.request), std::move(loaded.value()),
                                         std::move(types.value()), assigned_index, {{std::uint8_t{0}, assigned_index}}});
            for (const auto &record : result.namespaces.back().types.records)
                if (record.kind == CodeViewTypeKind::type_server)
                    pending.push_back({{record.type_server_guid, record.type_server_age, record.name}, item.depth + 1});
            require(pending.size() <= max_servers * 256ull,
                    "PDB LF_TYPESERVER2 reference count exceeds inspection limit", ErrorCode::resource_limit);
        }
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB type-server data exceeds available memory"}; }
}

Result<std::vector<PdbTypeServerMapEntry>> parse_pdb_type_server_map(const PdbDatabase &database,
                                                                    std::stop_token stop) {
    try {
        require(database.streams.size() > 3 && database.streams[3].has_value(),
                "PDB DBI stream is absent", ErrorCode::unsupported);
        const auto dbi = std::span<const std::byte>(*database.streams[3]);
        require(dbi.size() >= 64, "Truncated PDB DBI header");
        const auto module_bytes = u32(dbi, 24);
        const auto contrib_bytes = u32(dbi, 28);
        const auto section_map_bytes = u32(dbi, 32);
        const auto source_bytes = u32(dbi, 36);
        const auto type_server_bytes = u32(dbi, 40);
        const auto optional_bytes = u32(dbi, 48);
        const auto ec_bytes = u32(dbi, 52);
        std::uint64_t expected = 64;
        for (const auto size : {module_bytes, contrib_bytes, section_map_bytes, source_bytes,
                                type_server_bytes, optional_bytes, ec_bytes}) {
            require(size <= 64ull * 1024 * 1024 && expected <= dbi.size() && size <= dbi.size() - expected,
                    "PDB DBI substream exceeds its bounds", ErrorCode::resource_limit);
            expected += size;
        }
        require(expected == dbi.size(), "PDB DBI substream sizes do not match stream extent");
        require(type_server_bytes <= 32ull * 1024 * 1024,
                "PDB type-server map exceeds inspection limit", ErrorCode::resource_limit);
        const auto map_begin = std::size_t{64} + module_bytes + contrib_bytes + section_map_bytes + source_bytes;
        const auto map_end = map_begin + type_server_bytes;
        std::vector<PdbTypeServerMapEntry> entries;
        std::size_t pos = map_begin;
        auto cstring = [&](std::size_t &at) {
            std::string value;
            while (at < map_end && dbi[at] != std::byte{0}) {
                require(value.size() < 32768, "PDB type-server path exceeds limit", ErrorCode::resource_limit);
                value.push_back(static_cast<char>(std::to_integer<unsigned char>(dbi[at++])));
            }
            require(at < map_end, "Unterminated PDB type-server map string");
            ++at;
            return value;
        };
        while (pos < map_end) {
            check_cancel(stop);
            if (map_end - pos <= 3) {
                require(std::all_of(dbi.begin() + static_cast<std::ptrdiff_t>(pos),
                                    dbi.begin() + static_cast<std::ptrdiff_t>(map_end),
                                    [](std::byte value) { return value == std::byte{0}; }),
                        "Nonzero trailing bytes in PDB type-server map");
                pos = map_end;
                break;
            }
            require(map_end - pos >= 16, "Truncated PDB type-server map entry");
            require(entries.size() < 256, "PDB type-server map has more than 256 namespaces",
                    ErrorCode::resource_limit);
            PdbTypeServerMapEntry entry;
            // The namespace selector is the TSM array ordinal. tiBase is a
            // server type-index base (commonly 0x1000), not the selector.
            entry.index = static_cast<std::uint8_t>(entries.size());
            entry.type_base = u32(dbi, pos + 4);
            entry.signature = u32(dbi, pos + 8);
            entry.age = u32(dbi, pos + 12);
            pos += 16;
            entry.name = cstring(pos);
            entry.path = cstring(pos);
            pos = (pos + 3u) & ~std::size_t{3};
            require(pos <= map_end, "PDB type-server map alignment exceeds its substream");
            entries.push_back(std::move(entry));
        }
        std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) { return a.index < b.index; });
        return entries;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB type-server map exceeds available memory"}; }
}

Result<PdbTypeServerSet> resolve_pdb_type_server_map(const PdbDatabase &database,
        const PdbTypeServerResolver &resolver, std::size_t max_servers, std::stop_token stop) {
    try {
        require(static_cast<bool>(resolver), "PDB type-server resolver is empty", ErrorCode::invalid_argument);
        require(max_servers > 0 && max_servers <= 255,
                "PDB type-server resolver bound is invalid", ErrorCode::resource_limit);
        auto map = parse_pdb_type_server_map(database, stop);
        if (!map) return map.error();
        PdbTypeServerSet result;
        result.root_namespace_map.reserve(map.value().size());
        std::map<std::pair<std::uint32_t, std::uint32_t>, std::uint8_t> identities;
        std::map<std::uint8_t, std::string> identity_paths;
        identities.emplace(std::pair{database.info.signature, database.info.age}, std::uint8_t{0});
        identity_paths.emplace(std::uint8_t{0}, std::string{});
        std::map<std::uint8_t, std::size_t> positions;
        std::size_t next_namespace = 1; // Global selector zero is the root TPI.
        std::uint64_t server_bytes = 0;
        for (const auto &entry : map.value()) {
            check_cancel(stop);
            if (entry.index == 0) continue; // Selector zero means this PDB's TPI.
            require(!entry.name.empty() || !entry.path.empty(),
                    "PDB type-server map entry has no identity path");
            PdbTypeServerRequest request;
            request.signature = entry.signature;
            request.age = entry.age;
            request.path = entry.name.empty() ? entry.path : entry.name;
            const auto identity = std::pair{entry.signature, entry.age};
            if (const auto known = identities.find(identity); known != identities.end()) {
                if (known->second != 0) {
                    const auto path = identity_paths.find(known->second);
                    if (path != identity_paths.end())
                        require(path->second == request.path,
                                "Conflicting paths for one PDB type-server identity", ErrorCode::integrity);
                }
                result.root_namespace_map.emplace_back(entry.index, known->second);
                continue;
            }
            require(result.namespaces.size() < max_servers,
                    "PDB type-server count exceeds caller limit", ErrorCode::resource_limit);
            require(next_namespace <= 255,
                    "PDB type-server namespace selector overflow", ErrorCode::resource_limit);
            auto loaded = resolver(request);
            if (!loaded) return loaded.error();
            require(loaded.value().info.signature == entry.signature && loaded.value().info.age == entry.age,
                    "Resolved PDB type-server signature+age does not match the DBI map", ErrorCode::integrity);
            const auto bytes = type_server_stream_bytes(loaded.value());
            require(bytes <= max_type_server_stream_bytes - server_bytes,
                    "Resolved PDB type-server stream data exceeds the aggregate import budget", ErrorCode::resource_limit);
            server_bytes += bytes;
            auto types = parse_pdb_types(loaded.value(), stop);
            if (!types) return types.error();
            const auto assigned_index = static_cast<std::uint8_t>(next_namespace++);
            identities.emplace(identity, assigned_index);
            identity_paths.emplace(assigned_index, request.path);
            positions.emplace(assigned_index, result.namespaces.size());
            result.namespaces.push_back({std::move(request), std::move(loaded.value()),
                                         std::move(types.value()), assigned_index, {{std::uint8_t{0}, assigned_index}}});
            result.root_namespace_map.emplace_back(entry.index, assigned_index);
        }

        constexpr std::size_t max_depth = 32;
        std::vector<std::size_t> depths(result.namespaces.size(), 1);
        for (std::size_t cursor = 0; cursor < result.namespaces.size(); ++cursor) {
            check_cancel(stop);
            require(depths[cursor] <= max_depth,
                    "Nested DBI PDB type-server maps exceed depth limit", ErrorCode::resource_limit);
            const auto current_index = result.namespaces[cursor].index;
            auto nested_map = parse_pdb_type_server_map(result.namespaces[cursor].database, stop);
            if (!nested_map) return nested_map.error();
            std::vector<std::pair<std::uint8_t, std::uint8_t>> selector_map{{std::uint8_t{0}, current_index}};
            for (const auto &entry : nested_map.value()) {
                check_cancel(stop);
                if (entry.index == 0) continue;
                require(!entry.name.empty() || !entry.path.empty(),
                        "Nested PDB type-server map entry has no identity path");
                PdbTypeServerRequest request;
                request.signature = entry.signature;
                request.age = entry.age;
                request.path = entry.name.empty() ? entry.path : entry.name;
                const auto identity = std::pair{entry.signature, entry.age};
                auto known = identities.find(identity);
                std::uint8_t target_index = 0;
                if (known != identities.end()) {
                    target_index = known->second;
                    const auto path = identity_paths.find(target_index);
                    if (target_index != 0 && path != identity_paths.end())
                        require(path->second == request.path,
                                "Conflicting paths for one nested PDB type-server identity", ErrorCode::integrity);
                } else {
                    require(result.namespaces.size() < max_servers,
                            "PDB type-server count exceeds caller limit", ErrorCode::resource_limit);
                    require(next_namespace <= 255,
                            "Nested PDB type-server selector overflow", ErrorCode::resource_limit);
                    auto loaded = resolver(request);
                    if (!loaded) return loaded.error();
                    require(loaded.value().info.signature == entry.signature && loaded.value().info.age == entry.age,
                            "Resolved nested PDB type-server signature+age does not match the DBI map", ErrorCode::integrity);
                    const auto bytes = type_server_stream_bytes(loaded.value());
                    require(bytes <= max_type_server_stream_bytes - server_bytes,
                            "Resolved PDB type-server stream data exceeds the aggregate import budget", ErrorCode::resource_limit);
                    server_bytes += bytes;
                    auto types = parse_pdb_types(loaded.value(), stop);
                    if (!types) return types.error();
                    target_index = static_cast<std::uint8_t>(next_namespace++);
                    identities.emplace(identity, target_index);
                    identity_paths.emplace(target_index, request.path);
                    positions.emplace(target_index, result.namespaces.size());
                    result.namespaces.push_back({std::move(request), std::move(loaded.value()),
                                                 std::move(types.value()), target_index, {{std::uint8_t{0}, target_index}}});
                    depths.push_back(depths[cursor] + 1);
                }
                selector_map.emplace_back(entry.index, target_index);
            }
            const auto position = positions.find(current_index);
            require(position != positions.end(), "PDB type-server namespace index was lost", ErrorCode::integrity);
            result.namespaces[position->second].namespace_map = std::move(selector_map);
        }
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB type-server data exceeds available memory"}; }
}

Result<PdbTypeGraph> resolve_pdb_type_graph(const PdbTypeStream &stream, std::stop_token stop) {
    try {
        require(stream.records.size() <= max_type_records, "PDB TPI graph exceeds record limit", ErrorCode::resource_limit);
        require(stream.type_index_end >= stream.type_index_begin &&
                stream.type_index_end - stream.type_index_begin == stream.records.size(),
                "PDB TPI graph index range does not match records");
        PdbTypeGraph graph;
        graph.nodes.reserve(stream.records.size());
        std::map<std::uint32_t, std::size_t> by_index;
        for (std::size_t i = 0; i < stream.records.size(); ++i) {
            check_cancel(stop);
            const auto &record = stream.records[i];
            require(record.index == stream.type_index_begin + i,
                    "PDB TPI graph records are not in index order");
            by_index.emplace(record.index, i);
            graph.nodes.push_back({record, record.index, {}, 0});
        }
        // A CodeView unique name is the strongest identity for ODR-qualified
        // aggregates. Keep displayed-name matching only for records lacking it.
        using DefinitionKey = std::pair<CodeViewTypeKind, std::string>;
        const auto definition_key = [](const CodeViewTypeRecord &record) -> DefinitionKey {
            if (!record.unique_name.empty()) return {record.kind, std::string("U\0", 2) + record.unique_name};
            return {record.kind, std::string("N\0", 2) + record.name};
        };
        std::map<DefinitionKey, std::uint32_t> definitions;
        std::set<DefinitionKey> ambiguous_definitions;
        for (const auto &node : graph.nodes) {
            if (!node.record.name.empty() && !node.record.forward_declaration &&
                node.record.kind != CodeViewTypeKind::field_list && node.record.kind != CodeViewTypeKind::unsupported) {
                const auto key = definition_key(node.record);
                if (!definitions.emplace(key, node.record.index).second)
                    ambiguous_definitions.insert(key);
            }
        }
        for (auto &node : graph.nodes) {
            if (!node.record.forward_declaration || node.record.name.empty()) continue;
            const auto key = definition_key(node.record);
            const auto definition = definitions.find(key);
            if (definition != definitions.end() && !ambiguous_definitions.contains(key))
                node.canonical_index = definition->second;
        }
        const auto add_reference = [&](std::uint32_t source, std::uint32_t target, PdbTypeReferenceKind kind) {
            require(graph.references.size() < 4'000'000, "PDB TPI reference graph exceeds limit", ErrorCode::resource_limit);
            const auto target_namespace = static_cast<std::uint8_t>(target >> 24);
            const auto target_index = target & 0x00ffffffu;
            const bool primitive = target_namespace == 0 && target_index < 0x1000;
            const bool resolved = primitive || (target_namespace == 0 && by_index.contains(target_index));
            graph.references.push_back({source, target_index, kind, primitive, resolved, 0, target_namespace});
        };
        std::size_t expanded_count = 0;
        for (auto &node : graph.nodes) {
            check_cancel(stop);
            const auto &record = node.record;
            switch (record.kind) {
            case CodeViewTypeKind::pointer:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::pointee); break;
            case CodeViewTypeKind::array:
            case CodeViewTypeKind::strided_array:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::array_element);
                add_reference(record.index, record.underlying_type, PdbTypeReferenceKind::array_index); break;
            case CodeViewTypeKind::vector:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::vector_element); break;
            case CodeViewTypeKind::enumeration:
                add_reference(record.index, record.underlying_type, PdbTypeReferenceKind::enum_underlying);
                add_reference(record.index, record.field_list, PdbTypeReferenceKind::field_list); break;
            case CodeViewTypeKind::typedef_type:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::typedef_target); break;
            case CodeViewTypeKind::modifier:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::qualifier_base); break;
            case CodeViewTypeKind::bitfield:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::bitfield_underlying); break;
            case CodeViewTypeKind::procedure:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::function_result);
                add_reference(record.index, record.field_list, PdbTypeReferenceKind::function_argument_list);
                break;
            case CodeViewTypeKind::member_function:
                add_reference(record.index, record.referenced_type, PdbTypeReferenceKind::function_result);
                add_reference(record.index, record.member_class_type, PdbTypeReferenceKind::member_function_class);
                if (record.member_this_type)
                    add_reference(record.index, record.member_this_type, PdbTypeReferenceKind::member_function_this);
                add_reference(record.index, record.field_list, PdbTypeReferenceKind::function_argument_list);
                break;
            case CodeViewTypeKind::argument_list:
                for (const auto &argument : record.fields)
                    add_reference(record.index, argument.type, PdbTypeReferenceKind::argument_type);
                break;
            case CodeViewTypeKind::structure: case CodeViewTypeKind::class_type: case CodeViewTypeKind::union_type:
                if (!record.forward_declaration && record.field_list)
                    add_reference(record.index, record.field_list, PdbTypeReferenceKind::field_list);
                if (!record.forward_declaration && record.derivation_list)
                    add_reference(record.index, record.derivation_list, PdbTypeReferenceKind::class_derivation_list);
                if (!record.forward_declaration && record.vtable_shape)
                    add_reference(record.index, record.vtable_shape, PdbTypeReferenceKind::class_vtable_shape);
                break;
            case CodeViewTypeKind::vftable:
                if (record.vftable_complete_class_type)
                    add_reference(record.index, record.vftable_complete_class_type,
                                  PdbTypeReferenceKind::vftable_complete_class);
                if (record.vftable_overridden_type)
                    add_reference(record.index, record.vftable_overridden_type,
                                  PdbTypeReferenceKind::vftable_overridden_table);
                break;
            default: break;
            }
            if (record.kind == CodeViewTypeKind::field_list) {
                for (const auto &field : record.fields)
                    if (field.leaf == 0x150d || field.leaf == 0x150e)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::member);
                    else if (field.leaf == 0x1400 || field.leaf == 0x151a)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::base_class);
                    else if (field.leaf == 0x1401 || field.leaf == 0x1402) {
                        add_reference(record.index, field.type, PdbTypeReferenceKind::virtual_base_class);
                        add_reference(record.index, field.auxiliary_type, PdbTypeReferenceKind::virtual_base_pointer_type);
                    }
                    else if (field.leaf == 0x1510)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::nested_type);
                    else if (field.leaf == 0x1512)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::nested_type);
                    else if (field.leaf == 0x140a)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::friend_class);
                    else if (field.leaf == 0x150c)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::friend_function);
                    else if (field.leaf == 0x150f)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::method_list);
                    else if (field.leaf == 0x1511)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::method_type);
                    else if (field.leaf == 0x1409)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::vftable_pointer_type);
                    else if (field.leaf == 0x140c)
                        add_reference(record.index, field.type, PdbTypeReferenceKind::vftable_pointer_type);
                for (const auto continuation : record.field_list_continuations)
                    add_reference(record.index, continuation, PdbTypeReferenceKind::field_list_continuation);
            }
            if (record.kind == CodeViewTypeKind::method_list)
                for (const auto &method : record.fields)
                    add_reference(record.index, method.type, PdbTypeReferenceKind::method_type);
            if ((record.kind != CodeViewTypeKind::structure && record.kind != CodeViewTypeKind::class_type && record.kind != CodeViewTypeKind::union_type &&
                 record.kind != CodeViewTypeKind::enumeration) || record.forward_declaration || !record.field_list)
                continue;
            std::vector<std::uint32_t> pending{record.field_list};
            std::map<std::uint32_t, bool> seen;
            while (!pending.empty()) {
                check_cancel(stop);
                const auto field_index = pending.back(); pending.pop_back();
                if (seen.contains(field_index)) continue; // Cyclic LF_INDEX chains terminate here.
                seen.emplace(field_index, true);
                const auto found = by_index.find(field_index);
                if (found == by_index.end()) continue;
                const auto &field_list = graph.nodes[found->second].record;
                if (field_list.kind != CodeViewTypeKind::field_list) continue;
                for (const auto &field : field_list.fields) {
                    require(expanded_count < 2'000'000, "Expanded PDB field graph exceeds limit", ErrorCode::resource_limit);
                    ++expanded_count;
                    node.expanded_fields.push_back(field);
                }
                for (auto it = field_list.field_list_continuations.rbegin(); it != field_list.field_list_continuations.rend(); ++it)
                    pending.push_back(*it);
            }
        }
        return graph;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB TPI graph exceeds available memory"}; }
}

Result<PdbTypeGraph> resolve_pdb_type_graph(const PdbTypeStream &stream,
                                            const PdbTypeServerSet &servers,
                                            std::stop_token stop) {
    try {
        auto root = resolve_pdb_type_graph(stream, stop);
        if (!root) return root.error();
        PdbTypeGraph graph = std::move(root.value());
        const auto selector_table = [](const std::vector<std::pair<std::uint8_t, std::uint8_t>> &mapping) {
            std::array<int, 256> table{};
            table.fill(-1);
            for (const auto &[local, global] : mapping) table[local] = global;
            return table;
        };
        const auto remap_node = [&](PdbTypeGraphNode &node, const std::array<int, 256> &mapping) {
            std::size_t visited = 0;
            const auto remap_index = [&](std::uint32_t &index) {
                if ((visited++ & 0x3ffu) == 0) check_cancel(stop);
                const auto local = static_cast<std::uint8_t>(index >> 24);
                if (local == 0) return; // Selector zero means the source TPI.
                if (mapping[local] < 0)
                    index = 0xffffffffu; // Outside the bounded TPI index domain; importer fails closed.
                else
                    index = (std::uint32_t{static_cast<std::uint8_t>(mapping[local])} << 24) |
                            (index & 0x00ffffffu);
            };
            remap_index(node.record.referenced_type);
            remap_index(node.record.field_list);
            remap_index(node.record.derivation_list);
            remap_index(node.record.vtable_shape);
            remap_index(node.record.underlying_type);
            remap_index(node.record.member_class_type);
            remap_index(node.record.member_this_type);
            remap_index(node.record.vftable_complete_class_type);
            remap_index(node.record.vftable_overridden_type);
            for (auto &field : node.record.fields) { remap_index(field.type); remap_index(field.auxiliary_type); }
            for (auto &continuation : node.record.field_list_continuations) remap_index(continuation);
            for (auto &field : node.expanded_fields) { remap_index(field.type); remap_index(field.auxiliary_type); }
        };
        if (!servers.root_namespace_map.empty()) {
            const auto mapping = selector_table(servers.root_namespace_map);
            for (auto &reference : graph.references) {
                check_cancel(stop);
                const auto mapped = mapping[reference.target_namespace];
                if (mapped < 0)
                    reference.target_namespace_mapped = false;
                else
                    reference.target_namespace = static_cast<std::uint8_t>(mapped);
            }
            for (auto &node : graph.nodes) remap_node(node, mapping);
        }
        std::set<std::uint8_t> namespace_ids{0};
        std::size_t total_nodes = graph.nodes.size();
        for (const auto &server : servers.namespaces) {
            check_cancel(stop);
            require(server.index != 0 && namespace_ids.insert(server.index).second,
                    "PDB type-server namespace index is invalid or duplicated");
            require(server.types.records.size() <= max_type_records - total_nodes,
                    "Combined PDB TPI graph exceeds record limit", ErrorCode::resource_limit);
            total_nodes += server.types.records.size();
            auto server_graph = resolve_pdb_type_graph(server.types, stop);
            if (!server_graph) return server_graph.error();
            const auto mapping = selector_table(server.namespace_map);
            for (auto &node : server_graph.value().nodes)
            {
                remap_node(node, mapping);
                node.name_space = server.index;
            }
            for (auto &reference : server_graph.value().references) {
                reference.source_namespace = server.index;
                const auto local_namespace = reference.target_namespace;
                const auto mapped = mapping[local_namespace];
                if (mapped < 0)
                    reference.target_namespace_mapped = false;
                else
                    reference.target_namespace = static_cast<std::uint8_t>(mapped);
            }
            require(server_graph.value().references.size() <= 4'000'000 &&
                    graph.references.size() <= 4'000'000 - server_graph.value().references.size(),
                    "Combined PDB TPI reference graph exceeds limit", ErrorCode::resource_limit);
            graph.nodes.insert(graph.nodes.end(),
                               std::make_move_iterator(server_graph.value().nodes.begin()),
                               std::make_move_iterator(server_graph.value().nodes.end()));
            graph.references.insert(graph.references.end(),
                                    std::make_move_iterator(server_graph.value().references.begin()),
                                    std::make_move_iterator(server_graph.value().references.end()));
        }
        std::set<std::pair<std::uint8_t, std::uint32_t>> indexes;
        for (const auto &node : graph.nodes)
            require(indexes.emplace(node.name_space, node.record.index).second,
                    "Combined PDB TPI graph contains duplicate namespaced indices");
        for (auto &reference : graph.references) {
            check_cancel(stop);
            if (reference.primitive) {
                reference.resolved = true;
                continue;
            }
            reference.resolved = reference.target_namespace_mapped &&
                indexes.contains({reference.target_namespace, reference.target_index});
        }
        return graph;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Combined PDB TPI graph exceeds available memory"}; }
}

Result<PdbSymbolTable> parse_pdb_symbols(const PdbDatabase &database, std::stop_token stop) {
    try {
        require(database.streams.size() > 3 && database.streams[3].has_value(),
                "PDB DBI stream is absent", ErrorCode::unsupported);
        const auto dbi = std::span<const std::byte>(*database.streams[3]);
        require(dbi.size() >= 64, "Truncated PDB DBI header");
        auto r16 = [](std::span<const std::byte> b, std::size_t at) -> std::uint16_t {
            require(at <= b.size() && 2 <= b.size() - at, "Truncated PDB DBI field");
            return static_cast<std::uint16_t>(std::to_integer<unsigned>(b[at]) |
                (std::to_integer<unsigned>(b[at + 1]) << 8));
        };
        auto r32 = [](std::span<const std::byte> b, std::size_t at) -> std::uint32_t {
            require(at <= b.size() && 4 <= b.size() - at, "Truncated PDB DBI field");
            return u32(b, at);
        };
        const auto module_bytes = r32(dbi, 24);
        const auto contrib_bytes = r32(dbi, 28);
        const auto section_map_bytes = r32(dbi, 32);
        const auto source_bytes = r32(dbi, 36);
        const auto type_server_bytes = r32(dbi, 40);
        const auto optional_bytes = r32(dbi, 48);
        const auto ec_bytes = r32(dbi, 52);
        const auto symbol_record_stream = r16(dbi, 20);
        std::uint64_t expected = 64;
        for (auto n : {module_bytes, contrib_bytes, section_map_bytes, source_bytes,
                       type_server_bytes, optional_bytes, ec_bytes}) {
            require(n <= 64ull * 1024 * 1024 && expected <= dbi.size() && n <= dbi.size() - expected,
                    "PDB DBI substream exceeds its bounds", ErrorCode::resource_limit);
            expected += n;
        }
        require(expected == dbi.size(), "PDB DBI substream sizes do not match stream extent");
        require(module_bytes <= 32ull * 1024 * 1024, "PDB module list exceeds inspection limit", ErrorCode::resource_limit);

        struct Module { std::uint16_t index, stream; std::uint32_t symbols; std::string name, object; };
        std::vector<Module> modules;
        const auto module_end = std::size_t{64} + module_bytes;
        std::size_t pos = 64;
        auto cstring = [&](std::span<const std::byte> b, std::size_t &at, std::size_t limit) {
            std::string out;
            while (at < limit && b[at] != std::byte{0}) {
                require(out.size() < 32768, "PDB module path exceeds limit", ErrorCode::resource_limit);
                out.push_back(static_cast<char>(std::to_integer<unsigned char>(b[at++])));
            }
            require(at < limit, "Unterminated PDB module path");
            ++at;
            return out;
        };
        while (pos < module_end) {
            check_cancel(stop);
            require(64 <= module_end - pos, "Truncated PDB DBI module record");
            const auto stream = r16(dbi, pos + 34);
            const auto symbol_bytes = r32(dbi, pos + 36);
            auto at = pos + 64;
            auto name = cstring(dbi, at, module_end);
            auto object = cstring(dbi, at, module_end);
            pos = (at + 3u) & ~std::size_t{3};
            require(pos <= module_end, "PDB DBI module padding exceeds substream");
            modules.push_back({static_cast<std::uint16_t>(modules.size()), stream, symbol_bytes,
                               std::move(name), std::move(object)});
            require(modules.size() <= 65535, "PDB module count exceeds limit", ErrorCode::resource_limit);
        }
        PdbSymbolTable result;
        // CodeView symbol references use the byte offset in the module stream,
        // including its four-byte signature. Keep an index to the exact
        // parsed record so global references never resolve by name alone.
        std::map<std::uint64_t, std::size_t> module_symbol_offsets;
        const auto module_symbol_key = [](std::uint16_t module, std::uint32_t offset) {
            return (static_cast<std::uint64_t>(module) << 32) | offset;
        };
        constexpr std::uint16_t S_LDATA32 = 0x110c, S_GDATA32 = 0x110d;
        constexpr std::uint16_t S_LPROC32 = 0x110f, S_GPROC32 = 0x1110;
        constexpr std::uint16_t S_LPROC32_ID = 0x1146, S_GPROC32_ID = 0x1147;
        constexpr std::uint16_t S_END = 0x0006, S_PROC_ID_END = 0x114f;
        constexpr std::uint16_t S_BLOCK32 = 0x1103, S_FRAMEPROC = 0x1012;
        constexpr std::uint16_t S_INLINESITE = 0x114d, S_INLINESITE_END = 0x114e;
        for (const auto &module : modules) {
            check_cancel(stop);
            if (module.stream == 0xffff || module.symbols == 0) continue;
            require(module.stream < database.streams.size() && database.streams[module.stream].has_value(),
                    "PDB module refers to an absent symbol stream");
            const auto stream = std::span<const std::byte>(*database.streams[module.stream]);
            require(stream.size() >= 4 && module.symbols >= 4 && module.symbols <= stream.size(),
                    "PDB module symbol extent exceeds stream");
            const auto symbols = stream.subspan(4, module.symbols - 4);
            std::size_t at = 0;
            std::optional<std::size_t> active_procedure;
            std::uint32_t procedure_scope_depth = 0;
            bool procedure_has_frame = false;
            while (at < symbols.size()) {
                check_cancel(stop);
                require(symbols.size() - at >= 4, "Truncated CodeView module symbol record");
                const auto record_length = r16(symbols, at);
                const auto record_kind = r16(symbols, at + 2);
                if (record_length < 2 || record_length > symbols.size() - at - 2)
                    throw Failure{{ErrorCode::malformed, "Invalid CodeView module symbol record length at offset " +
                        std::to_string(at) + " (length " + std::to_string(record_length) + ", remaining " +
                        std::to_string(symbols.size() - at) + ", module " + std::to_string(module.index) + ")"}};
                const auto end = at + 2 + record_length;
                auto payload = at + 4;
                PdbSymbol symbol;
                bool supported = false;
                if (record_kind == S_LDATA32 || record_kind == S_GDATA32) {
                    require(end - payload >= 10, "Truncated CodeView data symbol");
                    symbol.type_index = r32(symbols, payload); payload += 4;
                    symbol.section_offset = r32(symbols, payload); payload += 4;
                    symbol.section = r16(symbols, payload); payload += 2;
                    symbol.kind = PdbSymbolKind::data;
                    supported = true;
                } else if (record_kind == S_LPROC32 || record_kind == S_GPROC32 ||
                           record_kind == S_LPROC32_ID || record_kind == S_GPROC32_ID) {
                    require(end - payload >= 35, "Truncated CodeView procedure symbol");
                    payload += 12; // Parent, end, next.
                    symbol.size = r32(symbols, payload); payload += 4;
                    payload += 8; // Debug start/end offsets.
                    symbol.type_index = r32(symbols, payload); payload += 4;
                    symbol.type_index_is_id = record_kind == S_LPROC32_ID || record_kind == S_GPROC32_ID;
                    symbol.section_offset = r32(symbols, payload); payload += 4;
                    symbol.section = r16(symbols, payload); payload += 2;
                    payload += 1; // Procedure flags.
                    symbol.kind = PdbSymbolKind::procedure;
                    supported = true;
                }
                if (supported) {
                    symbol.name = cstring(symbols, payload, end);
                    symbol.module_name = module.name;
                    symbol.object_name = module.object;
                    symbol.module_index = module.index;
                    symbol.record_kind = record_kind;
                    symbol.record_offset = static_cast<std::uint32_t>(at);
                    result.symbols.push_back(std::move(symbol));
                    require(at <= std::numeric_limits<std::uint32_t>::max() - 4,
                            "PDB module symbol offset exceeds inspection limit", ErrorCode::resource_limit);
                    module_symbol_offsets.emplace(module_symbol_key(module.index,
                        static_cast<std::uint32_t>(at + 4)), result.symbols.size() - 1);
                    if (record_kind == S_LPROC32 || record_kind == S_GPROC32 ||
                        record_kind == S_LPROC32_ID || record_kind == S_GPROC32_ID) {
                        active_procedure = result.symbols.size() - 1;
                        procedure_scope_depth = 1;
                        procedure_has_frame = false;
                    }
                    require(result.symbols.size() <= 2'000'000,
                            "PDB symbol count exceeds inspection limit", ErrorCode::resource_limit);
                } else if (record_kind == S_FRAMEPROC) {
                    require(end - payload >= 26 && end - payload <= 29, "Invalid CodeView S_FRAMEPROC size");
                    if (active_procedure && !procedure_has_frame) {
                        auto &procedure = result.symbols[*active_procedure];
                        procedure.frame_size = r32(symbols, payload); payload += 4;
                        procedure.frame_padding_size = r32(symbols, payload); payload += 4;
                        procedure.frame_padding_offset = r32(symbols, payload); payload += 4;
                        procedure.callee_saved_register_bytes = r32(symbols, payload); payload += 4;
                        procedure.exception_handler_offset = r32(symbols, payload); payload += 4;
                        procedure.exception_handler_section = r16(symbols, payload); payload += 2;
                        procedure.frame_flags = r32(symbols, payload); payload += 4;
                        procedure.has_frame_data = true;
                        procedure_has_frame = true;
                    } else payload += 26;
                    const auto padding = end - payload;
                    bool zero_padding = true;
                    bool leaf_padding = true;
                    for (std::size_t i = 0; i < padding; ++i) {
                        const auto actual = std::to_integer<unsigned>(symbols[payload + i]);
                        zero_padding = zero_padding && actual == 0;
                        leaf_padding = leaf_padding && actual == 0xf0u + padding - i;
                    }
                    require(zero_padding || leaf_padding, "Invalid CodeView S_FRAMEPROC padding");
                } else if (active_procedure && (record_kind == S_BLOCK32 || record_kind == S_INLINESITE)) {
                    ++procedure_scope_depth;
                } else if (active_procedure && (record_kind == S_END || record_kind == S_PROC_ID_END ||
                                                record_kind == S_INLINESITE_END)) {
                    if (procedure_scope_depth)
                        --procedure_scope_depth;
                    if (!procedure_scope_depth) {
                        active_procedure.reset();
                        procedure_has_frame = false;
                    }
                } else if (record_kind == S_LDATA32 || record_kind == S_GDATA32) {
                    // Data symbols cannot inherit a preceding procedure frame.
                    active_procedure.reset();
                    procedure_scope_depth = 0;
                    procedure_has_frame = false;
                }
                at = end;
            }
        }
        if (symbol_record_stream != 0xffff) {
            require(symbol_record_stream < database.streams.size() &&
                    database.streams[symbol_record_stream].has_value(),
                    "PDB DBI refers to an absent symbol-record stream");
            const auto records = std::span<const std::byte>(*database.streams[symbol_record_stream]);
            constexpr std::uint16_t S_PUB32 = 0x110e, S_GPROC32_GLOBAL_RECORD = 0x1110,
                                    S_GPROC32_ID_GLOBAL_RECORD = 0x1147;
            constexpr std::uint16_t S_PROCREF = 0x1125, S_DATAREF = 0x1126, S_LPROCREF = 0x1127;
            std::size_t at = 0;
            while (at < records.size()) {
                check_cancel(stop);
                require(records.size() - at >= 4, "Truncated CodeView global symbol record");
                const auto record_length = r16(records, at);
                const auto record_kind = r16(records, at + 2);
                require(record_length >= 2 && record_length <= records.size() - at - 2,
                        "Invalid CodeView global symbol record length");
                const auto end = at + 2 + record_length;
                auto payload = at + 4;
                PdbSymbol symbol;
                bool supported = false;
                bool is_reference = false;
                if (record_kind == S_PUB32) {
                    require(end - payload >= 10, "Truncated CodeView public symbol");
                    const auto flags = r32(records, payload); payload += 4;
                    symbol.section_offset = r32(records, payload); payload += 4;
                    symbol.section = r16(records, payload); payload += 2;
                    symbol.kind = (flags & 1) ? PdbSymbolKind::procedure : PdbSymbolKind::data;
                    symbol.public_symbol = true;
                    supported = true;
                } else if (record_kind == S_GDATA32) {
                    require(end - payload >= 10, "Truncated CodeView global data symbol");
                    payload += 4; // Type index.
                    symbol.section_offset = r32(records, payload); payload += 4;
                    symbol.section = r16(records, payload); payload += 2;
                    supported = true;
                } else if (record_kind == S_GPROC32_GLOBAL_RECORD ||
                           record_kind == S_GPROC32_ID_GLOBAL_RECORD) {
                    require(end - payload >= 35, "Truncated CodeView global procedure symbol");
                    payload += 12; // Parent, end, next.
                    symbol.size = r32(records, payload); payload += 4;
                    payload += 8; // Debug start/end offsets.
                    symbol.type_index = r32(records, payload); payload += 4;
                    symbol.type_index_is_id = record_kind == S_GPROC32_ID_GLOBAL_RECORD;
                    symbol.section_offset = r32(records, payload); payload += 4;
                    symbol.section = r16(records, payload); payload += 2;
                    payload += 1; // Procedure flags.
                    symbol.kind = PdbSymbolKind::procedure;
                    supported = true;
                } else if (record_kind == S_PROCREF || record_kind == S_LPROCREF || record_kind == S_DATAREF) {
                    require(end - payload >= 10, "Truncated CodeView symbol reference");
                    payload += 4; // Name checksum.
                    const auto module_offset = r32(records, payload); payload += 4;
                    const auto one_based_module = r16(records, payload); payload += 2;
                    require(one_based_module != 0 && one_based_module <= modules.size(),
                            "CodeView symbol reference has an invalid module index");
                    const auto target = module_symbol_offsets.find(module_symbol_key(
                        static_cast<std::uint16_t>(one_based_module - 1), module_offset));
                    require(target != module_symbol_offsets.end(),
                            "CodeView symbol reference does not identify a parsed module symbol");
                    const auto &resolved = result.symbols[target->second];
                    const bool wants_procedure = record_kind != S_DATAREF;
                    require((resolved.kind == PdbSymbolKind::procedure) == wants_procedure,
                            "CodeView symbol reference kind disagrees with its target");
                    symbol = resolved;
                    symbol.source = PdbSymbolSource::global_stream;
                    symbol.reference_record_kind = record_kind;
                    is_reference = true;
                    require(at <= std::numeric_limits<std::uint32_t>::max(),
                            "PDB global symbol offset exceeds inspection limit", ErrorCode::resource_limit);
                    symbol.reference_record_offset = static_cast<std::uint32_t>(at);
                    supported = true;
                }
                if (supported) {
                    symbol.name = cstring(records, payload, end);
                    symbol.source = PdbSymbolSource::global_stream;
                    if (!is_reference) symbol.module_index = 0xffff;
                    if (record_kind != S_PROCREF && record_kind != S_LPROCREF && record_kind != S_DATAREF)
                        symbol.record_kind = record_kind;
                    require(at <= std::numeric_limits<std::uint32_t>::max(),
                            "PDB global symbol offset exceeds inspection limit", ErrorCode::resource_limit);
                    if (!is_reference) symbol.record_offset = static_cast<std::uint32_t>(at);
                    result.symbols.push_back(std::move(symbol));
                    require(result.symbols.size() <= 2'000'000,
                            "PDB symbol count exceeds inspection limit", ErrorCode::resource_limit);
                }
                at = end;
            }
        }
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB symbol data exceeds available memory"}; }
}

Result<PdbLocalTable> parse_pdb_locals(const PdbDatabase &database, std::stop_token stop) {
    try {
        require(database.streams.size() > 3 && database.streams[3].has_value(),
                "PDB DBI stream is absent", ErrorCode::unsupported);
        const auto dbi = std::span<const std::byte>(*database.streams[3]);
        require(dbi.size() >= 64, "Truncated PDB DBI header");
        auto r16 = [](std::span<const std::byte> b, std::size_t at) -> std::uint16_t {
            require(at <= b.size() && 2 <= b.size() - at, "Truncated PDB DBI field");
            return static_cast<std::uint16_t>(std::to_integer<unsigned>(b[at]) |
                (std::to_integer<unsigned>(b[at + 1]) << 8));
        };
        auto r32 = [](std::span<const std::byte> b, std::size_t at) -> std::uint32_t { return u32(b, at); };
        const auto module_bytes = r32(dbi, 24);
        std::uint64_t expected = 64;
        for (const auto offset : {28u, 32u, 36u, 40u, 48u, 52u}) {
            const auto size = r32(dbi, offset);
            require(size <= 64ull * 1024 * 1024 && expected <= dbi.size() && size <= dbi.size() - expected,
                    "PDB DBI substream exceeds its bounds", ErrorCode::resource_limit);
            expected += size;
        }
        require(expected + module_bytes == dbi.size() && expected + module_bytes >= expected,
                "PDB module list exceeds DBI stream", ErrorCode::resource_limit);
        require(module_bytes <= 32ull * 1024 * 1024, "PDB module list exceeds inspection limit", ErrorCode::resource_limit);
        struct Module { std::uint16_t index, stream; std::uint32_t symbols; std::string name, object; };
        std::vector<Module> modules;
        const auto module_end = std::size_t{64} + module_bytes;
        std::size_t pos = 64;
        auto cstring = [&](std::span<const std::byte> b, std::size_t &at, std::size_t limit) {
            std::string out;
            while (at < limit && b[at] != std::byte{0}) {
                require(out.size() < 32768, "PDB module path exceeds limit", ErrorCode::resource_limit);
                out.push_back(static_cast<char>(std::to_integer<unsigned char>(b[at++])));
            }
            require(at < limit, "Unterminated PDB module path"); ++at; return out;
        };
        while (pos < module_end) {
            check_cancel(stop);
            require(64 <= module_end - pos, "Truncated PDB DBI module record");
            const auto stream = r16(dbi, pos + 34);
            const auto symbols = r32(dbi, pos + 36);
            auto at = pos + 64;
            auto name = cstring(dbi, at, module_end), object = cstring(dbi, at, module_end);
            pos = (at + 3u) & ~std::size_t{3};
            require(pos <= module_end, "PDB DBI module padding exceeds substream");
            modules.push_back({static_cast<std::uint16_t>(modules.size()), stream, symbols,
                               std::move(name), std::move(object)});
            require(modules.size() <= 65535, "PDB module count exceeds limit", ErrorCode::resource_limit);
        }

        constexpr std::uint16_t S_END = 0x0006, S_PROC_ID_END = 0x114f, S_BLOCK32 = 0x1103;
        constexpr std::uint16_t S_BPREL32 = 0x0100, S_LPROC32 = 0x110f, S_GPROC32 = 0x1110;
        constexpr std::uint16_t S_LPROC32_ID = 0x1146, S_GPROC32_ID = 0x1147;
        constexpr std::uint16_t S_REGREL32 = 0x1111, S_LOCAL = 0x113e;
        constexpr std::uint16_t S_DEFRANGE_REGISTER = 0x1141, S_DEFRANGE_FRAMEPOINTER_REL = 0x1142;
        constexpr std::uint16_t S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144;
        constexpr std::uint16_t S_DEFRANGE_SUBFIELD_REGISTER = 0x1143, S_DEFRANGE_REGISTER_REL = 0x1145;
        constexpr std::uint16_t S_DEFRANGE_REGISTER_REL_INDIR = 0x1177;
        constexpr std::uint16_t S_INLINESITE = 0x114d, S_INLINESITE_END = 0x114e;
        constexpr std::uint16_t S_INLINESITE2 = 0x115d;
        constexpr std::uint16_t local_parameter_flag = 0x0001;
        PdbLocalTable result;
        std::size_t inline_storage = 0, inline_range_count = 0;
        for (const auto &module : modules) {
            check_cancel(stop);
            if (module.stream == 0xffff || module.symbols == 0) continue;
            require(module.stream < database.streams.size() && database.streams[module.stream].has_value(),
                    "PDB module refers to an absent symbol stream");
            const auto stream = std::span<const std::byte>(*database.streams[module.stream]);
            require(stream.size() >= 4 && module.symbols >= 4 && module.symbols <= stream.size(),
                    "PDB module symbol extent exceeds stream");
            const auto symbols = stream.subspan(4, module.symbols - 4);
            std::size_t at = 0;
            bool in_procedure = false;
            std::uint32_t scope_depth = 0;
            std::optional<std::size_t> active_local;
            struct InlineScope { std::uint32_t record_offset = 0, inlinee_id = 0; };
            std::vector<InlineScope> inline_scopes;
            std::vector<bool> child_scope_is_inline;
            struct LexicalScope { std::uint16_t section = 0; std::uint32_t offset = 0, size = 0; };
            std::vector<LexicalScope> lexical_scopes;
            PdbLocalSymbol owner;
            auto inherit_inline_scope = [&](PdbLocalSymbol &local) {
                if (inline_scopes.empty()) return;
                local.inline_site_record_offset = inline_scopes.back().record_offset;
                local.inlinee_id = inline_scopes.back().inlinee_id;
            };
            auto inherit_lexical_scope = [&](PdbLocalSymbol &local) {
                if (lexical_scopes.empty()) return;
                const auto &scope = lexical_scopes.back();
                local.has_lexical_scope = true;
                local.lexical_scope_section = scope.section;
                local.lexical_scope_offset = scope.offset;
                local.lexical_scope_size = scope.size;
            };
            while (at < symbols.size()) {
                check_cancel(stop);
                require(symbols.size() - at >= 4, "Truncated CodeView module symbol record");
                const auto record_length = r16(symbols, at), kind = r16(symbols, at + 2);
                require(record_length >= 2 && record_length <= symbols.size() - at - 2,
                        "Invalid CodeView module symbol record length");
                const auto end = at + 2 + record_length;
                std::size_t payload = at + 4;
                auto read_name = [&](std::size_t &p) { return cstring(symbols, p, end); };
                if (kind == S_GPROC32 || kind == S_LPROC32 || kind == S_GPROC32_ID || kind == S_LPROC32_ID) {
                    require(!in_procedure, "CodeView procedure starts before its predecessor ends");
                    require(end - payload >= 35, "Truncated CodeView procedure symbol");
                    owner = {};
                    payload += 12;
                    owner.procedure_size = r32(symbols, payload); payload += 4;
                    payload += 8; // Debug start/end.
                    payload += 4; // Function type index.
                    owner.procedure_section_offset = r32(symbols, payload); payload += 4;
                    owner.procedure_section = r16(symbols, payload); payload += 2;
                    payload += 1; // Procedure flags.
                    owner.procedure_name = read_name(payload);
                    owner.module_name = module.name; owner.object_name = module.object;
                    owner.module_index = module.index;
                    in_procedure = true; scope_depth = 1;
                    inline_scopes.clear();
                    child_scope_is_inline.clear();
                    lexical_scopes.clear();
                } else if (in_procedure && kind == S_LOCAL) {
                    require(end - payload >= 6, "Truncated CodeView local symbol");
                    PdbLocalSymbol local = owner;
                    inherit_inline_scope(local);
                    inherit_lexical_scope(local);
                    local.type_index = r32(symbols, payload); payload += 4;
                    const auto flags = r16(symbols, payload); payload += 2;
                    local.parameter = (flags & local_parameter_flag) != 0;
                    local.name = read_name(payload);
                    local.record_kind = kind;
                    require(at <= std::numeric_limits<std::uint32_t>::max(),
                            "PDB local symbol offset exceeds inspection limit", ErrorCode::resource_limit);
                    local.record_offset = static_cast<std::uint32_t>(at);
                    result.locals.push_back(std::move(local));
                    active_local = result.locals.size() - 1;
                } else if (in_procedure && kind == S_BPREL32) {
                    require(end - payload >= 8, "Truncated CodeView frame-relative local");
                    PdbLocalSymbol local = owner;
                    inherit_inline_scope(local);
                    inherit_lexical_scope(local);
                    local.frame_offset = static_cast<std::int32_t>(r32(symbols, payload)); payload += 4;
                    local.type_index = r32(symbols, payload); payload += 4;
                    local.location_kind = PdbLocalLocationKind::frame_relative;
                    local.name = read_name(payload);
                    local.record_kind = kind;
                    require(at <= std::numeric_limits<std::uint32_t>::max(),
                            "PDB local symbol offset exceeds inspection limit", ErrorCode::resource_limit);
                    local.record_offset = static_cast<std::uint32_t>(at);
                    result.locals.push_back(std::move(local));
                    active_local.reset();
                } else if (in_procedure && kind == S_REGREL32) {
                    require(end - payload >= 10, "Truncated CodeView register-relative local");
                    PdbLocalSymbol local = owner;
                    inherit_inline_scope(local);
                    inherit_lexical_scope(local);
                    local.frame_offset = static_cast<std::int32_t>(r32(symbols, payload)); payload += 4;
                    local.type_index = r32(symbols, payload); payload += 4;
                    local.register_id = r16(symbols, payload); payload += 2;
                    local.location_kind = PdbLocalLocationKind::register_relative;
                    local.name = read_name(payload);
                    local.record_kind = kind;
                    require(at <= std::numeric_limits<std::uint32_t>::max(),
                            "PDB local symbol offset exceeds inspection limit", ErrorCode::resource_limit);
                    local.record_offset = static_cast<std::uint32_t>(at);
                    result.locals.push_back(std::move(local));
                    active_local.reset();
                } else if (in_procedure && active_local &&
                           (kind == S_DEFRANGE_REGISTER || kind == S_DEFRANGE_FRAMEPOINTER_REL ||
                            kind == S_DEFRANGE_SUBFIELD_REGISTER ||
                            kind == S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE ||
                            kind == S_DEFRANGE_REGISTER_REL || kind == S_DEFRANGE_REGISTER_REL_INDIR)) {
                    auto &local = result.locals[*active_local];
                    PdbLocalLiveRange range;
                    std::size_t range_at = payload;
                    if (kind == S_DEFRANGE_REGISTER) {
                        require(end - payload >= 12, "Truncated CodeView register defrange");
                        range.location_kind = PdbLocalLocationKind::register_value;
                        range.register_id = r16(symbols, payload);
                        const auto flags = r16(symbols, payload + 2);
                        require((flags & 0xfffeu) == 0, "Invalid CodeView register defrange flags");
                        range.may_have_no_name = (flags & 1u) != 0;
                        range_at += 4;
                    } else if (kind == S_DEFRANGE_SUBFIELD_REGISTER) {
                        require(end - payload >= 16, "Truncated CodeView subfield-register defrange");
                        range.location_kind = PdbLocalLocationKind::register_value;
                        range.subfield_register = true;
                        range.register_id = r16(symbols, payload);
                        const auto flags = r16(symbols, payload + 2);
                        require((flags & 0xfffeu) == 0, "Invalid CodeView subfield-register flags");
                        range.may_have_no_name = (flags & 1u) != 0;
                        const auto parent = r32(symbols, payload + 4);
                        require((parent & 0xfffff000u) == 0, "Invalid CodeView subfield-register parent offset");
                        range.offset_in_parent = static_cast<std::uint16_t>(parent & 0x0fffu);
                        range_at += 8;
                    } else if (kind == S_DEFRANGE_FRAMEPOINTER_REL) {
                        require(end - payload >= 12, "Truncated CodeView frame-pointer defrange");
                        range.location_kind = PdbLocalLocationKind::frame_relative;
                        range.frame_offset = static_cast<std::int32_t>(r32(symbols, payload)); range_at += 4;
                    } else if (kind == S_DEFRANGE_REGISTER_REL) {
                        require(end - payload >= 16, "Truncated CodeView register-relative defrange");
                        range.location_kind = PdbLocalLocationKind::register_relative;
                        range.register_id = r16(symbols, payload);
                        const auto flags_and_parent = r16(symbols, payload + 2);
                        require((flags_and_parent & 0x000eu) == 0, "Invalid CodeView register-relative flags");
                        range.spilled_udt_member = (flags_and_parent & 1u) != 0;
                        range.offset_in_parent = static_cast<std::uint16_t>(flags_and_parent >> 4);
                        range.frame_offset = static_cast<std::int32_t>(r32(symbols, payload + 4)); range_at += 8;
                    } else if (kind == S_DEFRANGE_REGISTER_REL_INDIR) {
                        require(end - payload >= 20, "Truncated CodeView indirect register-relative defrange");
                        range.location_kind = PdbLocalLocationKind::register_relative;
                        range.indirect = true;
                        range.register_id = r16(symbols, payload);
                        const auto flags_and_parent = r16(symbols, payload + 2);
                        require((flags_and_parent & 0x000eu) == 0, "Invalid CodeView indirect register-relative flags");
                        range.spilled_udt_member = (flags_and_parent & 1u) != 0;
                        range.offset_in_parent = static_cast<std::uint16_t>(flags_and_parent >> 4);
                        range.frame_offset = static_cast<std::int32_t>(r32(symbols, payload + 4));
                        range.offset_in_udt = static_cast<std::int32_t>(r32(symbols, payload + 8));
                        range_at += 12;
                    } else {
                        require(end - payload == 4, "Invalid CodeView full-scope frame defrange size");
                        range.location_kind = PdbLocalLocationKind::frame_relative;
                        range.frame_offset = static_cast<std::int32_t>(r32(symbols, payload));
                        range.section = owner.procedure_section;
                        range.section_offset = owner.procedure_section_offset;
                        range.size = owner.procedure_size;
                        range_at = end;
                    }
                    if (kind != S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE) {
                        range.section_offset = r32(symbols, range_at);
                        range.section = r16(symbols, range_at + 4);
                        range.size = r16(symbols, range_at + 6);
                        range_at += 8;
                        require((end - range_at) % 4 == 0, "Invalid CodeView defrange gap list size");
                        while (range_at < end) {
                            range.gaps.push_back({r16(symbols, range_at), r16(symbols, range_at + 2)});
                            range_at += 4;
                        }
                    }
                    if (local.live_ranges.empty()) {
                        local.location_kind = range.location_kind;
                        local.frame_offset = range.frame_offset;
                        local.register_id = range.register_id;
                    }
                    local.live_ranges.push_back(std::move(range));
                } else if (in_procedure && (kind == S_INLINESITE || kind == S_INLINESITE2)) {
                    const std::size_t fixed_size = kind == S_INLINESITE2 ? 16 : 12;
                    require(end - payload >= fixed_size, "Truncated CodeView inline-site symbol");
                    const auto inlinee_id = r32(symbols, payload + 8);
                    require(inlinee_id >= 0x1000, "Invalid CodeView inlinee IPI index");
                    require(at <= std::numeric_limits<std::uint32_t>::max(),
                            "PDB inline-site record offset exceeds inspection limit", ErrorCode::resource_limit);
                    require(inline_scopes.size() < 256 && scope_depth < 512 && result.inline_sites.size() < 250'000,
                            "PDB inline-site count or nesting exceeds limit", ErrorCode::resource_limit);
                    PdbInlineSite site;
                    site.module_index = module.index; site.inlinee_id = inlinee_id;
                    site.record_offset = static_cast<std::uint32_t>(at);
                    site.procedure_section = owner.procedure_section;
                    site.procedure_offset = owner.procedure_section_offset;
                    site.procedure_size = owner.procedure_size;
                    site.procedure_name = owner.procedure_name;
                    site.depth = static_cast<std::uint32_t>(inline_scopes.size() + 1);
                    if (!inline_scopes.empty()) site.parent_record_offset = inline_scopes.back().record_offset;
                    auto annotation_at = payload + fixed_size;
                    const auto annotation_start = annotation_at;
                    auto compressed = [&]() -> std::uint32_t {
                        require(annotation_at < end, "Truncated inline binary annotation operand");
                        const auto first = std::to_integer<std::uint32_t>(symbols[annotation_at++]);
                        if (!(first & 0x80)) return first;
                        const auto extra = (first & 0xc0) == 0x80 ? 1u : 3u;
                        require((first & 0xe0) != 0xe0 && extra <= end - annotation_at,
                                "Invalid compressed inline annotation operand");
                        auto value = first & (extra == 1 ? 0x3fu : 0x1fu);
                        for (unsigned i = 0; i < extra; ++i)
                            value = (value << 8) | std::to_integer<std::uint32_t>(symbols[annotation_at++]);
                        return value;
                    };
                    auto signed_operand = [](std::uint32_t value) -> std::int64_t {
                        return (value & 1u) ? -static_cast<std::int64_t>(value >> 1) : value >> 1;
                    };
                    std::uint64_t code = 0;
                    std::int64_t line_delta = 0;
                    std::optional<std::uint32_t> file_id;
                    auto emit = [&](std::uint32_t size) {
                        if (code > site.procedure_size || size > site.procedure_size - code)
                            throw Failure{{ErrorCode::malformed, "Inline annotation range [" +
                                std::to_string(code) + ", " + std::to_string(code + size) +
                                ") exceeds procedure size " + std::to_string(site.procedure_size) +
                                " for " + site.procedure_name}};
                        if (size) {
                            require(++inline_range_count <= 1'000'000,
                                    "PDB inline range count exceeds limit", ErrorCode::resource_limit);
                            site.ranges.push_back({static_cast<std::uint32_t>(code), size, line_delta, file_id});
                        }
                        code += size;
                    };
                    while (annotation_at < end) {
                        check_cancel(stop);
                        const auto op_at = annotation_at;
                        const auto op = compressed();
                        if (op == 0) {
                            while (annotation_at < end)
                                require(symbols[annotation_at++] == std::byte{0}, "Invalid inline annotation padding");
                            break;
                        }
                        if (op == 2 || op > 13) {
                            site.unsupported_opcode = op;
                            site.annotation_offset = static_cast<std::uint32_t>(op_at - annotation_start);
                            site.ranges.clear();
                            break;
                        }
                        const auto operand = compressed();
                        switch (op) {
                        case 1: code = operand; break;
                        case 3: code += operand; break;
                        case 4: emit(operand); break;
                        case 5: file_id = operand; break;
                        case 6: line_delta += signed_operand(operand); break;
                        case 11:
                            code += operand & 15u;
                            line_delta += signed_operand(operand >> 4);
                            break;
                        case 12: code += compressed(); emit(operand); break;
                        // End-line, statement/expression, and column metadata
                        // have no effect on this slice's start-line attribution.
                        default: break;
                        }
                        if (code > site.procedure_size)
                            throw Failure{{ErrorCode::malformed, "Inline annotation offset " + std::to_string(code) +
                                " exceeds procedure size " + std::to_string(site.procedure_size) +
                                " for " + site.procedure_name + " at opcode " + std::to_string(op)}};
                    }
                    const auto storage = sizeof(PdbInlineSite) + site.procedure_name.size() +
                        site.ranges.size() * sizeof(PdbInlineRange);
                    require(storage <= 64ull * 1024 * 1024 - inline_storage,
                            "PDB inline output exceeds 64 MiB", ErrorCode::resource_limit);
                    inline_storage += storage;
                    result.inline_sites.push_back(std::move(site));
                    inline_scopes.push_back({static_cast<std::uint32_t>(at), inlinee_id});
                    child_scope_is_inline.push_back(true);
                    ++scope_depth;
                    active_local.reset();
                } else if (in_procedure && kind == S_BLOCK32) {
                    require(end - payload >= 18, "Truncated CodeView block scope");
                    require(scope_depth < 512, "PDB lexical scope nesting exceeds limit", ErrorCode::resource_limit);
                    // S_BLOCK32 stores parent/end symbol offsets, a code
                    // extent, and its section-relative start before the name.
                    lexical_scopes.push_back({r16(symbols, payload + 16),
                                              r32(symbols, payload + 12),
                                              r32(symbols, payload + 8)});
                    ++scope_depth;
                    child_scope_is_inline.push_back(false);
                    active_local.reset();
                } else if (in_procedure && kind == S_INLINESITE_END) {
                    require(!inline_scopes.empty() && scope_depth > 1 &&
                            !child_scope_is_inline.empty() && child_scope_is_inline.back(),
                            "Unmatched CodeView inline-site end");
                    inline_scopes.pop_back();
                    child_scope_is_inline.pop_back();
                    --scope_depth;
                    active_local.reset();
                } else if (in_procedure && (kind == S_END || kind == S_PROC_ID_END)) {
                    if (scope_depth > 1) {
                        require(kind == S_END && !child_scope_is_inline.empty() && !child_scope_is_inline.back() &&
                                !lexical_scopes.empty(), "CodeView scope ending does not match its owner");
                        lexical_scopes.pop_back();
                        child_scope_is_inline.pop_back();
                    }
                    if (scope_depth) --scope_depth;
                    active_local.reset();
                    if (!scope_depth) {
                        require(inline_scopes.empty(), "CodeView procedure ends with open inline-site scopes");
                        require(lexical_scopes.empty(), "CodeView procedure ends with open block scopes");
                        in_procedure = false;
                    }
                } else if (in_procedure) {
                    active_local.reset();
                }
                if (result.locals.size() > 2'000'000)
                    fail(ErrorCode::resource_limit, "PDB local symbol count exceeds inspection limit");
                at = end;
            }
            require(!in_procedure, "CodeView module ends with an open procedure scope");
        }
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB local symbol data exceeds available memory"}; }
}

Result<PdbSourceLineTable> parse_pdb_source_lines(const PdbDatabase &database, std::stop_token stop) {
    try {
        require(database.streams.size() > 3 && database.streams[3].has_value(),
                "PDB DBI stream is absent", ErrorCode::unsupported);
        const auto dbi = std::span<const std::byte>(*database.streams[3]);
        require(dbi.size() >= 64, "Truncated PDB DBI header");
        auto r16 = [](std::span<const std::byte> b, std::size_t at) -> std::uint16_t {
            require(at <= b.size() && 2 <= b.size() - at, "Truncated PDB DBI field");
            return static_cast<std::uint16_t>(std::to_integer<unsigned>(b[at]) |
                (std::to_integer<unsigned>(b[at + 1]) << 8));
        };
        auto r32 = [](std::span<const std::byte> b, std::size_t at) -> std::uint32_t { return u32(b, at); };
        const auto module_bytes = r32(dbi, 24);
        std::uint64_t expected = 64;
        for (const auto offset : {28u, 32u, 36u, 40u, 48u, 52u}) {
            const auto size = r32(dbi, offset);
            require(size <= 64ull * 1024 * 1024 && expected <= dbi.size() && size <= dbi.size() - expected,
                    "PDB DBI substream exceeds its bounds", ErrorCode::resource_limit);
            expected += size;
        }
        require(expected + module_bytes == dbi.size() && expected + module_bytes >= expected,
                "PDB module list exceeds DBI stream", ErrorCode::resource_limit);
        require(module_bytes <= 32ull * 1024 * 1024, "PDB module list exceeds inspection limit", ErrorCode::resource_limit);
        struct Module { std::uint16_t index, stream; std::uint32_t symbols, c11, c13; std::string name, object; };
        std::vector<Module> modules;
        std::size_t pos = 64, module_end = 64 + module_bytes;
        auto read_cstring = [&](std::size_t &at) {
            std::string result;
            while (at < module_end && dbi[at] != std::byte{0}) {
                require(result.size() < 32768, "PDB module path exceeds limit", ErrorCode::resource_limit);
                result.push_back(static_cast<char>(std::to_integer<unsigned char>(dbi[at++])));
            }
            require(at < module_end, "Unterminated PDB module path"); ++at; return result;
        };
        while (pos < module_end) {
            check_cancel(stop);
            require(64 <= module_end - pos, "Truncated PDB DBI module record");
            const auto stream_id = r16(dbi, pos + 34);
            const auto symbols = r32(dbi, pos + 36), c11 = r32(dbi, pos + 40), c13 = r32(dbi, pos + 44);
            std::size_t at = pos + 64;
            auto name = read_cstring(at), object = read_cstring(at);
            pos = (at + 3u) & ~std::size_t{3};
            require(pos <= module_end, "PDB DBI module padding exceeds substream");
            modules.push_back({static_cast<std::uint16_t>(modules.size()), stream_id, symbols, c11, c13,
                               std::move(name), std::move(object)});
            require(modules.size() <= 65535, "PDB module count exceeds limit", ErrorCode::resource_limit);
        }
        PdbSourceLineTable result;
        std::size_t result_storage = 0;
        constexpr std::size_t max_line_storage = 256ull * 1024 * 1024;
        std::span<const std::byte> global_strings;
        if (const auto names = database.named_streams.find("/names"); names != database.named_streams.end()) {
            require(names->second < database.streams.size() && database.streams[names->second].has_value(),
                    "PDB /names stream is absent");
            const auto name_stream = std::span<const std::byte>(*database.streams[names->second]);
            require(name_stream.size() >= 12 && r32(name_stream, 0) == 0xeffeeffe,
                    "Invalid PDB /names string-table header");
            const auto hash_version = r32(name_stream, 4), byte_size = r32(name_stream, 8);
            require((hash_version == 1 || hash_version == 2) && byte_size <= name_stream.size() - 12,
                    "PDB /names string-table extent is invalid", ErrorCode::resource_limit);
            global_strings = name_stream.subspan(12, byte_size);
        }
        constexpr std::uint32_t lines_kind = 0xf2, strings_kind = 0xf3, checksums_kind = 0xf4;
        for (const auto &module : modules) {
            check_cancel(stop);
            if (module.stream == 0xffff || module.c13 == 0) continue;
            require(module.c13 <= 32ull * 1024 * 1024, "PDB module C13 data exceeds 32 MiB", ErrorCode::resource_limit);
            require(module.stream < database.streams.size() && database.streams[module.stream].has_value(),
                    "PDB module refers to an absent C13 stream");
            const auto stream = std::span<const std::byte>(*database.streams[module.stream]);
            const std::uint64_t c13_start64 = std::uint64_t{module.symbols} + module.c11;
            require(module.symbols >= 4 && c13_start64 <= stream.size() && module.c13 <= stream.size() - c13_start64,
                    "PDB module C13 extent exceeds stream", ErrorCode::resource_limit);
            const auto c13_start = static_cast<std::size_t>(c13_start64);
            const auto c13 = stream.subspan(c13_start, module.c13);
            struct Checksum { std::uint32_t string_offset; std::uint8_t kind; std::vector<std::byte> bytes; };
            std::map<std::uint32_t, Checksum> files;
            std::span<const std::byte> strings;
            bool strings_seen = false;
            struct LineSubsection { std::span<const std::byte> bytes; std::uint32_t stream_offset; };
            std::vector<LineSubsection> line_subsections;
            std::vector<std::span<const std::byte>> inlinee_subsections;
            std::size_t subpos = 0;
            std::size_t subsection_count = 0;
            while (subpos < c13.size()) {
                check_cancel(stop);
                require(++subsection_count <= 65536, "C13 subsection count exceeds limit", ErrorCode::resource_limit);
                require(c13.size() - subpos >= 8, "Truncated C13 subsection header");
                const auto start = subpos;
                const auto raw_kind = r32(c13, subpos), length = r32(c13, subpos + 4); subpos += 8;
                require(length <= c13.size() - subpos, "C13 subsection exceeds module extent", ErrorCode::resource_limit);
                const auto kind = raw_kind & 0x7fffffffu;
                const auto payload = c13.subspan(subpos, length);
                if (raw_kind & 0x80000000u) {
                    // DEBUG_S_IGNORE applies to the complete subsection.
                } else if (kind == strings_kind) {
                    require(!strings_seen, "Duplicate C13 string table"); strings_seen = true;
                    require(payload.size() >= 4 && r32(payload, 0) == 0xeffeeffe, "Invalid C13 string table signature");
                    strings = payload.subspan(4);
                } else if (kind == checksums_kind) {
                    require(files.empty(), "Duplicate C13 file checksum table");
                    std::size_t file_pos = 0;
                    while (file_pos < payload.size()) {
                        check_cancel(stop);
                        require(payload.size() - file_pos >= 6, "Truncated C13 file checksum record");
                        const auto file_id = static_cast<std::uint32_t>(file_pos);
                        const auto string_offset = r32(payload, file_pos);
                        const auto checksum_size = std::to_integer<std::uint8_t>(payload[file_pos + 4]);
                        const auto checksum_kind = std::to_integer<std::uint8_t>(payload[file_pos + 5]);
                        require(checksum_size <= payload.size() - file_pos - 6, "C13 checksum bytes exceed subsection");
                        Checksum file; file.string_offset = string_offset; file.kind = checksum_kind;
                        file.bytes.assign(payload.begin() + static_cast<std::ptrdiff_t>(file_pos + 6),
                            payload.begin() + static_cast<std::ptrdiff_t>(file_pos + 6 + checksum_size));
                        require(files.emplace(file_id, std::move(file)).second, "Duplicate C13 file identity");
                        require(files.size() <= 65535, "C13 source file count exceeds limit", ErrorCode::resource_limit);
                        const auto consumed = std::size_t{6} + checksum_size;
                        const auto aligned = (consumed + 3u) & ~std::size_t{3};
                        require(aligned <= payload.size() - file_pos, "C13 checksum padding exceeds subsection");
                        file_pos += aligned;
                    }
                } else if (kind == lines_kind) {
                    line_subsections.push_back({payload, static_cast<std::uint32_t>(c13_start + start)});
                } else if (kind == 0xf6) {
                    inlinee_subsections.push_back(payload);
                }
                const auto next = (subpos + length + 3u) & ~std::size_t{3};
                require(next <= c13.size(), "C13 subsection padding exceeds module extent");
                subpos = next;
            }
            auto lookup_path = [&](std::uint32_t string_offset) {
                const auto table = strings.empty() ? global_strings : strings;
                require(!table.empty() && string_offset < table.size(), "C13 source filename has invalid string offset");
                std::string path;
                auto at = static_cast<std::size_t>(string_offset);
                while (at < table.size() && table[at] != std::byte{0}) {
                    require(path.size() < 32768, "C13 source path exceeds limit", ErrorCode::resource_limit);
                    path.push_back(static_cast<char>(std::to_integer<unsigned char>(table[at++])));
                }
                require(at < table.size(), "Unterminated C13 source path");
                return path;
            };
            for (const auto &[file_id, file] : files) {
                auto path = lookup_path(file.string_offset);
                const auto storage = sizeof(PdbSourceFile) + path.size();
                require(storage <= max_line_storage - result_storage,
                        "PDB source-file output exceeds 256 MiB", ErrorCode::resource_limit);
                result_storage += storage;
                result.files.push_back({module.index, file_id, std::move(path)});
                require(result.files.size() <= 1'000'000, "PDB source-file count exceeds limit", ErrorCode::resource_limit);
            }
            std::set<std::uint32_t> inlinee_ids;
            for (const auto bytes : inlinee_subsections) {
                require(bytes.size() >= 4, "Truncated C13 inlinee line signature");
                const auto signature = r32(bytes, 0);
                if (signature > 1) {
                    require(result.unsupported_inlinee_signatures.size() < 1'000'000 &&
                            sizeof(std::pair<std::uint16_t, std::uint32_t>) <= max_line_storage - result_storage,
                            "PDB unsupported inlinee output exceeds limit", ErrorCode::resource_limit);
                    result_storage += sizeof(std::pair<std::uint16_t, std::uint32_t>);
                    result.unsupported_inlinee_signatures.emplace_back(module.index, signature);
                    continue;
                }
                std::size_t entry = 4;
                while (entry < bytes.size()) {
                    check_cancel(stop);
                    require(bytes.size() - entry >= 12, "Truncated C13 inlinee line entry");
                    const auto id = r32(bytes, entry), file = r32(bytes, entry + 4), line = r32(bytes, entry + 8);
                    require(id >= 0x1000 && files.contains(file), "Invalid C13 inlinee identity or source file");
                    require(inlinee_ids.insert(id).second, "Ambiguous duplicate C13 inlinee identity");
                    entry += 12;
                    if (signature == 1) {
                        require(bytes.size() - entry >= 4, "Truncated C13 inlinee extra-file count");
                        const auto count = r32(bytes, entry); entry += 4;
                        require(count <= 65535 && count <= (bytes.size() - entry) / 4,
                                "C13 inlinee extra files exceed subsection", ErrorCode::resource_limit);
                        for (std::uint32_t i = 0; i < count; ++i, entry += 4)
                            require(files.contains(r32(bytes, entry)), "C13 inlinee references unknown extra file");
                    }
                    require(sizeof(PdbInlineeLine) <= max_line_storage - result_storage,
                            "PDB inlinee output exceeds 256 MiB", ErrorCode::resource_limit);
                    result_storage += sizeof(PdbInlineeLine);
                    result.inlinees.push_back({module.index, id, file, line});
                    require(result.inlinees.size() <= 1'000'000, "PDB inlinee count exceeds limit", ErrorCode::resource_limit);
                }
            }
            for (const auto &subsection : line_subsections) {
                check_cancel(stop);
                const auto bytes = subsection.bytes;
                require(bytes.size() >= 12, "Truncated C13 line fragment header");
                const auto reloc_offset = r32(bytes, 0), code_size = r32(bytes, 8);
                const auto section = r16(bytes, 4), flags = r16(bytes, 6);
                const bool has_columns = (flags & 1u) != 0;
                std::size_t block_pos = 12;
                while (block_pos < bytes.size()) {
                    check_cancel(stop);
                    require(bytes.size() - block_pos >= 12, "Truncated C13 line block header");
                    const auto file_id = r32(bytes, block_pos), line_count = r32(bytes, block_pos + 4), block_size = r32(bytes, block_pos + 8);
                    require(block_size >= 12 && block_size <= bytes.size() - block_pos, "Invalid C13 line block size");
                    require(line_count <= 2'000'000, "C13 line count exceeds inspection limit", ErrorCode::resource_limit);
                    const std::uint64_t item_size = has_columns ? 12 : 8;
                    const auto encoded_size = checked_mul(line_count, item_size, "C13 line array size overflows");
                    require(encoded_size == block_size - 12, "C13 line count does not match line block size");
                    const auto file = files.find(file_id);
                    require(file != files.end(), "C13 line references an unknown source file");
                    const auto path = lookup_path(file->second.string_offset);
                    const auto line_data = block_pos + 12;
                    for (std::uint32_t index = 0; index < line_count; ++index) {
                        check_cancel(stop);
                        const auto entry = line_data + std::size_t{index} * 8;
                        const auto line_offset = r32(bytes, entry), line_flags = r32(bytes, entry + 4);
                        const auto line_number = line_flags & 0x00ffffffu;
                        const auto end_delta = (line_flags >> 24) & 0x7fu;
                        require(line_offset <= code_size && reloc_offset <= UINT32_MAX - line_offset,
                                "C13 line address exceeds its contribution");
                        PdbSourceLine line;
                        line.source_path = path; line.source_file_id = file_id;
                        line.checksum_kind = file->second.kind; line.checksum = file->second.bytes;
                        line.section = section; line.reloc_offset = reloc_offset;
                        line.section_offset = reloc_offset + line_offset;
                        line.contribution_size = code_size; line.block_size = block_size;
                        line.line = line_number; line.end_line = line_number + end_delta;
                        line.has_columns = has_columns; line.is_statement = (line_flags & 0x80000000u) != 0;
                        line.end_sequence = false;
                        if (has_columns) {
                            const auto column = line_data + std::size_t{line_count} * 8 + std::size_t{index} * 4;
                            line.start_column = r16(bytes, column); line.end_column = r16(bytes, column + 2);
                        }
                        line.module_name = module.name; line.object_name = module.object;
                        line.module_index = module.index; line.subsection_offset = subsection.stream_offset;
                        const auto line_storage = sizeof(PdbSourceLine) + line.source_path.size() + line.checksum.size() +
                            line.module_name.size() + line.object_name.size();
                        require(line_storage <= max_line_storage - result_storage,
                                "PDB source-line output exceeds 256 MiB", ErrorCode::resource_limit);
                        result_storage += line_storage;
                        result.lines.push_back(std::move(line));
                        require(result.lines.size() <= 2'000'000, "PDB source line count exceeds inspection limit", ErrorCode::resource_limit);
                    }
                    block_pos += block_size;
                }
            }
        }
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "PDB source-line data exceeds available memory"}; }
}

Result<PdbDatabase> parse_pdb(std::span<const std::byte> file, std::stop_token stop) {
    try {
        static constexpr char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
        require(file.size() >= superblock_size, "Truncated MSF 7.0 superblock");
        for (std::size_t i = 0; i < sizeof(magic) - 1; ++i)
            require(file[i] == static_cast<std::byte>(magic[i]), "Invalid MSF 7.0 signature");

        const auto block_size = u32(file, 32);
        const auto block_count = u32(file, 40);
        const auto directory_size = u32(file, 44);
        const auto block_map = u32(file, 52);
        require(block_size == 512 || block_size == 1024 || block_size == 2048 || block_size == 4096,
                "Invalid MSF block size");
        const auto free_map = u32(file, 36);
        require(free_map == 1 || free_map == 2, "Invalid MSF free block map selector");
        require(block_count != 0, "MSF block count is zero");
        const auto declared_size = checked_mul(block_size, block_count, "MSF file extent overflow");
        require(declared_size == file.size(), "MSF declared extent does not match the supplied file");
        require(directory_size != 0 && directory_size <= max_directory_size,
                "MSF directory size is empty or exceeds the inspection limit", ErrorCode::resource_limit);
        const auto directory_blocks = (std::uint64_t{directory_size} + block_size - 1) / block_size;
        const auto map_bytes = checked_mul(directory_blocks, 4, "MSF block map size overflow");
        const auto map_blocks = (map_bytes + block_size - 1) / block_size;
        require(map_bytes <= block_size && std::uint64_t{block_map} + map_blocks <= block_count,
                "MSF directory block map exceeds declared blocks");
        const auto map_offset = checked_mul(block_map, block_size, "MSF map offset overflow");
        const auto map_end = map_offset + map_bytes;
        require(map_end <= declared_size, "MSF directory block map exceeds file");

        std::vector<std::byte> directory;
        directory.reserve(directory_size);
        for (std::uint64_t i = 0; i < directory_blocks; ++i) {
            check_cancel(stop);
            const auto block = u32(file, static_cast<std::size_t>(map_offset + i * 4));
            require(block < block_count, "MSF directory references an invalid block");
            const auto offset = checked_mul(block, block_size, "MSF directory block offset overflow");
            const auto amount = std::min<std::uint64_t>(block_size, directory_size - directory.size());
            require(offset <= declared_size && amount <= declared_size - offset,
                    "MSF directory block exceeds file");
            directory.insert(directory.end(), file.begin() + static_cast<std::ptrdiff_t>(offset),
                             file.begin() + static_cast<std::ptrdiff_t>(offset + amount));
        }

        const auto stream_count = u32(directory, 0);
        require(stream_count >= 2 && stream_count <= 1'000'000,
                "Invalid MSF stream count", ErrorCode::resource_limit);
        const auto sizes_bytes = checked_mul(stream_count, 4, "MSF stream table overflow");
        require(4 + sizes_bytes <= directory.size(), "Truncated MSF stream size table");
        PdbDatabase database;
        database.block_size = block_size;
        database.streams.resize(stream_count);
        std::uint64_t cursor = 4 + sizes_bytes;
        std::uint64_t total_data = 0;
        std::vector<std::uint32_t> sizes(stream_count);
        for (std::uint32_t i = 0; i < stream_count; ++i) sizes[i] = u32(directory, 4 + i * 4);
        for (std::uint32_t i = 0; i < stream_count; ++i) {
            check_cancel(stop);
            const auto size = sizes[i];
            if (size == absent_stream) continue;
            require(size <= max_stream_data - total_data,
                    "MSF stream bytes exceed the inspection limit", ErrorCode::resource_limit);
            total_data += size;
            const auto blocks = (std::uint64_t{size} + block_size - 1) / block_size;
            const auto block_bytes = checked_mul(blocks, 4, "MSF stream block table overflow");
            require(cursor <= directory.size() && block_bytes <= directory.size() - cursor,
                    "Truncated MSF stream block table");
            if (size == 0) {
                database.streams[i] = std::vector<std::byte>{};
                continue;
            }
            std::vector<std::byte> stream;
            stream.reserve(size);
            for (std::uint64_t j = 0; j < blocks; ++j) {
                check_cancel(stop);
                const auto block = u32(directory, static_cast<std::size_t>(cursor + j * 4));
                require(block < block_count, "MSF stream references an invalid block");
                const auto offset = checked_mul(block, block_size, "MSF stream block offset overflow");
                const auto amount = std::min<std::uint64_t>(block_size, size - stream.size());
                require(offset <= declared_size && amount <= declared_size - offset,
                        "MSF stream block exceeds file");
                stream.insert(stream.end(), file.begin() + static_cast<std::ptrdiff_t>(offset),
                              file.begin() + static_cast<std::ptrdiff_t>(offset + amount));
            }
            cursor += block_bytes;
            database.streams[i] = std::move(stream);
        }
        require(cursor == directory.size(), "MSF stream directory has trailing or unreferenced data");

        require(database.streams[1].has_value() && database.streams[1]->size() >= 28,
                "PDB information stream is missing or truncated");
        const auto info = std::span<const std::byte>(*database.streams[1]);
        database.info.version = u32(info, 0);
        require(database.info.version == 20000404, "Unsupported PDB information stream version", ErrorCode::unsupported);
        database.info.signature = u32(info, 4);
        database.info.age = u32(info, 8);
        std::copy_n(info.begin() + 12, database.info.guid.size(), database.info.guid.begin());
        if (info.size() > 28) {
            std::size_t name_map_cursor = 28;
            require(info.size() - name_map_cursor >= 4, "Truncated PDB named-stream string buffer");
            const auto string_bytes = u32(info, name_map_cursor); name_map_cursor += 4;
            require(string_bytes <= info.size() - name_map_cursor, "PDB named-stream string buffer exceeds info stream", ErrorCode::resource_limit);
            const auto names = info.subspan(name_map_cursor, string_bytes); name_map_cursor += string_bytes;
            require(info.size() - name_map_cursor >= 8, "Truncated PDB named-stream hash table");
            const auto count = u32(info, name_map_cursor), capacity = u32(info, name_map_cursor + 4); name_map_cursor += 8;
            require(capacity > 0 && capacity <= 1'000'000 && count <= capacity,
                    "Invalid PDB named-stream hash table dimensions", ErrorCode::resource_limit);
            auto read_bits = [&](std::vector<std::uint32_t> &words) {
                require(info.size() - name_map_cursor >= 4, "Truncated PDB named-stream bit vector");
                const auto n = u32(info, name_map_cursor); name_map_cursor += 4;
                require(n <= (capacity + 31) / 32 && std::uint64_t{n} * 4 <= info.size() - name_map_cursor,
                        "PDB named-stream bit vector exceeds bounds", ErrorCode::resource_limit);
                words.reserve(n);
                for (std::uint32_t i = 0; i < n; ++i, name_map_cursor += 4) words.push_back(u32(info, name_map_cursor));
            };
            std::vector<std::uint32_t> present, deleted;
            read_bits(present); read_bits(deleted);
            auto bit_is_set = [](const std::vector<std::uint32_t> &words, std::uint32_t bit) {
                const auto word = bit / 32;
                return word < words.size() && ((words[word] >> (bit % 32)) & 1u) != 0;
            };
            std::uint32_t present_count = 0;
            for (std::uint32_t bucket = 0; bucket < capacity; ++bucket) {
                const bool is_present = bit_is_set(present, bucket), is_deleted = bit_is_set(deleted, bucket);
                require(!(is_present && is_deleted), "PDB named-stream bucket is both present and deleted");
                if (!is_present) continue;
                ++present_count;
                require(info.size() - name_map_cursor >= 8, "Truncated PDB named-stream hash entry");
                const auto key = u32(info, name_map_cursor), stream = u32(info, name_map_cursor + 4); name_map_cursor += 8;
                require(key < names.size() && stream < database.streams.size(), "Invalid PDB named-stream key or stream index");
                std::string name;
                auto at = static_cast<std::size_t>(key);
                while (at < names.size() && names[at] != std::byte{0}) {
                    require(name.size() < 4096, "PDB named-stream name exceeds limit", ErrorCode::resource_limit);
                    name.push_back(static_cast<char>(std::to_integer<unsigned char>(names[at++])));
                }
                require(at < names.size() && !name.empty(), "Invalid PDB named-stream name");
                require(database.named_streams.emplace(std::move(name), stream).second, "Duplicate PDB named-stream name");
            }
            const auto bit_words = std::max(present.size(), deleted.size());
            for (std::uint64_t bit = capacity; bit < std::uint64_t{bit_words} * 32; ++bit)
                require(!bit_is_set(present, static_cast<std::uint32_t>(bit)) && !bit_is_set(deleted, static_cast<std::uint32_t>(bit)),
                        "PDB named-stream bit vector exceeds table capacity");
            require(present_count == count, "PDB named-stream bucket count does not match header");
            require((info.size() - name_map_cursor) % 4 == 0, "PDB info stream has truncated feature code");
        }
        check_cancel(stop);
        return database;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "PDB data exceeds available memory"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "PDB allocation size is too large"};
    }
}

} // namespace hexlab::types



