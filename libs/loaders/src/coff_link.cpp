#include "hexlab/loaders/coff_link.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>

namespace hexlab {
namespace {
struct Failure { Error error; };
constexpr std::size_t max_coff_name_bytes = 4096;
constexpr std::uint16_t machine_amd64 = 0x8664, machine_arm64 = 0xaa64;
constexpr std::size_t max_bigobj_sections = 1'000'000;
constexpr std::array<std::uint8_t,16> bigobj_class_id{
    0xc7,0xa1,0xba,0xd1,0xee,0xba,0xa9,0x4b,0xaf,0x20,0xfa,0xf6,0x6a,0xa4,0xdc,0xb8};
void require(bool ok, std::string message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, std::move(message)}};
}
std::uint64_t le(std::span<const std::byte> b, std::size_t at, std::size_t n) {
    require(at <= b.size() && n <= b.size() - at, "Truncated COFF object");
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v |= std::to_integer<std::uint64_t>(b[at + i]) << (8 * i);
    return v;
}
void put(std::vector<std::byte> &b, std::size_t at, std::uint64_t v, std::size_t n) {
    require(at <= b.size() && n <= b.size() - at, "PE output field exceeds output extent", ErrorCode::resource_limit);
    for (std::size_t i = 0; i < n; ++i) b[at + i] = static_cast<std::byte>(v >> (8 * i));
}
std::uint64_t align(std::uint64_t n, std::uint64_t a) {
    require(a && (a & (a - 1)) == 0 && n <= UINT64_MAX - (a - 1), "COFF section alignment is invalid", ErrorCode::resource_limit);
    return (n + a - 1) & ~(a - 1);
}
std::string fixed_name(std::span<const std::byte> b) {
    std::size_t n = 0; while (n < b.size() && b[n] != std::byte{0}) ++n;
    return {reinterpret_cast<const char *>(b.data()), n};
}
std::string section_name(std::span<const std::byte> field, std::span<const std::byte> strings) {
    const auto short_name = fixed_name(field);
    if (short_name.size() < 2 || short_name.front() != '/')
        return short_name;
    std::uint64_t offset = 0;
    bool digit = false;
    for (std::size_t i = 1; i < short_name.size(); ++i) {
        const auto c = static_cast<unsigned char>(short_name[i]);
        if (c < '0' || c > '9')
            return short_name;
        digit = true;
        require(offset <= (UINT64_MAX - (c - '0')) / 10,
                "COFF long section name offset overflows");
        offset = offset * 10 + (c - '0');
    }
    if (!digit)
        return short_name;
    require(offset >= 4 && offset < strings.size(), "COFF long section name is outside string table");
    const auto begin = static_cast<std::size_t>(offset);
    auto end = begin;
    while (end < strings.size() && strings[end] != std::byte{0}) {
        require(end - begin < max_coff_name_bytes, "COFF long section name exceeds limit", ErrorCode::resource_limit);
        ++end;
    }
    require(end < strings.size(), "Unterminated COFF long section name");
    require(end > begin, "Empty COFF long section name");
    return {reinterpret_cast<const char *>(strings.data() + begin), end - begin};
}
std::string sym_name(std::span<const std::byte> row, std::span<const std::byte> strings) {
    if (le(row, 0, 4) != 0) return fixed_name(row.first(8));
    const auto off = le(row, 4, 4);
    require(off >= 4 && off < strings.size(), "COFF symbol name is outside string table");
    std::size_t end = static_cast<std::size_t>(off);
    while (end < strings.size() && strings[end] != std::byte{0}) {
        require(end - static_cast<std::size_t>(off) < max_coff_name_bytes,
                "COFF symbol name exceeds limit", ErrorCode::resource_limit);
        ++end;
    }
    require(end < strings.size(), "Unterminated COFF symbol name");
    return {reinterpret_cast<const char *>(strings.data() + off), end - static_cast<std::size_t>(off)};
}
std::string import_string(std::span<const std::byte> bytes, std::size_t &at) {
    const auto begin = at;
    while (at < bytes.size() && bytes[at] != std::byte{0}) {
        require(at - begin < max_coff_name_bytes, "COFF import-object name exceeds limit", ErrorCode::resource_limit);
        ++at;
    }
    require(at < bytes.size(), "Unterminated COFF import-object name");
    const auto size = at - begin;
    ++at;
    require(size != 0, "Empty COFF import-object name");
    return {reinterpret_cast<const char *>(bytes.data() + begin), size};
}
struct ImportObject {
    std::string public_name, lookup_name, dll_name;
    std::uint16_t type = 0, ordinal_or_hint = 0;
    bool by_ordinal = false;
};
ImportObject parse_import_object(std::span<const std::byte> bytes) {
    require(bytes.size() >= 20, "Truncated COFF import-object header");
    require(le(bytes, 0, 2) == 0 && le(bytes, 2, 2) == 0xffff && le(bytes, 4, 2) == 0,
            "Invalid or unsupported COFF import-object header", ErrorCode::unsupported);
    require(le(bytes, 6, 2) == 0x8664,
            "PE import-object architecture is unsupported by the AMD64 static writer", ErrorCode::unsupported);
    const auto payload_size = le(bytes, 12, 4);
    require(payload_size == bytes.size() - 20, "COFF import-object payload size disagrees with object extent");
    const auto type_info = le(bytes, 18, 2);
    const auto import_type = static_cast<std::uint16_t>(type_info & 3);
    const auto name_type = static_cast<std::uint16_t>((type_info >> 2) & 7);
    require((type_info >> 5) == 0, "COFF import-object reserved bits must be zero");
    require(import_type <= 2 && name_type <= 4,
            "COFF import-object type or name type is unsupported", ErrorCode::unsupported);
    const auto payload = bytes.subspan(20);
    std::size_t at = 0;
    ImportObject result;
    result.public_name = import_string(payload, at);
    result.dll_name = import_string(payload, at);
    result.type = import_type;
    result.ordinal_or_hint = static_cast<std::uint16_t>(le(bytes, 16, 2));
    result.by_ordinal = name_type == 0;
    if (name_type == 4) {
        result.lookup_name = import_string(payload, at);
    } else {
        result.lookup_name = result.public_name;
        if (name_type == 2 || name_type == 3) {
            if (!result.lookup_name.empty() &&
                (result.lookup_name.front() == '?' || result.lookup_name.front() == '@' || result.lookup_name.front() == '_'))
                result.lookup_name.erase(0, 1);
            if (name_type == 3) {
                const auto suffix = result.lookup_name.find('@');
                if (suffix != std::string::npos) result.lookup_name.resize(suffix);
            }
        }
    }
    require(at == payload.size(), "COFF import-object payload has trailing data");
    require(!result.lookup_name.empty() || result.by_ordinal,
            "COFF import-by-name record has no lookup name");
    return result;
}
std::size_t arm64_relocation_width(std::uint16_t type) {
    if (type == 14) return 8; // ADDR64
    if ((type >= 1 && type <= 7) || (type >= 15 && type <= 17)) return 4;
    throw Failure{{ErrorCode::unsupported, "Unsupported ARM64 COFF relocation type " + std::to_string(type)}};
}
std::int64_t signed_bits(std::uint32_t value, unsigned bits) {
    const auto mask = (UINT64_C(1) << bits) - 1;
    const auto v = static_cast<std::uint64_t>(value) & mask;
    return static_cast<std::int64_t>(v) - ((v & (UINT64_C(1) << (bits - 1))) ? static_cast<std::int64_t>(mask + 1) : 0);
}
std::uint64_t arm64_addend(std::uint64_t target, std::int64_t addend) {
    if (addend >= 0) {
        require(target <= UINT64_MAX - static_cast<std::uint64_t>(addend),
                "ARM64 COFF relocation address overflows", ErrorCode::unsupported);
        return target + static_cast<std::uint64_t>(addend);
    }
    const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    require(target >= magnitude, "ARM64 COFF relocation address underflows", ErrorCode::unsupported);
    return target - magnitude;
}
void apply_arm64_relocation(std::vector<std::byte> &bytes, std::size_t field, std::uint16_t type,
                             std::uint64_t target, std::uint64_t place, std::uint64_t image_base,
                             std::uint64_t text_begin, std::uint64_t text_size, bool code) {
    if (type == 14) {
        put(bytes, field, arm64_addend(target, std::bit_cast<std::int64_t>(le(bytes, field, 8))), 8);
        return;
    }
    if (type == 1 || type == 2 || type == 17) {
        require(target <= INT64_MAX && place <= INT64_MAX, "ARM64 COFF address exceeds signed relocation domain", ErrorCode::unsupported);
        const auto addend = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(le(bytes, field, 4)));
        const auto base = static_cast<std::int64_t>(target) -
            (type == 2 ? static_cast<std::int64_t>(image_base) : type == 17 ? static_cast<std::int64_t>(place) + 4 : 0);
        require(base <= INT64_MAX - INT32_MAX && base >= INT64_MIN - INT32_MIN,
                "ARM64 COFF scalar relocation arithmetic overflows", ErrorCode::unsupported);
        const auto value = base + addend;
        require(type == 17 ? value >= INT32_MIN && value <= INT32_MAX : value >= 0 && static_cast<std::uint64_t>(value) <= UINT32_MAX,
                "ARM64 COFF 32-bit relocation is out of range", ErrorCode::unsupported);
        put(bytes, field, static_cast<std::uint32_t>(value), 4);
        return;
    }
    require(code && (place & 3) == 0, "ARM64 instruction relocations require aligned .text fields", ErrorCode::unsupported);
    auto instruction = static_cast<std::uint32_t>(le(bytes, field, 4));
    if (type == 3 || type == 15 || type == 16) {
        const unsigned bits = type == 3 ? 26 : type == 15 ? 19 : 14;
        const unsigned shift = type == 3 ? 0 : 5;
        const auto immediate_mask = ((UINT32_C(1) << bits) - 1) << shift;
        bool encoding = false;
        if (type == 3) encoding = (instruction & 0x7c000000u) == 0x14000000u; // B/BL
        else if (type == 15) encoding =
            ((instruction & 0xff000010u) == 0x54000000u && (instruction & 15u) < 14) || // B.cond
            (instruction & 0x7e000000u) == 0x34000000u; // CBZ/CBNZ
        else encoding = (instruction & 0x7e000000u) == 0x36000000u; // TBZ/TBNZ
        require(encoding, "ARM64 COFF branch relocation does not match a supported branch instruction", ErrorCode::unsupported);
        require((instruction & immediate_mask) == 0, "ARM64 COFF branch relocation requires a zero encoded addend", ErrorCode::unsupported);
        require((target & 3) == 0 && target >= text_begin && target - text_begin < text_size &&
                text_size - (target - text_begin) >= 4,
                "ARM64 COFF branch target is not a complete aligned instruction in linked .text", ErrorCode::unsupported);
        const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(place);
        const auto limit = INT64_C(1) << (bits + 1);
        require(delta >= -limit && delta < limit && delta % 4 == 0,
                "ARM64 COFF branch target is out of range; veneers are unsupported", ErrorCode::unsupported);
        const auto encoded = static_cast<std::uint32_t>(static_cast<std::uint64_t>(delta / 4) & ((UINT64_C(1) << bits) - 1));
        put(bytes, field, (instruction & ~immediate_mask) | (encoded << shift), 4);
        return;
    }
    if (type == 4 || type == 5) {
        require((instruction & 0x9f000000u) == (type == 4 ? 0x90000000u : 0x10000000u),
                "ARM64 COFF page/address relocation requires ADRP or ADR", ErrorCode::unsupported);
        const auto raw = ((instruction >> 29) & 3u) | (((instruction >> 5) & 0x7ffffu) << 2);
        // COFF stores this implicit addend in bytes, including for ADRP.
        // Add it before computing either the page delta or byte delta.
        const auto adjusted = arm64_addend(target, signed_bits(raw, 21));
        require(adjusted <= INT64_MAX && place <= INT64_MAX,
                "ARM64 COFF address relocation exceeds signed domain", ErrorCode::unsupported);
        const auto delta = type == 4
            ? static_cast<std::int64_t>(adjusted >> 12) - static_cast<std::int64_t>(place >> 12)
            : static_cast<std::int64_t>(adjusted) - static_cast<std::int64_t>(place);
        require(delta >= -(INT64_C(1) << 20) && delta < (INT64_C(1) << 20),
                "ARM64 COFF ADR/ADRP target is out of range", ErrorCode::unsupported);
        const auto encoded = static_cast<std::uint32_t>(static_cast<std::uint64_t>(delta) & 0x1fffffu);
        instruction = (instruction & ~0x60ffffe0u) | ((encoded & 3u) << 29) | ((encoded >> 2) << 5);
        put(bytes, field, instruction, 4);
        return;
    }
    require(type == 6 || type == 7, "Unsupported ARM64 COFF instruction relocation", ErrorCode::unsupported);
    unsigned scale = 0;
    if (type == 6) {
        require((instruction & 0x5f800000u) == 0x11000000u && (instruction & (1u << 22)) == 0,
                "ARM64 PAGEOFFSET_12A requires unshifted ADD/ADDS immediate", ErrorCode::unsupported);
    } else {
        require((instruction & 0x3b000000u) == 0x39000000u,
                "ARM64 PAGEOFFSET_12L requires an unsigned-immediate load/store", ErrorCode::unsupported);
        scale = instruction >> 30;
        const auto opc = (instruction >> 22) & 3u;
        if (instruction & (1u << 26)) {
            require(opc < 2 || scale == 0, "ARM64 vector load/store encoding is reserved", ErrorCode::unsupported);
            if (opc >= 2) scale = 4;
        } else require((scale != 3 || opc < 2) && (scale != 2 || opc != 3),
                       "ARM64 PAGEOFFSET_12L prefetch/reserved encoding is unsupported", ErrorCode::unsupported);
    }
    const auto addend = static_cast<std::uint64_t>((instruction >> 10) & 0xfffu) << scale;
    const auto low = arm64_addend(target, static_cast<std::int64_t>(addend)) & 0xfffu;
    require((low & ((UINT64_C(1) << scale) - 1)) == 0,
            "ARM64 COFF page offset violates load/store access alignment", ErrorCode::unsupported);
    put(bytes, field, (instruction & ~0x003ffc00u) | (static_cast<std::uint32_t>(low >> scale) << 10), 4);
}
struct Symbol { std::string name; std::uint32_t value = 0; std::int32_t section = 0; std::uint8_t storage = 0; std::uint32_t table_index = 0; };
struct Reloc { std::uint32_t offset = 0, symbol = 0; std::uint16_t type = 0; };
enum class OutputKind { text, rdata, data, pdata, xdata, bss };
enum class ComdatSelection : std::uint8_t { none=0, no_duplicates=1, any=2, same_size=3, exact_match=4, associative=5, largest=6 };
struct Section { std::string name; OutputKind kind = OutputKind::text; std::vector<std::byte> bytes; std::vector<Reloc> relocs; std::uint64_t out = 0, size = 0; std::uint32_t characteristics = 0; bool comdat=false, selected=true; ComdatSelection selection=ComdatSelection::none; std::uint16_t associative_parent=0; std::uint32_t comdat_key_symbol=UINT32_MAX; };
struct Object { std::vector<Section> sections; std::vector<Symbol> symbols; std::vector<ImportObject> imports; std::uint16_t machine=machine_amd64; };
Object parse(const ByteStorage &storage, std::stop_token stop, std::size_t &symbols_total,
             std::size_t &relocs_total, const CoffLinkLimits &limits) {
    require(!stop.stop_requested(), "COFF link canceled", ErrorCode::canceled);
    require(storage.size() <= limits.max_output_bytes && storage.size() <= SIZE_MAX, "COFF object exceeds configured limit", ErrorCode::resource_limit);
    auto v = storage.read_at({0}, static_cast<std::size_t>(storage.size()));
    if (!v) throw Failure{v.error()};
    const auto b = std::span<const std::byte>(v.value().bytes);
    require(b.size() >= 20, "Truncated COFF header");
    bool bigobj = false;
    if (le(b, 0, 2) == 0 && le(b, 2, 2) == 0xffff) {
        const auto version = le(b, 4, 2);
        if (version == 0) {
            Object import_object;
            import_object.imports.push_back(parse_import_object(b));
            const auto import_symbols = import_object.imports.front().type == 0 ? 2u : 1u;
            require(import_symbols <= limits.max_symbols - symbols_total,
                    "COFF import-object symbol limit exceeded", ErrorCode::resource_limit);
            symbols_total += import_symbols;
            return import_object;
        }
        require(b.size() >= 56, "Truncated anonymous COFF object header");
        require(version >= 2, "Unsupported anonymous COFF object version", ErrorCode::unsupported);
        bigobj = std::equal(bigobj_class_id.begin(), bigobj_class_id.end(), b.begin() + 12,
            [](std::uint8_t a, std::byte value) { return a == std::to_integer<std::uint8_t>(value); });
        require(bigobj, "Unsupported anonymous COFF object class", ErrorCode::unsupported);
    }
    const auto machine = le(b, bigobj ? 6 : 0, 2);
    require(machine == machine_amd64 || machine == machine_arm64,
            "COFF link subset requires AMD64 or ARM64 objects", ErrorCode::unsupported);
    const auto header_size = bigobj ? 56u : 20u;
    const auto count = static_cast<std::size_t>(bigobj ? le(b, 44, 4) : le(b, 2, 2));
    const auto symoff = bigobj ? le(b, 48, 4) : le(b, 8, 4);
    const auto symcount = bigobj ? le(b, 52, 4) : le(b, 12, 4);
    const auto optsize = bigobj ? 0 : le(b, 16, 2);
    require(optsize == 0, "COFF link input must be an object without optional header", ErrorCode::unsupported);
    if (machine == machine_arm64)
        require((le(b, 18, 2) & 0x2002u) == 0, "ARM64 COFF link input cannot be an executable or DLL", ErrorCode::unsupported);
    require(count && count <= (bigobj ? max_bigobj_sections : 96) &&
                count <= (b.size() - std::min<std::size_t>(header_size, b.size())) / 40,
            "Invalid or over-limit COFF section table", bigobj ? ErrorCode::resource_limit : ErrorCode::malformed);
    require(symcount <= limits.max_symbols - symbols_total, "COFF link symbol limit exceeded", ErrorCode::resource_limit);
    symbols_total += static_cast<std::size_t>(symcount);
    const auto symbol_size = bigobj ? 20u : 18u;
    require(machine != machine_arm64 || symcount == 0 || symoff >= header_size + count * 40,
            "ARM64 COFF symbol table overlaps its headers");
    require(symcount == 0 || (symoff <= b.size() && symcount <= (b.size() - symoff) / symbol_size), "COFF symbol table exceeds object extent");
    const auto strings_at = static_cast<std::size_t>(symoff + symcount * symbol_size);
    std::span<const std::byte> strings;
    if (symcount) {
        require(strings_at <= b.size() && b.size() - strings_at >= 4, "COFF string table header is missing");
        const auto string_size = le(b, strings_at, 4);
        require(string_size >= 4 && string_size <= b.size() - strings_at, "Invalid COFF string table size");
        strings = b.subspan(strings_at, static_cast<std::size_t>(string_size));
    } else if (symoff) {
        require(symoff <= b.size() && b.size() - static_cast<std::size_t>(symoff) >= 4,
                "COFF string table header is missing");
        const auto string_size = le(b, static_cast<std::size_t>(symoff), 4);
        require(string_size >= 4 && string_size <= b.size() - static_cast<std::size_t>(symoff),
                "Invalid COFF string table size");
        strings = b.subspan(static_cast<std::size_t>(symoff), static_cast<std::size_t>(string_size));
    }
    Object o;
    o.machine = static_cast<std::uint16_t>(machine);
    std::vector<std::uint32_t> symbol_index(static_cast<std::size_t>(symcount));
    struct SectionAux {std::uint32_t length=0,checksum=0,relocations=0,lines=0;std::int32_t number=0;std::uint8_t selection=0;std::uint32_t symbol_table_index=0;};
    std::vector<std::optional<SectionAux>> section_aux(count);
    for (std::size_t i = 0; i < symcount;) {
        const auto row = b.subspan(static_cast<std::size_t>(symoff + i * symbol_size), symbol_size);
        const auto aux = static_cast<std::size_t>(le(row, bigobj ? 19 : 17, 1));
        require(aux <= symcount - i - 1, "COFF auxiliary symbol count exceeds table");
        Symbol s{sym_name(row, strings), static_cast<std::uint32_t>(le(row, 8, 4)),
                 bigobj ? static_cast<std::int32_t>(le(row, 12, 4)) : static_cast<std::int16_t>(le(row, 12, 2)),
                 static_cast<std::uint8_t>(le(row, bigobj ? 18 : 16, 1)),static_cast<std::uint32_t>(i)};
        const auto type = le(row, bigobj ? 16 : 14, 2);
        require(machine != machine_arm64 || s.storage != 105,
                "ARM64 COFF weak-external aliases are unsupported", ErrorCode::unsupported);
        if (aux && s.storage == 3 && s.section > 0 && static_cast<std::size_t>(s.section) <= count &&
            s.value == 0 && type == 0) {
            const auto section_header = b.subspan(header_size + (static_cast<std::size_t>(s.section) - 1) * 40, 40);
            if (s.name == section_name(section_header.first(8), strings)) {
                require(aux==1,"COFF section-definition symbol must have exactly one auxiliary record");
                const auto aux_record = b.subspan(static_cast<std::size_t>(symoff + (i + 1) * symbol_size), symbol_size);
                const auto section_index=static_cast<std::size_t>(s.section-1);
                require(!section_aux[section_index],"Duplicate COFF section-definition auxiliary record");
                require(le(aux_record,15,1)==0,"COFF section-definition auxiliary reserved byte must be zero");
                const auto high_number = bigobj ? le(aux_record,16,2) : 0;
                require(bigobj ? le(aux_record,18,2)==0 : le(aux_record,16,2)==0,
                        "COFF section-definition auxiliary reserved bytes must be zero");
                section_aux[section_index]=SectionAux{static_cast<std::uint32_t>(le(aux_record,0,4)),static_cast<std::uint32_t>(le(aux_record,8,4)),
                    static_cast<std::uint32_t>(le(aux_record,4,2)),static_cast<std::uint32_t>(le(aux_record,6,2)),
                    static_cast<std::int32_t>(le(aux_record,12,2) | (high_number << 16)),
                    static_cast<std::uint8_t>(le(aux_record,14,1)),static_cast<std::uint32_t>(i)};
            }
        }
        symbol_index[i] = static_cast<std::uint32_t>(o.symbols.size());
        o.symbols.push_back(std::move(s));
        for (std::size_t a = 1; a <= aux; ++a) symbol_index[i + a] = UINT32_MAX;
        i += 1 + aux;
    }
    o.sections.resize(count);
    for (std::size_t i = 0; i < count; ++i) {
        require(!stop.stop_requested(), "COFF link canceled", ErrorCode::canceled);
        const auto h = b.subspan(header_size + i * 40, 40);
        auto &s = o.sections[i]; s.name = section_name(h.first(8), strings);
        const auto raw_size = le(h, 16, 4), raw_at = le(h, 20, 4), rel_at = le(h, 24, 4), rel_count = le(h, 32, 2);
        s.characteristics = static_cast<std::uint32_t>(le(h, 36, 4));
        if (machine == machine_arm64)
            require(!s.name.starts_with(".pdata") && !s.name.starts_with(".xdata"),
                    "ARM64 COFF unwind contributions are unsupported", ErrorCode::unsupported);
        require((s.characteristics&0x01000000)==0,
                "COFF extended relocation-overflow sections are unsupported",ErrorCode::unsupported);
        const bool uninitialized = (s.characteristics & 0x80) != 0;
        s.comdat=(s.characteristics&0x1000)!=0;
        if(s.comdat){
            require(section_aux[i].has_value(),"COFF COMDAT section lacks a section-definition auxiliary record");
            const auto& aux=*section_aux[i];
            require(aux.selection>=1 && aux.selection<=6,"Unsupported or invalid COFF COMDAT selection mode",ErrorCode::unsupported);
            s.selection=static_cast<ComdatSelection>(aux.selection);s.associative_parent=aux.number;
            const auto raw_key_symbol=aux.symbol_table_index+2;
            require(raw_key_symbol<symcount && symbol_index[raw_key_symbol]!=UINT32_MAX,
                    "COFF COMDAT section has no following key symbol");
            s.comdat_key_symbol=symbol_index[raw_key_symbol];
            const auto key_position=s.comdat_key_symbol;
            require(key_position<o.symbols.size(),"Invalid COFF COMDAT key symbol index");
            const auto& key=o.symbols[key_position];
            require(!key.name.empty() && key.section==static_cast<std::int32_t>(i+1) && key.storage==2 && key.value<=raw_size,
                    "COFF COMDAT key must be an external definition in its section",ErrorCode::unsupported);
        } else if(section_aux[i]) {
            require(section_aux[i]->selection==0,"Non-COMDAT COFF section has a COMDAT selection mode");
        }
        if (s.name == ".text" || s.name.starts_with(".text$")) {
            require(!uninitialized, "COFF code section cannot be uninitialized: " + s.name, ErrorCode::unsupported);
            s.kind = OutputKind::text;
        } else if (s.name == ".rdata" || s.name.starts_with(".rdata$")) {
            require(!uninitialized, "COFF read-only data section cannot be uninitialized: " + s.name, ErrorCode::unsupported);
            s.kind = OutputKind::rdata;
        } else if (s.name == ".data" || s.name.starts_with(".data$")) {
            require(!uninitialized, "COFF data section cannot be uninitialized: " + s.name, ErrorCode::unsupported);
            s.kind = OutputKind::data;
        } else if (s.name == ".pdata" || s.name.starts_with(".pdata$")) {
            require(!uninitialized, "COFF procedure-data section cannot be uninitialized: " + s.name, ErrorCode::unsupported);
            s.kind = OutputKind::pdata;
            require(raw_size % 12 == 0, "AMD64 COFF .pdata size must contain whole RUNTIME_FUNCTION records");
        } else if (s.name == ".xdata" || s.name.starts_with(".xdata$")) {
            require(!uninitialized, "COFF unwind-data section cannot be uninitialized: " + s.name, ErrorCode::unsupported);
            s.kind = OutputKind::xdata;
        } else if ((s.name == ".bss" || s.name.starts_with(".bss$")) && uninitialized) {
            s.kind = OutputKind::bss;
        } else {
            throw Failure{{ErrorCode::unsupported,
                           "COFF link subset supports .text, .rdata, .data, .pdata, .xdata, and uninitialized .bss sections; found " + s.name}};
        }
        if (machine == machine_arm64) {
            require(le(h, 8, 4) == 0 && le(h, 12, 4) == 0,
                    "ARM64 COFF object section virtual addresses/sizes must be zero", ErrorCode::unsupported);
            require(((s.characteristics >> 20) & 15u) <= 14,
                    "ARM64 COFF section uses a reserved alignment code", ErrorCode::unsupported);
            const std::uint32_t content = s.kind == OutputKind::text ? 0x20u : s.kind == OutputKind::bss ? 0x80u : 0x40u;
            const std::uint32_t access = s.kind == OutputKind::text ? 0x60000000u :
                s.kind == OutputKind::rdata ? 0x40000000u : 0xc0000000u;
            const auto allowed = content | access | 0x00f01000u; // alignment and supported COMDAT
            require((s.characteristics & (0xe00000e0u)) == (content | access) &&
                    (s.characteristics & ~allowed) == 0,
                    "ARM64 COFF section flags cannot be represented by the static PE writer: " + s.name,
                    ErrorCode::unsupported);
            require(s.kind != OutputKind::text || raw_size % 4 == 0,
                    "ARM64 COFF code contributions must contain whole four-byte instructions");
        }
        require(raw_size <= limits.max_output_bytes && raw_size <= SIZE_MAX, "COFF section exceeds configured limit", ErrorCode::resource_limit);
        s.size = raw_size;
        if (uninitialized) {
            require(s.kind == OutputKind::bss && raw_at == 0,
                    "COFF uninitialized data must be a .bss section without raw bytes", ErrorCode::unsupported);
            if (section_aux[i])
                require(section_aux[i]->length == raw_size, "COFF .bss section auxiliary length disagrees with section header");
        } else {
            require(machine != machine_arm64 || raw_size == 0 || raw_at >= header_size + count * 40,
                    "ARM64 COFF raw section data overlaps its headers");
            require(raw_at <= b.size() && raw_size <= b.size() - raw_at, "COFF section raw data exceeds object extent");
            s.bytes.assign(b.begin() + static_cast<std::ptrdiff_t>(raw_at), b.begin() + static_cast<std::ptrdiff_t>(raw_at + raw_size));
        }
        require(rel_count <= limits.max_relocations - relocs_total, "COFF relocation limit exceeded", ErrorCode::resource_limit);
        relocs_total += static_cast<std::size_t>(rel_count);
        require(rel_count == 0 || (rel_at <= b.size() && rel_count <= (b.size() - rel_at) / 10), "COFF relocation table exceeds object extent");
        require(machine != machine_arm64 || rel_count == 0 || rel_at >= header_size + count * 40,
                "ARM64 COFF relocation table overlaps its headers");
        if(section_aux[i])
            require(section_aux[i]->length==raw_size && section_aux[i]->relocations==rel_count &&
                    section_aux[i]->lines==le(h,34,2),"COFF section-definition auxiliary metadata disagrees with section header");
        std::map<std::uint32_t, std::uint32_t> arm64_fields;
        for (std::size_t r = 0; r < rel_count; ++r) {
            const auto at = static_cast<std::size_t>(rel_at) + r * 10;
            const auto type = static_cast<std::uint16_t>(le(b,at+8,2));
            const auto offset=static_cast<std::uint32_t>(le(b,at,4));
            if (machine == machine_arm64 && type == 0) {
                require(offset <= raw_size, "ARM64 COFF ABSOLUTE no-op relocation offset exceeds its section");
                continue;
            }
            const auto idx = static_cast<std::uint32_t>(le(b, at + 4, 4));
            require(idx < symcount && symbol_index[idx] != UINT32_MAX, "COFF relocation references invalid/auxiliary symbol index");
            require(offset<raw_size,"COFF relocation address is outside section raw data");
            if (machine == machine_arm64) {
                const auto width = arm64_relocation_width(type);
                require(!uninitialized && width <= raw_size - offset, "ARM64 COFF relocation field exceeds initialized section data");
                const auto end = static_cast<std::uint32_t>(offset + width);
                const auto next = arm64_fields.lower_bound(offset);
                require((next == arm64_fields.end() || end <= next->first) &&
                        (next == arm64_fields.begin() || std::prev(next)->second <= offset),
                        "ARM64 COFF relocation fields overlap", ErrorCode::unsupported);
                arm64_fields.emplace(offset, end);
            }
            if (s.kind == OutputKind::pdata)
                require(type == 3 && offset % 4 == 0 && offset % 12 <= 8,
                        "AMD64 COFF .pdata relocations must target 32-bit RUNTIME_FUNCTION fields with ADDR32NB",
                        ErrorCode::unsupported);
            s.relocs.push_back({offset,symbol_index[idx],type});
        }
    }
    // Section numbers in object symbols are one-based original COFF section IDs.
    for (const auto &s : o.symbols) {
        require(s.section >= -2 && s.section <= static_cast<std::int32_t>(count), "COFF symbol section is invalid");
        if (s.section > 0)
            require(s.value <= o.sections[static_cast<std::size_t>(s.section - 1)].size,
                    "COFF symbol value exceeds its section extent");
    }
    return o;
}
bool same_relocation_target(const Object& left,std::uint32_t left_index,const Object& right,std::uint32_t right_index){
    if(left_index>=left.symbols.size()||right_index>=right.symbols.size())return false;
    const auto& a=left.symbols[left_index];const auto& b=right.symbols[right_index];
    if(a.name!=b.name||a.storage!=b.storage)return false;
    // External relocations bind by name after COMDAT choice, regardless of
    // the local section-table numbering in the competing input objects.
    if(a.storage==2)return true;
    if(a.value!=b.value)return false;
    if(a.section>0){
        const auto ai=static_cast<std::size_t>(a.section-1),bi=static_cast<std::size_t>(b.section-1);
        return ai<left.sections.size()&&bi<right.sections.size()&&left.sections[ai].name==right.sections[bi].name;
    }
    return a.section==b.section;
}
bool exact_comdat_match(const Object& left,const Section& a,const Object& right,const Section& b){
    if(a.name!=b.name||a.kind!=b.kind||a.characteristics!=b.characteristics||a.size!=b.size||
       a.bytes!=b.bytes||a.relocs.size()!=b.relocs.size())return false;
    for(std::size_t i=0;i<a.relocs.size();++i){
        const auto& x=a.relocs[i];const auto& y=b.relocs[i];
        if(x.offset!=y.offset||x.type!=y.type||!same_relocation_target(left,x.symbol,right,y.symbol))return false;
    }
    return true;
}
void select_comdats(std::vector<Object>& objects,std::stop_token stop){
    struct Candidate{std::size_t object,section;};
    std::map<std::string,std::vector<Candidate>,std::less<>> groups;
    for(std::size_t oi=0;oi<objects.size();++oi){
        auto& object=objects[oi];
        for(std::size_t si=0;si<object.sections.size();++si){
            require(!stop.stop_requested(),"COFF COMDAT selection canceled",ErrorCode::canceled);
            auto& section=object.sections[si];if(!section.comdat)continue;
            section.selected=false;
            if(section.selection==ComdatSelection::associative){
                require(section.associative_parent>0&&section.associative_parent<=object.sections.size(),
                        "COFF associative COMDAT parent section is invalid");
            }else{
                require(section.associative_parent==0,"Non-associative COFF COMDAT has an association parent");
                const auto& key=object.symbols.at(section.comdat_key_symbol);
                groups[key.name].push_back({oi,si});
            }
        }
    }
    for(const auto& [key,candidates]:groups){
        require(!stop.stop_requested(),"COFF COMDAT selection canceled",ErrorCode::canceled);
        require(!candidates.empty(),"Empty COFF COMDAT candidate group");
        const auto selection=objects[candidates.front().object].sections[candidates.front().section].selection;
        for(const auto candidate:candidates)
            require(objects[candidate.object].sections[candidate.section].selection==selection,
                    "Conflicting COMDAT selection modes for key "+key,ErrorCode::unsupported);
        if(selection==ComdatSelection::no_duplicates)
            require(candidates.size()==1,"Duplicate NODUPLICATES COMDAT key: "+key,ErrorCode::unsupported);
        std::size_t winner=0;
        if(selection==ComdatSelection::same_size){
            const auto size=objects[candidates.front().object].sections[candidates.front().section].size;
            for(const auto candidate:candidates)
                require(objects[candidate.object].sections[candidate.section].size==size,
                        "SAME_SIZE COMDAT definitions differ in size: "+key,ErrorCode::unsupported);
        }else if(selection==ComdatSelection::exact_match){
            const auto first=candidates.front();const auto& first_object=objects[first.object];const auto& first_section=first_object.sections[first.section];
            for(const auto candidate:candidates)
                require(exact_comdat_match(first_object,first_section,objects[candidate.object],objects[candidate.object].sections[candidate.section]),
                        "EXACT_MATCH COMDAT definitions differ: "+key,ErrorCode::unsupported);
        }else if(selection==ComdatSelection::largest){
            for(std::size_t i=1;i<candidates.size();++i){
                const auto candidate=candidates[i];
                if(objects[candidate.object].sections[candidate.section].size>
                   objects[candidates[winner].object].sections[candidates[winner].section].size)winner=i;
            }
        }else require(selection==ComdatSelection::any||selection==ComdatSelection::no_duplicates,
                      "Unsupported COFF COMDAT selection mode",ErrorCode::unsupported);
        const auto chosen=candidates[winner];objects[chosen.object].sections[chosen.section].selected=true;
    }
    // Association chains are section-local and bounded by the 96-section COFF
    // header limit. Resolve them with tri-state DFS so cycles and non-COMDAT
    // parents fail before layout or relocation.
    for(auto& object:objects){
        std::vector<std::uint8_t> state(object.sections.size(),0);
        const auto resolve=[&](auto&& self,std::size_t index)->bool{
            auto& section=object.sections[index];
            if(!section.comdat)return true;
            if(section.selection!=ComdatSelection::associative)return section.selected;
            if(state[index]==1)throw Failure{{ErrorCode::unsupported,"COFF associative COMDAT chain contains a cycle"}};
            if(state[index]==2)return section.selected;
            state[index]=1;
            const auto parent=static_cast<std::size_t>(section.associative_parent-1);
            require(object.sections[parent].comdat,"COFF associative COMDAT parent is not COMDAT",ErrorCode::unsupported);
            const bool parent_selected=self(self,parent);
            section.selected=parent_selected;state[index]=2;return section.selected;
        };
        for(std::size_t si=0;si<object.sections.size();++si){
            require(!stop.stop_requested(),"COFF COMDAT selection canceled",ErrorCode::canceled);
            if(object.sections[si].comdat&&object.sections[si].selection==ComdatSelection::associative)(void)resolve(resolve,si);
        }
    }
}
}

namespace {
Result<std::vector<std::byte>> link_coff_executable_impl(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry,
    std::stop_token stop, CoffLinkLimits limits, std::optional<std::uint16_t> required_machine) {
    try {
        require(!inputs.empty() && inputs.size() <= limits.max_objects, "COFF object count is outside configured limits", ErrorCode::resource_limit);
        require(!entry.empty() && limits.max_output_bytes > 0, "COFF link entry and limits must be valid", ErrorCode::invalid_argument);
        std::vector<Object> objects; objects.reserve(inputs.size());
        std::size_t symbols_total = 0, relocs_total = 0;
        std::uint64_t text_size = 0, rdata_size = 0, data_size = 0, pdata_size = 0, xdata_size = 0, bss_size = 0;
        bool has_rdata = false, has_pdata = false, has_xdata = false, has_bss = false;
        std::optional<std::uint16_t> selected_machine = required_machine;
        std::uint64_t maximum_alignment = 1;
        std::map<std::string, std::uint64_t, std::less<>> definitions;
        struct Common { std::uint32_t size=0; std::uint32_t alignment=1; std::uint64_t offset=0; };
        std::map<std::string, Common, std::less<>> common_symbols;
        std::set<std::string, std::less<>> strong_names;
        std::set<std::string, std::less<>> absolute_names;
        struct Pending { std::size_t object, section; Reloc relocation; };
        std::vector<Pending> pending;
        std::map<std::string, ImportObject, std::less<>> imports_by_iat;
        std::map<std::string, std::string, std::less<>> function_imports;
        for (const auto &input : inputs) {
            require(input != nullptr, "COFF link input is null", ErrorCode::invalid_argument);
            auto object = parse(*input, stop, symbols_total, relocs_total, limits);
            if (!selected_machine) selected_machine = object.machine;
            require(object.machine == *selected_machine, "COFF link inputs have mixed or unexpected machine architectures", ErrorCode::unsupported);
            objects.push_back(std::move(object));
        }
        const bool arm64 = *selected_machine == machine_arm64;
        select_comdats(objects,stop);
        for (const auto &object : objects) for (const auto &import : object.imports) {
            require(!stop.stop_requested(), "COFF import collection canceled", ErrorCode::canceled);
            const auto iat_name = "__imp_" + import.public_name;
            require(iat_name.size() <= max_coff_name_bytes,
                    "COFF import address symbol exceeds limit", ErrorCode::resource_limit);
            const auto [found, inserted] = imports_by_iat.emplace(iat_name, import);
            require(inserted || (found->second.public_name == import.public_name &&
                        found->second.lookup_name == import.lookup_name && found->second.dll_name == import.dll_name &&
                        found->second.type == import.type && found->second.ordinal_or_hint == import.ordinal_or_hint &&
                        found->second.by_ordinal == import.by_ordinal),
                    "Conflicting COFF import objects define " + iat_name, ErrorCode::unsupported);
            if (import.type == 0) {
                const auto [public_entry, public_inserted] = function_imports.emplace(import.public_name, iat_name);
                require(public_inserted || public_entry->second == iat_name,
                        "Conflicting COFF function import symbols", ErrorCode::unsupported);
            }
        }
        // In COFF, an external with section number zero and nonzero value is
        // a common allocation; its value is the requested byte size. MSVC
        // aligns small commons to their next power of two, capped at 32.
        for (const auto& object : objects) for (const auto& symbol : object.symbols) {
            require(!stop.stop_requested(), "COFF common-symbol scan canceled", ErrorCode::canceled);
            if (symbol.storage != 2) continue;
            if (symbol.section == -1) {
                absolute_names.insert(symbol.name);
                continue;
            }
            if (symbol.section > 0) {
                if (object.sections[static_cast<std::size_t>(symbol.section - 1)].selected)
                    strong_names.insert(symbol.name);
                continue;
            }
            if (symbol.section != 0 || symbol.value == 0) continue;
            require(!symbol.name.empty(), "COFF common symbol has no name", ErrorCode::malformed);
            std::uint32_t alignment = 1;
            while (alignment < 32 && alignment < symbol.value) alignment <<= 1;
            auto [found, inserted] = common_symbols.emplace(symbol.name,
                Common{symbol.value, alignment, 0});
            if (!inserted) {
                found->second.size = std::max(found->second.size, symbol.value);
                found->second.alignment = std::max(found->second.alignment, alignment);
            }
        }
        for(std::size_t oi=0;oi<objects.size();++oi){
            auto& o=objects[oi];
            for (auto &s : o.sections) {
                if(!s.selected)continue;
                has_rdata |= s.kind == OutputKind::rdata;
                has_pdata |= s.kind == OutputKind::pdata;
                has_xdata |= s.kind == OutputKind::xdata;
                has_bss |= s.kind == OutputKind::bss;
                const auto align_code = (s.characteristics >> 20) & 0xf;
                require(align_code <= 14, "COFF section uses a reserved alignment code", ErrorCode::unsupported);
                const std::uint64_t a = std::max(align_code ? (UINT64_C(1) << (align_code - 1)) : UINT64_C(1),
                    arm64 && s.kind == OutputKind::text ? UINT64_C(4) : UINT64_C(1));
                maximum_alignment = std::max(maximum_alignment, a);
                if (s.kind == OutputKind::pdata)
                    require(a <= 4, "COFF .pdata contribution alignment cannot exceed DWORD alignment", ErrorCode::unsupported);
                auto &output_size = s.kind == OutputKind::text ? text_size :
                    s.kind == OutputKind::rdata ? rdata_size :
                    s.kind == OutputKind::data ? data_size :
                    s.kind == OutputKind::pdata ? pdata_size :
                    s.kind == OutputKind::xdata ? xdata_size : bss_size;
                output_size = align(output_size, a);
                s.out = output_size;
                require(output_size <= limits.max_output_bytes, "COFF output section alignment exceeds limit", ErrorCode::resource_limit);
                require(s.size <= limits.max_output_bytes - output_size, "COFF output section exceeds limit", ErrorCode::resource_limit);
                output_size += s.size;
            }
            for (std::size_t si=0;si<o.sections.size();++si)if(o.sections[si].selected)
                for (const auto &r : o.sections[si].relocs) {
                    require(o.sections[si].kind!=OutputKind::bss,"Relocations in selected COFF .bss are not supported",ErrorCode::unsupported);
                    const auto &target = o.symbols[r.symbol];
                    require(target.section <= 0 || o.sections[static_cast<std::size_t>(target.section - 1)].kind != OutputKind::pdata,
                            "COFF relocations to symbols inside sorted .pdata are unsupported", ErrorCode::unsupported);
                    pending.push_back({oi,si,r});
                }
        }
        for (auto& [name, common] : common_symbols) {
            require(!stop.stop_requested(), "COFF common-symbol layout canceled", ErrorCode::canceled);
            require(!absolute_names.contains(name),
                    "COFF common symbol conflicts with an unsupported absolute definition: " + name,
                    ErrorCode::unsupported);
            if (strong_names.contains(name)) continue;
            bss_size = align(bss_size, common.alignment);
            require(bss_size <= limits.max_output_bytes &&
                    common.size <= limits.max_output_bytes - bss_size,
                    "Combined COFF common symbols exceed output limit", ErrorCode::resource_limit);
            common.offset = bss_size;
            bss_size += common.size;
            has_bss = true;
        }
        struct ImportGroup {
            std::string dll;
            std::vector<std::string> symbols;
            std::uint64_t descriptor = 0, ilt = 0, iat = 0, dll_name = 0;
        };
        std::map<std::string, std::vector<std::string>, std::less<>> grouped_imports;
        for (const auto &[iat_name, import] : imports_by_iat)
            grouped_imports[import.dll_name].push_back(iat_name);
        std::vector<ImportGroup> import_groups;
        import_groups.reserve(grouped_imports.size());
        for (auto &[dll, names] : grouped_imports)
            import_groups.push_back({dll, std::move(names)});
        const bool has_idata = !import_groups.empty();
        std::uint64_t idata_size = 0, import_descriptor_size = 0, import_iat_offset = 0, import_iat_size = 0;
        std::map<std::string, std::uint64_t, std::less<>> import_iat_offsets, import_name_offsets;
        const auto add_extent = [](std::uint64_t value, std::uint64_t amount, const char *message) {
            require(value <= UINT64_MAX - amount, message, ErrorCode::resource_limit);
            return value + amount;
        };
        if (has_idata) {
            require(import_groups.size() < UINT64_MAX / 20, "PE import descriptor count overflows", ErrorCode::resource_limit);
            import_descriptor_size = (import_groups.size() + 1) * 20;
            std::uint64_t cursor = import_descriptor_size;
            for (std::size_t i = 0; i < import_groups.size(); ++i) {
                auto &group = import_groups[i];
                group.descriptor = i * 20;
                group.ilt = cursor;
                const auto slots = static_cast<std::uint64_t>(group.symbols.size()) + 1;
                require(slots <= UINT64_MAX / 8, "PE import lookup table size overflows", ErrorCode::resource_limit);
                cursor = add_extent(cursor, slots * 8, "PE import lookup table size overflows");
            }
            import_iat_offset = cursor;
            for (auto &group : import_groups) {
                group.iat = cursor;
                const auto slots = static_cast<std::uint64_t>(group.symbols.size()) + 1;
                require(slots <= UINT64_MAX / 8, "PE import address table size overflows", ErrorCode::resource_limit);
                for (std::size_t i = 0; i < group.symbols.size(); ++i)
                    import_iat_offsets.emplace(group.symbols[i], cursor + i * 8);
                cursor = add_extent(cursor, slots * 8, "PE import address table size overflows");
            }
            import_iat_size = cursor - import_iat_offset;
            for (const auto &[iat_name, import] : imports_by_iat) {
                if (import.by_ordinal) continue;
                cursor = align(cursor, 2);
                import_name_offsets.emplace(iat_name, cursor);
                cursor = add_extent(cursor, 2 + import.lookup_name.size() + 1, "PE import name data size overflows");
            }
            for (auto &group : import_groups) {
                group.dll_name = cursor;
                cursor = add_extent(cursor, group.dll.size() + 1, "PE import DLL name data size overflows");
            }
            idata_size = cursor;
            require(idata_size <= limits.max_output_bytes, "PE import data exceeds configured output limit", ErrorCode::resource_limit);
        }
        std::map<std::string, std::uint64_t, std::less<>> import_thunk_offsets;
        for (const auto &[public_name, iat_name] : function_imports) {
            if (strong_names.contains(public_name)) continue;
            require(!common_symbols.contains(public_name),
                    "COFF function import conflicts with a common symbol: " + public_name, ErrorCode::unsupported);
            require(text_size <= limits.max_output_bytes && 6 <= limits.max_output_bytes - text_size,
                    "COFF import thunk code exceeds configured output limit", ErrorCode::resource_limit);
            import_thunk_offsets.emplace(public_name, text_size);
            text_size += 6;
        }
        require(!has_pdata || (has_xdata && text_size != 0),
                "AMD64 COFF .pdata requires .text and .xdata contributions", ErrorCode::unsupported);
        require(!has_pdata || pdata_size % 12 == 0,
                "Merged AMD64 COFF .pdata has a partial RUNTIME_FUNCTION record");
        constexpr std::uint64_t image_base = UINT64_C(0x140000000);
        const std::uint64_t section_alignment = arm64 ? std::max(UINT64_C(0x1000), maximum_alignment) : UINT64_C(0x1000);
        constexpr std::uint64_t file_alignment = 0x200;
        const auto section_count = 2 + (has_rdata ? 1 : 0) + (has_pdata ? 1 : 0) + (has_xdata ? 1 : 0) + (has_bss ? 1 : 0) + (has_idata ? 1 : 0);
        const auto header_size = align(UINT64_C(0x1b0) + section_count * 40, file_alignment);
        const auto text_raw_size = align(text_size, file_alignment);
        const auto text_rva = section_alignment;
        const auto after_text = text_rva + std::max(text_size, UINT64_C(1));
        const auto rdata_rva = has_rdata ? align(after_text, section_alignment) : 0;
        const auto data_rva = align(has_rdata ? rdata_rva + std::max(rdata_size, UINT64_C(1)) : after_text,
                                    section_alignment);
        const auto pdata_rva = has_pdata ? align(data_rva + std::max(data_size, UINT64_C(1)), section_alignment) : 0;
        const auto after_pdata = has_pdata ? pdata_rva + std::max(pdata_size, UINT64_C(1)) :
            data_rva + std::max(data_size, UINT64_C(1));
        const auto xdata_rva = has_xdata ? align(after_pdata, section_alignment) : 0;
        const auto after_xdata = has_xdata ? xdata_rva + std::max(xdata_size, UINT64_C(1)) : after_pdata;
        const auto bss_rva = align(after_xdata, section_alignment);
        const auto idata_rva = has_idata ? align(has_bss ? bss_rva + std::max(bss_size, UINT64_C(1)) : after_xdata,
                                                 section_alignment) : 0;
        const auto rdata_raw_size = has_rdata ? align(rdata_size, file_alignment) : 0;
        const auto data_raw_size = align(data_size, file_alignment);
        const auto pdata_raw_size = has_pdata ? align(pdata_size, file_alignment) : 0;
        const auto xdata_raw_size = has_xdata ? align(xdata_size, file_alignment) : 0;
        const auto idata_raw_size = has_idata ? align(idata_size, file_alignment) : 0;
        require(text_size <= UINT32_MAX && rdata_size <= UINT32_MAX && data_size <= UINT32_MAX &&
                pdata_size <= UINT32_MAX && xdata_size <= UINT32_MAX && bss_size <= UINT32_MAX &&
                idata_size <= UINT32_MAX,
                "COFF output section exceeds PE32+ section size", ErrorCode::resource_limit);
        require(image_base <= UINT64_MAX - bss_rva && bss_size <= UINT64_MAX - image_base - bss_rva,
                "PE image address overflows", ErrorCode::resource_limit);
        std::vector<std::byte> text(static_cast<std::size_t>(text_size), std::byte{0});
        std::vector<std::byte> rdata(static_cast<std::size_t>(rdata_size), std::byte{0});
        std::vector<std::byte> data(static_cast<std::size_t>(data_size), std::byte{0});
        std::vector<std::byte> pdata(static_cast<std::size_t>(pdata_size), std::byte{0});
        std::vector<std::byte> xdata(static_cast<std::size_t>(xdata_size), std::byte{0});
        for (const auto &o : objects) for (const auto &s : o.sections) {
            if (!s.selected||s.kind == OutputKind::bss) continue;
            auto &out = s.kind == OutputKind::text ? text :
                        s.kind == OutputKind::rdata ? rdata :
                        s.kind == OutputKind::data ? data :
                        s.kind == OutputKind::pdata ? pdata : xdata;
            std::copy(s.bytes.begin(), s.bytes.end(), out.begin() + static_cast<std::ptrdiff_t>(s.out));
        }
        std::vector<std::byte> idata(static_cast<std::size_t>(idata_size), std::byte{0});
        if (has_idata) {
            for (const auto &group : import_groups) {
                const auto directory_offset = static_cast<std::size_t>(group.descriptor);
                put(idata, directory_offset, idata_rva + group.ilt, 4);
                put(idata, directory_offset + 12, idata_rva + group.dll_name, 4);
                put(idata, directory_offset + 16, idata_rva + group.iat, 4);
                for (std::size_t i = 0; i < group.symbols.size(); ++i) {
                    const auto &iat_name = group.symbols[i];
                    const auto &import = imports_by_iat.at(iat_name);
                    std::uint64_t value = 0;
                    if (import.by_ordinal)
                        value = UINT64_C(0x8000000000000000) | import.ordinal_or_hint;
                    else {
                        const auto name = import_name_offsets.at(iat_name);
                        value = idata_rva + name;
                        put(idata, static_cast<std::size_t>(name), import.ordinal_or_hint, 2);
                        std::memcpy(idata.data() + static_cast<std::ptrdiff_t>(name + 2),
                                    import.lookup_name.data(), import.lookup_name.size());
                    }
                    put(idata, static_cast<std::size_t>(group.ilt + i * 8), value, 8);
                    put(idata, static_cast<std::size_t>(group.iat + i * 8), value, 8);
                }
                std::memcpy(idata.data() + static_cast<std::ptrdiff_t>(group.dll_name),
                            group.dll.data(), group.dll.size());
            }
        }
        std::map<std::string, std::uint64_t, std::less<>> import_iat_addresses;
        for (const auto &[iat_name, import] : imports_by_iat) {
            (void)import;
            const auto offset = import_iat_offsets.at(iat_name);
            import_iat_addresses.emplace(iat_name, image_base + idata_rva + offset);
        }
        std::map<std::string, std::uint64_t, std::less<>> import_function_addresses;
        for (const auto &[public_name, text_offset] : import_thunk_offsets) {
            const auto iat_name = function_imports.at(public_name);
            const auto thunk_va = image_base + text_rva + text_offset;
            const auto iat_va = import_iat_addresses.at(iat_name);
            const auto displacement = static_cast<std::int64_t>(iat_va) - static_cast<std::int64_t>(thunk_va + 6);
            require(displacement >= INT32_MIN && displacement <= INT32_MAX,
                    "AMD64 import thunk cannot reach its IAT slot", ErrorCode::unsupported);
            const auto offset = static_cast<std::size_t>(text_offset);
            require(offset <= text.size() && 6 <= text.size() - offset,
                    "AMD64 import thunk exceeds output .text", ErrorCode::resource_limit);
            text[offset] = std::byte{0xff};
            text[offset + 1] = std::byte{0x25};
            put(text, offset + 2, static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement)), 4);
            import_function_addresses.emplace(public_name, thunk_va);
        }
        const auto section_va = [&](std::size_t oi, std::int32_t sn) -> std::uint64_t {
            require(sn > 0 && static_cast<std::size_t>(sn) <= objects[oi].sections.size(), "COFF relocation references unsupported absolute or undefined symbol", ErrorCode::unsupported);
            const auto &s = objects[oi].sections[static_cast<std::size_t>(sn - 1)];
            require(s.selected,"COFF symbol refers to a discarded section and has no selected provider",ErrorCode::unsupported);
            const auto rva = s.kind == OutputKind::text ? text_rva :
                s.kind == OutputKind::rdata ? rdata_rva :
                s.kind == OutputKind::data ? data_rva :
                s.kind == OutputKind::pdata ? pdata_rva :
                s.kind == OutputKind::xdata ? xdata_rva : bss_rva;
            return image_base + rva + s.out;
        };
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            const auto &o = objects[oi];
            for (const auto &sym : o.symbols) {
                if (sym.storage != 2 || sym.section <= 0 || !o.sections[static_cast<std::size_t>(sym.section-1)].selected) continue;
                const auto value = section_va(oi, sym.section) + sym.value;
                require(definitions.emplace(sym.name, value).second, "Duplicate COFF definition: " + sym.name, ErrorCode::unsupported);
            }
        }
        for (const auto& [name, common] : common_symbols) {
            if (strong_names.contains(name)) continue;
            const auto address = image_base + bss_rva + common.offset;
            require(definitions.emplace(name, address).second,
                    "COFF common symbol conflicts with a selected definition: " + name, ErrorCode::unsupported);
        }
        for (const auto &[name, address] : import_iat_addresses)
            require(definitions.emplace(name, address).second,
                    "COFF import address symbol conflicts with another definition: " + name, ErrorCode::unsupported);
        for (const auto &[name, address] : import_function_addresses)
            require(definitions.emplace(name, address).second,
                    "COFF imported function conflicts with another definition: " + name, ErrorCode::unsupported);
        const auto entry_it = definitions.find(entry);
        require(entry_it != definitions.end(), "COFF executable entry symbol is undefined: " + std::string(entry), ErrorCode::unsupported);
        bool entry_is_code = false;
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            for (const auto &sym : objects[oi].symbols) {
                if (sym.storage != 2 || sym.section <= 0 || sym.name != entry || !objects[oi].sections[static_cast<std::size_t>(sym.section-1)].selected) continue;
                const auto &section = objects[oi].sections[static_cast<std::size_t>(sym.section - 1)];
                entry_is_code = section.kind == OutputKind::text && sym.value < section.size &&
                    (!arm64 || ((entry_it->second & 3) == 0 && section.size - sym.value >= 4));
                break;
            }
            if (entry_is_code) break;
        }
        if (!entry_is_code)
            entry_is_code = import_function_addresses.contains(std::string(entry));
        require(entry_is_code, "COFF executable entry must name a byte inside an initialized .text section", ErrorCode::unsupported);
        for (const auto &p : pending) {
            require(!stop.stop_requested(), "COFF link canceled", ErrorCode::canceled);
            auto &obj = objects[p.object]; auto &section = obj.sections[p.section];
            require(section.name != ".bss", "Relocations in output .bss are not supported", ErrorCode::unsupported);
            const auto &sym = obj.symbols[p.relocation.symbol];
            std::uint64_t target = 0;
            if (sym.section > 0 && objects[p.object].sections[static_cast<std::size_t>(sym.section-1)].selected)
                target = section_va(p.object, sym.section) + sym.value;
            else if(sym.section>0&&sym.storage==2){
                const auto found=definitions.find(sym.name);
                require(found!=definitions.end(),"Discarded COMDAT symbol has no selected provider: "+sym.name,ErrorCode::unsupported);
                target=found->second;
            }
            else if (sym.section == 0) {
                const auto found = definitions.find(sym.name);
                require(found != definitions.end(), "Unresolved strong COFF symbol " + sym.name, ErrorCode::unsupported);
                target = found->second;
            } else throw Failure{{ErrorCode::unsupported, "COFF absolute symbols are not supported"}};
            require(section.kind != OutputKind::bss, "Relocations in output .bss are not supported", ErrorCode::unsupported);
            auto &dst = section.kind == OutputKind::text ? text :
                        section.kind == OutputKind::rdata ? rdata :
                        section.kind == OutputKind::data ? data :
                        section.kind == OutputKind::pdata ? pdata : xdata;
            const auto place_offset = section.out + p.relocation.offset;
            const auto place_rva = section.kind == OutputKind::text ? text_rva :
                section.kind == OutputKind::rdata ? rdata_rva :
                section.kind == OutputKind::data ? data_rva :
                section.kind == OutputKind::pdata ? pdata_rva : xdata_rva;
            const auto place_va = image_base + place_rva + place_offset;
            const auto type = p.relocation.type;
            if (arm64) {
                const auto width = arm64_relocation_width(type);
                require(p.relocation.offset <= section.bytes.size() && width <= section.bytes.size() - p.relocation.offset,
                        "ARM64 COFF relocation field exceeds section extent");
                apply_arm64_relocation(dst, static_cast<std::size_t>(place_offset), type, target, place_va, image_base,
                                        image_base + text_rva, text_size, section.kind == OutputKind::text);
                continue;
            }
            const std::size_t width = type == 1 ? 8 : (type >= 2 && type <= 10 ? 4 : 0);
            require(width != 0, "Unsupported AMD64 COFF relocation type " + std::to_string(type), ErrorCode::unsupported);
            require(p.relocation.offset <= section.bytes.size() && width <= section.bytes.size() - p.relocation.offset,
                    "COFF relocation field exceeds section extent");
            const auto field = static_cast<std::size_t>(place_offset);
            if (type == 1) {
                const auto addend = static_cast<std::int64_t>(le(dst, field, 8));
                std::uint64_t value = target;
                if (addend >= 0) {
                    require(value <= UINT64_MAX - static_cast<std::uint64_t>(addend), "COFF ADDR64 relocation overflows", ErrorCode::unsupported);
                    value += static_cast<std::uint64_t>(addend);
                } else {
                    const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
                    require(value >= magnitude, "COFF ADDR64 relocation underflows", ErrorCode::unsupported);
                    value -= magnitude;
                }
                put(dst, field, value, 8);
            } else if (type == 2 || type == 3) {
                const auto addend = static_cast<std::int32_t>(le(dst, field, 4));
                const auto value = static_cast<std::int64_t>(target) + addend -
                    (type == 3 ? static_cast<std::int64_t>(image_base) : 0);
                require(value >= 0 && static_cast<std::uint64_t>(value) <= UINT32_MAX, "COFF ADDR32 relocation overflows", ErrorCode::unsupported);
                put(dst, field, static_cast<std::uint32_t>(value), 4);
            } else {
                const auto addend = static_cast<std::int32_t>(le(dst, field, 4));
                const auto extra = static_cast<std::int64_t>(type - 4);
                const auto value = static_cast<std::int64_t>(target) + addend - static_cast<std::int64_t>(place_va) - 4 - extra;
                require(value >= INT32_MIN && value <= INT32_MAX, "COFF REL32 relocation overflows", ErrorCode::unsupported);
                put(dst, field, static_cast<std::uint32_t>(static_cast<std::int32_t>(value)), 4);
            }
        }
        if (has_pdata) {
            require(pdata.size() / 12 <= limits.max_runtime_functions,
                    "AMD64 COFF runtime-function limit exceeded", ErrorCode::resource_limit);
            std::vector<std::array<std::byte, 12>> functions;
            functions.reserve(pdata.size() / 12);
            std::set<std::array<std::byte, 12>> chained_functions;
            std::set<std::uint32_t> validating_unwind;
            std::set<std::uint32_t> validated_unwind;
            const auto validate_unwind = [&](auto &&self, std::uint32_t unwind_rva, std::size_t depth) -> void {
                require(!stop.stop_requested(), "COFF unwind validation canceled", ErrorCode::canceled);
                require(depth < 32, "AMD64 chained UNWIND_INFO depth limit exceeded", ErrorCode::resource_limit);
                require(unwind_rva && (unwind_rva & 3u) == 0 && unwind_rva >= xdata_rva &&
                            unwind_rva < xdata_rva + xdata_size,
                        "AMD64 UNWIND_INFO RVA is outside or misaligned in linked .xdata");
                if (validated_unwind.contains(unwind_rva)) return;
                require(validating_unwind.insert(unwind_rva).second,
                        "AMD64 chained UNWIND_INFO contains a cycle");
                const auto info_offset = static_cast<std::size_t>(unwind_rva - xdata_rva);
                require(info_offset <= xdata.size() && xdata.size() - info_offset >= 4,
                        "Truncated AMD64 UNWIND_INFO header");
                const auto version_flags = std::to_integer<std::uint8_t>(xdata[info_offset]);
                const auto version = version_flags & 7u;
                const auto flags = version_flags >> 3;
                const auto code_count = std::to_integer<std::uint8_t>(xdata[info_offset + 2]);
                require(version == 1 && (flags & ~7u) == 0 && ((flags & 4u) == 0 || (flags & 3u) == 0),
                        "Unsupported or malformed AMD64 UNWIND_INFO header", ErrorCode::unsupported);
                const auto tail = static_cast<std::uint64_t>(info_offset) + 4 +
                    static_cast<std::uint64_t>(code_count + (code_count & 1u)) * 2;
                const auto extra = (flags & 4u) ? 12u : ((flags & 3u) ? 4u : 0u);
                require(tail <= xdata.size() && extra <= xdata.size() - static_cast<std::size_t>(tail),
                        "AMD64 UNWIND_INFO code or handler tail exceeds linked .xdata");
                if (flags & 3u) {
                    const auto handler = static_cast<std::uint32_t>(le(xdata, static_cast<std::size_t>(tail), 4));
                    require(handler >= text_rva && handler < text_rva + text_size,
                            "AMD64 UNWIND_INFO handler RVA is outside linked .text");
                }
                if (flags & 4u) {
                    const auto chain_begin = static_cast<std::uint32_t>(le(xdata, static_cast<std::size_t>(tail), 4));
                    const auto chain_end = static_cast<std::uint32_t>(le(xdata, static_cast<std::size_t>(tail + 4), 4));
                    const auto chain_unwind = static_cast<std::uint32_t>(le(xdata, static_cast<std::size_t>(tail + 8), 4));
                    require(chain_begin >= text_rva && chain_begin < chain_end && chain_end <= text_rva + text_size,
                            "AMD64 chained RUNTIME_FUNCTION range is outside linked .text");
                    std::array<std::byte, 12> chained_function{};
                    std::copy_n(xdata.begin() + static_cast<std::ptrdiff_t>(tail), 12, chained_function.begin());
                    chained_functions.insert(chained_function);
                    self(self, chain_unwind, depth + 1);
                }
                validating_unwind.erase(unwind_rva);
                validated_unwind.insert(unwind_rva);
            };
            for (std::size_t offset = 0; offset < pdata.size(); offset += 12) {
                if ((offset & 0x3ffffu) == 0)
                    require(!stop.stop_requested(), "COFF runtime-function validation canceled", ErrorCode::canceled);
                const auto begin = static_cast<std::uint32_t>(le(pdata, offset, 4));
                const auto end = static_cast<std::uint32_t>(le(pdata, offset + 4, 4));
                const auto unwind = static_cast<std::uint32_t>(le(pdata, offset + 8, 4));
                require(begin >= text_rva && begin < end && end <= text_rva + text_size,
                        "AMD64 RUNTIME_FUNCTION range is outside linked .text");
                validate_unwind(validate_unwind, unwind, 0);
                std::array<std::byte, 12> function{};
                std::copy_n(pdata.begin() + static_cast<std::ptrdiff_t>(offset), 12, function.begin());
                functions.push_back(function);
            }
            std::set<std::array<std::byte, 12>> function_table;
            function_table.insert(functions.begin(), functions.end());
            for (const auto &chained_function : chained_functions)
                require(function_table.contains(chained_function),
                        "AMD64 chained UNWIND_INFO does not copy a linked RUNTIME_FUNCTION record");
            std::sort(functions.begin(), functions.end(), [](const auto &left, const auto &right) {
                const auto begin = [](const auto &record) {
                    return std::uint32_t(std::to_integer<std::uint8_t>(record[0])) |
                           (std::uint32_t(std::to_integer<std::uint8_t>(record[1])) << 8) |
                           (std::uint32_t(std::to_integer<std::uint8_t>(record[2])) << 16) |
                           (std::uint32_t(std::to_integer<std::uint8_t>(record[3])) << 24);
                };
                return begin(left) < begin(right);
            });
            std::uint32_t previous_end = 0;
            for (std::size_t index = 0; index < functions.size(); ++index) {
                const auto begin = std::uint32_t(std::to_integer<std::uint8_t>(functions[index][0])) |
                    (std::uint32_t(std::to_integer<std::uint8_t>(functions[index][1])) << 8) |
                    (std::uint32_t(std::to_integer<std::uint8_t>(functions[index][2])) << 16) |
                    (std::uint32_t(std::to_integer<std::uint8_t>(functions[index][3])) << 24);
                const auto end = std::uint32_t(std::to_integer<std::uint8_t>(functions[index][4])) |
                    (std::uint32_t(std::to_integer<std::uint8_t>(functions[index][5])) << 8) |
                    (std::uint32_t(std::to_integer<std::uint8_t>(functions[index][6])) << 16) |
                    (std::uint32_t(std::to_integer<std::uint8_t>(functions[index][7])) << 24);
                require(index == 0 || begin >= previous_end,
                        "AMD64 RUNTIME_FUNCTION entries overlap");
                previous_end = end;
                std::copy(functions[index].begin(), functions[index].end(),
                          pdata.begin() + static_cast<std::ptrdiff_t>(index * 12));
            }
        }
        const auto text_raw = header_size;
        const auto rdata_raw = text_raw + text_raw_size;
        const auto data_raw = rdata_raw + rdata_raw_size;
        const auto pdata_raw = data_raw + data_raw_size;
        const auto xdata_raw = pdata_raw + pdata_raw_size;
        const auto idata_raw = xdata_raw + xdata_raw_size;
        const auto file_size = idata_raw + idata_raw_size;
        require(file_size <= limits.max_output_bytes && file_size <= SIZE_MAX, "PE output exceeds configured limit", ErrorCode::resource_limit);
        std::vector<std::byte> out(static_cast<std::size_t>(file_size), std::byte{0});
        out[0] = std::byte{'M'}; out[1] = std::byte{'Z'}; put(out, 0x3c, 0x80, 4);
        put(out, 0x80, 0x00004550, 4); put(out, 0x84, *selected_machine, 2); put(out, 0x86, section_count, 2);
        put(out, 0x94, 240, 2); put(out, 0x96, arm64 ? 0x0023 : 0x0003, 2);
        const std::size_t op = 0x98;
        put(out, op, 0x20b, 2); put(out, op + 2, 14, 1); put(out, op + 4, text_raw_size, 4);
        put(out, op + 8, rdata_raw_size + data_raw_size + pdata_raw_size + xdata_raw_size + idata_raw_size, 4);
        put(out, op + 12, bss_size, 4);
        put(out, op + 16, static_cast<std::uint32_t>(entry_it->second - image_base), 4);
        put(out, op + 20, text_rva, 4); put(out, op + 24, image_base, 8);
        put(out, op + 32, section_alignment, 4); put(out, op + 36, file_alignment, 4);
        put(out, op + 40, arm64 ? 10 : 6, 2); put(out, op + 48, arm64 ? 10 : 6, 2);
        put(out, op + 60, header_size, 4);
        const auto image_end = has_idata ? idata_rva + std::max(idata_size, UINT64_C(1)) :
            has_bss ? bss_rva + std::max(bss_size, UINT64_C(1)) :
            has_xdata ? xdata_rva + std::max(xdata_size, UINT64_C(1)) :
            has_pdata ? pdata_rva + std::max(pdata_size, UINT64_C(1)) :
            data_rva + std::max(data_size, UINT64_C(1));
        const auto image_size = align(image_end, section_alignment);
        require(image_size <= UINT32_MAX, "PE image size exceeds PE32+ header field", ErrorCode::resource_limit);
        put(out, op + 56, image_size, 4); // SizeOfImage; +64 is the checksum.
        put(out, op + 68, 3, 2); put(out, op + 72, 0x100000, 8); put(out, op + 80, 0x1000, 8);
        put(out, op + 88, 0x100000, 8); put(out, op + 96, 0x1000, 8); put(out, op + 108, 16, 4);
        if (has_pdata) {
            put(out, op + 112 + 3 * 8, pdata_rva, 4);
            put(out, op + 112 + 3 * 8 + 4, pdata_size, 4);
        }
        if (has_idata) {
            put(out, op + 112 + 1 * 8, idata_rva, 4);
            put(out, op + 112 + 1 * 8 + 4, import_descriptor_size, 4);
            put(out, op + 112 + 12 * 8, idata_rva + import_iat_offset, 4);
            put(out, op + 112 + 12 * 8 + 4, import_iat_size, 4);
        }
        const auto sh = op + 240;
        const auto write_section = [&](std::size_t at, const char *name, std::uint64_t virtual_size, std::uint64_t rva,
                                       std::uint64_t raw_size, std::uint64_t raw, std::uint32_t flags) {
            std::memcpy(out.data() + at, name, std::strlen(name)); put(out, at + 8, virtual_size, 4); put(out, at + 12, rva, 4);
            put(out, at + 16, raw_size, 4); put(out, at + 20, raw_size ? raw : 0, 4); put(out, at + 36, flags, 4);
        };
        write_section(sh, ".text", text.size(), text_rva, text_raw_size, text_raw, 0x60000020);
        auto next_section = sh + 40;
        if (has_rdata) {
            write_section(next_section, ".rdata", rdata.size(), rdata_rva, rdata_raw_size, rdata_raw, 0x40000040);
            next_section += 40;
        }
        write_section(next_section, ".data", data.size(), data_rva, data_raw_size, data_raw, 0xc0000040);
        next_section += 40;
        if (has_pdata) {
            write_section(next_section, ".pdata", pdata.size(), pdata_rva, pdata_raw_size, pdata_raw, 0x40000040);
            next_section += 40;
        }
        if (has_xdata) {
            write_section(next_section, ".xdata", xdata.size(), xdata_rva, xdata_raw_size, xdata_raw, 0x40000040);
            next_section += 40;
        }
        if (has_bss) {
            write_section(next_section, ".bss", bss_size, bss_rva, 0, 0, 0xc0000080);
            next_section += 40;
        }
        if (has_idata) {
            write_section(next_section, ".idata", idata.size(), idata_rva, idata_raw_size, idata_raw, 0xc0000040);
            next_section += 40;
        }
        if (!text.empty()) std::copy(text.begin(), text.end(), out.begin() + static_cast<std::ptrdiff_t>(text_raw));
        if (!rdata.empty()) std::copy(rdata.begin(), rdata.end(), out.begin() + static_cast<std::ptrdiff_t>(rdata_raw));
        if (!data.empty()) std::copy(data.begin(), data.end(), out.begin() + static_cast<std::ptrdiff_t>(data_raw));
        if (!pdata.empty()) std::copy(pdata.begin(), pdata.end(), out.begin() + static_cast<std::ptrdiff_t>(pdata_raw));
        if (!xdata.empty()) std::copy(xdata.begin(), xdata.end(), out.begin() + static_cast<std::ptrdiff_t>(xdata_raw));
        if (!idata.empty()) std::copy(idata.begin(), idata.end(), out.begin() + static_cast<std::ptrdiff_t>(idata_raw));
        return out;
    } catch (const Failure &f) { return f.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate COFF executable link output"}; }
}
} // namespace

Result<std::vector<std::byte>> link_coff_executable(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry,
    std::stop_token stop, CoffLinkLimits limits) {
    return link_coff_executable_impl(inputs, entry, stop, limits, {});
}

Result<std::vector<std::byte>> link_coff_amd64_executable(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry,
    std::stop_token stop, CoffLinkLimits limits) {
    return link_coff_executable_impl(inputs, entry, stop, limits, machine_amd64);
}
} // namespace hexlab
