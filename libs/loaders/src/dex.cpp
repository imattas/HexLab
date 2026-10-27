#include "hexlab/loaders/dex.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hexlab {
namespace {
constexpr std::uint64_t max_file_size = UINT64_C(512) * 1024 * 1024;
constexpr std::uint32_t max_items = 1'000'000;
constexpr std::uint32_t header_bytes = 0x70;
constexpr std::uint32_t dex041_header_bytes = 0x78;

struct Reader {
    std::span<const std::byte> bytes;
    std::size_t pos = 0;
    bool u16(std::uint16_t &v) {
        if (bytes.size() - pos < 2) return false;
        v = std::to_integer<std::uint8_t>(bytes[pos]) |
            (std::uint16_t(std::to_integer<std::uint8_t>(bytes[pos + 1])) << 8);
        pos += 2; return true;
    }
    bool u32(std::uint32_t &v) {
        if (bytes.size() - pos < 4) return false;
        v = 0;
        for (unsigned i = 0; i < 4; ++i) v |= std::uint32_t(std::to_integer<std::uint8_t>(bytes[pos + i])) << (8 * i);
        pos += 4; return true;
    }
    bool uleb(std::uint32_t &v) {
        v = 0;
        for (unsigned i = 0; i < 5; ++i) {
            if (pos >= bytes.size()) return false;
            const auto b = std::to_integer<std::uint8_t>(bytes[pos++]);
            if (i == 4 && (b & 0xf0)) return false;
            v |= std::uint32_t(b & 0x7f) << (7 * i);
            if (!(b & 0x80)) return true;
        }
        return false;
    }
    bool sleb(std::int32_t &v) {
        std::uint32_t raw = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 5; ++i) {
            if (pos >= bytes.size()) return false;
            const auto b = std::to_integer<std::uint8_t>(bytes[pos++]);
            raw |= std::uint32_t(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) {
                if (shift < 32 && (b & 0x40)) raw |= ~std::uint32_t{0} << shift;
                v = static_cast<std::int32_t>(raw); return true;
            }
        }
        return false;
    }
    bool seek(std::size_t p) { if (p > bytes.size()) return false; pos = p; return true; }
    bool skip(std::size_t n) { if (n > bytes.size() - pos) return false; pos += n; return true; }
};
struct Proto { std::uint32_t return_type = 0; std::vector<std::uint16_t> parameters; };
struct Method { std::uint16_t owner = 0, proto = 0; std::uint32_t name = 0; };
struct Field { std::uint16_t owner = 0, type = 0; std::uint32_t name = 0; };
struct HiddenApiMemberRef { DexHiddenApiMemberKind kind; std::uint32_t index; };
struct Code { std::uint32_t method = 0; std::uint64_t file_offset = 0; std::uint32_t byte_size = 0, debug = 0, registers = 0, ins = 0; std::vector<DexExceptionRegion> exception_regions; };

bool extent(std::uint64_t off, std::uint64_t count, std::uint64_t stride, std::uint64_t size) {
    return off <= size && (!count || (stride && count <= (size - off) / stride));
}
std::uint32_t adler32(std::span<const std::byte> bytes, std::stop_token stop) {
    constexpr std::uint32_t modulus = 65521;
    std::uint32_t a = 1, b = 0;
    for (std::size_t begin = 0; begin < bytes.size();) {
        if (stop.stop_requested()) return 0;
        const auto count = std::min<std::size_t>(5552, bytes.size() - begin);
        for (std::size_t i = 0; i < count; ++i) {
            a += std::to_integer<std::uint8_t>(bytes[begin + i]);
            b += a;
        }
        a %= modulus;
        b %= modulus;
        begin += count;
    }
    return (b << 16) | a;
}

std::array<std::byte, 20> sha1(std::span<const std::byte> bytes, std::stop_token stop, bool &canceled) {
    std::uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe,
                  h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const auto process = [&](const std::byte *block) {
        std::array<std::uint32_t, 80> words{};
        for (unsigned i = 0; i < 16; ++i) {
            const auto at = i * 4;
            words[i] = (std::uint32_t(std::to_integer<std::uint8_t>(block[at])) << 24) |
                       (std::uint32_t(std::to_integer<std::uint8_t>(block[at + 1])) << 16) |
                       (std::uint32_t(std::to_integer<std::uint8_t>(block[at + 2])) << 8) |
                       std::to_integer<std::uint8_t>(block[at + 3]);
        }
        for (unsigned i = 16; i < words.size(); ++i)
            words[i] = std::rotl(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
        auto a = h0, b = h1, c = h2, d = h3, e = h4;
        for (unsigned i = 0; i < words.size(); ++i) {
            std::uint32_t f = 0, k = 0;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { f = b ^ c ^ d; k = 0xca62c1d6; }
            const auto temp = std::rotl(a, 5) + f + e + k + words[i];
            e = d; d = c; c = std::rotl(b, 30); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    };
    std::size_t offset = 0;
    while (bytes.size() - offset >= 64) {
        if ((offset & ((1u << 20) - 1)) == 0 && stop.stop_requested()) { canceled = true; return {}; }
        process(bytes.data() + offset);
        offset += 64;
    }
    std::array<std::byte, 128> tail{};
    const auto remaining = bytes.size() - offset;
    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(), tail.begin());
    tail[remaining] = std::byte{0x80};
    const std::size_t padded = remaining < 56 ? 64 : 128;
    const auto bit_length = static_cast<std::uint64_t>(bytes.size()) * 8;
    for (unsigned i = 0; i < 8; ++i)
        tail[padded - 1 - i] = static_cast<std::byte>((bit_length >> (i * 8)) & 0xff);
    process(tail.data());
    if (padded == 128) process(tail.data() + 64);
    std::array<std::byte, 20> digest{};
    const std::array<std::uint32_t, 5> state{h0, h1, h2, h3, h4};
    for (std::size_t i = 0; i < state.size(); ++i)
        for (unsigned j = 0; j < 4; ++j)
            digest[i * 4 + j] = static_cast<std::byte>((state[i] >> (24 - j * 8)) & 0xff);
    canceled = stop.stop_requested();
    return digest;
}

std::string utf8(std::uint32_t cp) {
    std::string out;
    if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) { out.push_back(static_cast<char>(0xc0 | (cp >> 6))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    else if (cp <= 0xffff) { out.push_back(static_cast<char>(0xe0 | (cp >> 12))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    else { out.push_back(static_cast<char>(0xf0 | (cp >> 18))); out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    return out;
}
bool decode_mutf8(std::span<const std::byte> raw, std::uint32_t expected_units, std::string &out) {
    std::vector<std::uint16_t> units;
    for (std::size_t p = 0; p < raw.size();) {
        const auto b = std::to_integer<std::uint8_t>(raw[p++]);
        if (b == 0) return false;
        if (b < 0x80) units.push_back(b);
        else if ((b & 0xe0) == 0xc0) {
            if (p >= raw.size()) return false;
            const auto b2 = std::to_integer<std::uint8_t>(raw[p++]);
            if ((b2 & 0xc0) != 0x80) return false;
            const auto cp = std::uint16_t(((b & 0x1f) << 6) | (b2 & 0x3f));
            if (cp == 0) { units.push_back(0); continue; }
            if (cp < 0x80) return false;
            units.push_back(cp);
        } else if ((b & 0xf0) == 0xe0) {
            if (raw.size() - p < 2) return false;
            const auto b2 = std::to_integer<std::uint8_t>(raw[p++]);
            const auto b3 = std::to_integer<std::uint8_t>(raw[p++]);
            if ((b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80) return false;
            const auto cp = std::uint16_t(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
            if (cp < 0x800) return false;
            units.push_back(cp);
        } else return false;
    }
    if (units.size() != expected_units) return false;
    out.clear();
    for (std::size_t i = 0; i < units.size(); ++i) {
        std::uint32_t cp = units[i];
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 >= units.size() || units[i + 1] < 0xdc00 || units[i + 1] > 0xdfff) return false;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (units[++i] - 0xdc00);
        } else if (cp >= 0xdc00 && cp <= 0xdfff) return false;
        out += utf8(cp);
    }
    return true;
}

struct MapData {
    std::vector<std::uint32_t> offsets;
    std::uint32_t method_handle_count = 0, method_handle_off = 0;
    std::uint32_t call_site_count = 0, call_site_off = 0;
    std::uint32_t hiddenapi_count = 0, hiddenapi_off = 0;
    bool has_method_handles = false, has_call_sites = false;
    bool has_hiddenapi = false;
};
Result<MapData> parse_map(std::span<const std::byte> bytes, std::uint32_t offset) {
    if (!offset || (offset & 3) || !extent(offset, 1, 4, bytes.size()))
        return Error{ErrorCode::malformed, "DEX map_list offset is invalid"};
    Reader r{bytes}; r.seek(offset);
    std::uint32_t count = 0;
    if (!r.u32(count) || count == 0 || count > 4096 || !extent(offset + 4, count, 12, bytes.size()))
        return Error{ErrorCode::malformed, "DEX map_list extent is invalid"};
    MapData result;
    std::array<bool, 0x10001> seen{};
    result.offsets.reserve(count);
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint16_t type = 0, unused = 0; std::uint32_t size = 0, item_off = 0;
        if (!r.u16(type) || !r.u16(unused) || !r.u32(size) || !r.u32(item_off) || unused || type >= seen.size() || seen[type] ||
            item_off > bytes.size() || (i && item_off < previous))
            return Error{ErrorCode::malformed, "DEX map entry is invalid, duplicated, or out of order"};
        seen[type] = true; previous = item_off; result.offsets.push_back(item_off);
        if (type == 0x0007) { result.has_call_sites = true; result.call_site_count = size; result.call_site_off = item_off; }
        if (type == 0x0008) { result.has_method_handles = true; result.method_handle_count = size; result.method_handle_off = item_off; }
        if (type == 0xf000) { result.has_hiddenapi = true; result.hiddenapi_count = size; result.hiddenapi_off = item_off; }
        if (size && item_off == bytes.size()) return Error{ErrorCode::malformed, "DEX map entry starts at end of file"};
    }
    return result;
}

Result<LoadedImage> parse(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    const auto file_size = storage->size();
    if (file_size < header_bytes) return Error{ErrorCode::malformed, "Truncated DEX header"};
    if (file_size > max_file_size || file_size > SIZE_MAX)
        return Error{ErrorCode::resource_limit, "DEX input exceeds the 512 MiB parser limit"};
    auto source = storage->read_at({0}, static_cast<std::size_t>(file_size));
    if (!source) return source.error();
    if (source.value().bytes.size() != file_size) return Error{ErrorCode::io, "DEX source returned an incomplete read"};
    const auto bytes = std::span<const std::byte>(source.value().bytes);
    if (std::memcmp(bytes.data(), "dex\n", 4) != 0 || bytes[7] != std::byte{0})
        return Error{ErrorCode::malformed, "Invalid DEX magic"};
    for (std::size_t i = 4; i <= 6; ++i)
        if (bytes[i] < std::byte{'0'} || bytes[i] > std::byte{'9'})
            return Error{ErrorCode::malformed, "DEX version field is not decimal"};
    const auto version = (std::to_integer<unsigned>(bytes[4]) - '0') * 100 +
                         (std::to_integer<unsigned>(bytes[5]) - '0') * 10 +
                         (std::to_integer<unsigned>(bytes[6]) - '0');
    bool dex041_single_member = false;
    std::uint32_t dex041_logical_size = 0;
    if (version == 41) {
        if (file_size < dex041_header_bytes)
            return Error{ErrorCode::malformed, "Truncated DEX 041 header"};
        Reader container_header{bytes}; container_header.seek(32);
        std::uint32_t declared_header=0, endian=0;
        if (!container_header.u32(dex041_logical_size) || !container_header.u32(declared_header) ||
            !container_header.u32(endian) || !container_header.seek(0x70))
            return Error{ErrorCode::malformed, "Truncated DEX 041 container header fields"};
        std::uint32_t container_size=0, header_offset=0;
        if (!container_header.u32(container_size) || !container_header.u32(header_offset))
            return Error{ErrorCode::malformed, "Truncated DEX 041 container bounds"};
        if (declared_header != dex041_header_bytes || endian != 0x12345678 ||
            container_size != file_size || header_offset != 0 || dex041_logical_size < dex041_header_bytes ||
            dex041_logical_size > container_size)
            return Error{ErrorCode::malformed, "DEX 041 header or container bounds are inconsistent with the physical input"};
        if (dex041_logical_size != container_size)
            return Error{ErrorCode::unsupported,
                         "DEX 041 multi-member containers are recognized, but only single-member containers are supported"};
        dex041_single_member = true;
    }
    if (version < 35 || (version > 40 && !dex041_single_member))
        return Error{ErrorCode::unsupported, "DEX versions 035 through 040 and single-member 041 containers are supported"};
    Reader h{bytes}; h.seek(32);
    std::uint32_t stored_file_size=0, header_size=0, endian=0, link_size=0, link_off=0, map_off=0;
    std::uint32_t string_count=0,string_off=0,type_count=0,type_off=0,proto_count=0,proto_off=0;
    std::uint32_t field_count=0,field_off=0,method_count=0,method_off=0,class_count=0,class_off=0,data_size=0,data_off=0;
    if (!h.u32(stored_file_size)||!h.u32(header_size)||!h.u32(endian)||!h.u32(link_size)||!h.u32(link_off)||!h.u32(map_off)||
        !h.u32(string_count)||!h.u32(string_off)||!h.u32(type_count)||!h.u32(type_off)||!h.u32(proto_count)||!h.u32(proto_off)||
        !h.u32(field_count)||!h.u32(field_off)||!h.u32(method_count)||!h.u32(method_off)||!h.u32(class_count)||!h.u32(class_off)||!h.u32(data_size)||!h.u32(data_off))
        return Error{ErrorCode::malformed, "Truncated DEX header fields"};
    if (stored_file_size != (dex041_single_member ? dex041_logical_size : file_size) ||
        header_size != (dex041_single_member ? dex041_header_bytes : header_bytes) || endian != 0x12345678)
        return Error{ErrorCode::malformed, "DEX header size, file size, or endian tag is unsupported"};
    bool hash_canceled = false;
    const auto signature = sha1(bytes.subspan(32), stop, hash_canceled);
    if (hash_canceled) return Error{ErrorCode::canceled, "DEX signature validation canceled"};
    if (!std::equal(signature.begin(), signature.end(), bytes.begin() + 12))
        return Error{ErrorCode::malformed, "DEX SHA-1 signature mismatch at file offset 0x0c"};
    const auto stored_checksum = std::uint32_t(std::to_integer<std::uint8_t>(bytes[8])) |
                                 (std::uint32_t(std::to_integer<std::uint8_t>(bytes[9])) << 8) |
                                 (std::uint32_t(std::to_integer<std::uint8_t>(bytes[10])) << 16) |
                                 (std::uint32_t(std::to_integer<std::uint8_t>(bytes[11])) << 24);
    const auto computed_checksum = adler32(bytes.subspan(12), stop);
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX checksum validation canceled"};
    if (computed_checksum != stored_checksum)
        return Error{ErrorCode::malformed, "DEX Adler-32 checksum mismatch at file offset 0x08"};
    if (string_count > max_items || type_count > max_items || proto_count > max_items || method_count > max_items || class_count > max_items || field_count > max_items)
        return Error{ErrorCode::resource_limit, "DEX identifier table exceeds one million items"};
    if (dex041_single_member) {
        // In v41 data_size/data_off are unused. For the single-member case all
        // offsets still address this physical file, so bound data by the end of
        // the fixed header and identifier tables through the container end.
        std::uint64_t fixed_end = dex041_header_bytes;
        const auto include_table = [&](std::uint32_t off, std::uint32_t count, std::uint32_t stride) {
            if (count) fixed_end = std::max(fixed_end, std::uint64_t(off) + std::uint64_t(count) * stride);
        };
        include_table(string_off, string_count, 4); include_table(type_off, type_count, 4);
        include_table(proto_off, proto_count, 12); include_table(field_off, field_count, 8);
        include_table(method_off, method_count, 8); include_table(class_off, class_count, 32);
        fixed_end = (fixed_end + 3) & ~std::uint64_t{3};
        if (fixed_end > file_size) return Error{ErrorCode::malformed, "DEX 041 fixed tables exceed the container"};
        data_off = static_cast<std::uint32_t>(fixed_end);
        data_size = static_cast<std::uint32_t>(file_size - fixed_end);
    }
    if ((string_count && (string_off & 3)) || (type_count && (type_off & 3)) ||
        (proto_count && (proto_off & 3)) || (field_count && (field_off & 3)) ||
        (method_count && (method_off & 3)) || (class_count && (class_off & 3)) ||
        (data_size && (data_off & 3)) || !extent(string_off,string_count,4,file_size) || !extent(type_off,type_count,4,file_size) ||
        !extent(proto_off,proto_count,12,file_size) || !extent(field_off,field_count,8,file_size) ||
        !extent(method_off,method_count,8,file_size) || !extent(class_off,class_count,32,file_size) ||
        !extent(data_off,data_size,1,file_size) || (link_size && !extent(link_off,link_size,1,file_size)))
        return Error{ErrorCode::malformed, "DEX table or data section exceeds the input"};
    auto map = parse_map(bytes,map_off); if (!map) return map.error();
    if (dex041_single_member && map_off < data_off)
        return Error{ErrorCode::malformed, "DEX 041 map_list overlaps the fixed header or identifier tables"};
    if (version < 38 && (map.value().has_call_sites || map.value().has_method_handles))
        return Error{ErrorCode::malformed, "DEX call-site and method-handle sections require version 038 or later"};
    if (version < 39 && map.value().has_hiddenapi)
        return Error{ErrorCode::malformed, "DEX hidden API data requires version 039 or later"};
    if (map.value().call_site_count > max_items || map.value().method_handle_count > max_items)
        return Error{ErrorCode::resource_limit, "DEX call-site or method-handle table exceeds one million items"};
    if ((map.value().call_site_count && ((map.value().call_site_off & 3) ||
         !extent(map.value().call_site_off, map.value().call_site_count, 4, file_size))) ||
        (map.value().method_handle_count && ((map.value().method_handle_off & 3) ||
         !extent(map.value().method_handle_off, map.value().method_handle_count, 8, file_size))))
        return Error{ErrorCode::malformed, "DEX call-site or method-handle table exceeds the input"};
    if (map.value().has_hiddenapi && map.value().hiddenapi_count != 1)
        return Error{ErrorCode::malformed, "DEX hiddenapi_class_data map entry must describe one section"};
    std::uint32_t hiddenapi_size = 0;
    std::vector<std::uint32_t> hiddenapi_offsets;
    std::uint64_t hiddenapi_data_cursor = 0;
    if (map.value().has_hiddenapi) {
        const auto section_off = map.value().hiddenapi_off;
        if ((section_off & 3) || section_off < data_off || section_off >= std::uint64_t(data_off) + data_size ||
            !extent(section_off, 1, 4, file_size))
            return Error{ErrorCode::malformed, "DEX hiddenapi_class_data section offset is invalid"};
        Reader hidden{bytes}; hidden.seek(section_off);
        if (!hidden.u32(hiddenapi_size) || hiddenapi_size < 4ull + std::uint64_t(class_count) * 4 ||
            !extent(section_off, hiddenapi_size, 1, std::uint64_t(data_off) + data_size))
            return Error{ErrorCode::malformed, "DEX hiddenapi_class_data size or offsets table is invalid"};
        const auto next_section = std::upper_bound(map.value().offsets.begin(), map.value().offsets.end(), section_off);
        const auto section_limit = next_section == map.value().offsets.end()
            ? std::uint64_t(data_off) + data_size : std::uint64_t(*next_section);
        if (std::uint64_t(section_off) + hiddenapi_size > section_limit)
            return Error{ErrorCode::malformed, "DEX hiddenapi_class_data section overlaps the next mapped section"};
        hiddenapi_offsets.reserve(class_count);
        for (std::uint32_t class_index = 0; class_index < class_count; ++class_index) {
            std::uint32_t relative = 0;
            if (!hidden.u32(relative)) return Error{ErrorCode::malformed, "Truncated DEX hidden API offsets table"};
            if (relative && (relative < 4ull + std::uint64_t(class_count) * 4 || relative >= hiddenapi_size))
                return Error{ErrorCode::malformed, "DEX hidden API class offset is outside the flag payload"};
            hiddenapi_offsets.push_back(relative);
        }
        hiddenapi_data_cursor = 4ull + std::uint64_t(class_count) * 4;
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX loading canceled"};

    std::vector<std::string> strings; strings.reserve(string_count);
    std::uint64_t decoded_string_bytes = 0;
    Reader ids{bytes};
    for (std::uint32_t i=0;i<string_count;++i) {
        if (!ids.seek(string_off + std::size_t(i)*4)) return Error{ErrorCode::malformed,"DEX string_ids offset is invalid"};
        std::uint32_t off=0; if(!ids.u32(off)||off<data_off||off>=std::uint64_t(data_off)+data_size) return Error{ErrorCode::malformed,"DEX string_data offset is outside data section"};
        Reader str{bytes}; str.seek(off); std::uint32_t utf16_size=0;
        if(!str.uleb(utf16_size)||utf16_size>1'000'000) return Error{ErrorCode::malformed,"DEX string length is invalid"};
        const auto begin=str.pos; while(str.pos<bytes.size()&&str.pos-begin<=3'000'000&&bytes[str.pos]!=std::byte{0}) ++str.pos;
        if(str.pos==bytes.size()||str.pos-begin>3'000'000) return Error{ErrorCode::malformed,"DEX string terminator is missing or exceeds the string budget"};
        std::string value; if(!decode_mutf8(bytes.subspan(begin,str.pos-begin),utf16_size,value)) return Error{ErrorCode::malformed,"DEX string is not valid modified UTF-8 or its UTF-16 length disagrees"};
        if(value.size()>4'000'000) return Error{ErrorCode::resource_limit,"Decoded DEX string exceeds the size budget"};
        decoded_string_bytes += value.size();
        if(decoded_string_bytes > max_file_size) return Error{ErrorCode::resource_limit,"Aggregate DEX strings exceed the memory budget"};
        strings.push_back(std::move(value));
    }
    std::vector<std::string> types; types.reserve(type_count);
    for(std::uint32_t i=0;i<type_count;++i){
        ids.seek(type_off+std::size_t(i)*4);std::uint32_t string_idx=0;
        if(!ids.u32(string_idx)||string_idx>=strings.size())return Error{ErrorCode::malformed,"DEX type_id references an invalid string"};
        types.push_back(strings[string_idx]);
    }
    std::vector<Field> fields; fields.reserve(field_count);
    for(std::uint32_t i=0;i<field_count;++i){
        ids.seek(field_off+std::size_t(i)*8);Field f;
        if(!ids.u16(f.owner)||!ids.u16(f.type)||!ids.u32(f.name)||f.owner>=types.size()||f.type>=types.size()||f.name>=strings.size())
            return Error{ErrorCode::malformed,"DEX field_id contains an invalid index"};
        fields.push_back(f);
    }
    std::vector<Proto> protos; protos.reserve(proto_count);
    std::uint64_t total_proto_parameters = 0;
    for(std::uint32_t i=0;i<proto_count;++i){
        ids.seek(proto_off+std::size_t(i)*12); std::uint32_t shorty=0,ret=0,param_off=0;
        if(!ids.u32(shorty)||!ids.u32(ret)||!ids.u32(param_off)||shorty>=strings.size()||ret>=types.size())return Error{ErrorCode::malformed,"DEX proto_id references invalid string or type"};
        Proto p; p.return_type=ret;
        if(param_off){
            if((param_off&3)||!extent(param_off,1,4,file_size))return Error{ErrorCode::malformed,"DEX proto parameter list offset is invalid"};
            Reader list{bytes};list.seek(param_off);std::uint32_t n=0;
            if(!list.u32(n)||n>255||!extent(param_off+4,n,2,file_size))return Error{ErrorCode::malformed,"DEX proto parameter list extent is invalid"};
            total_proto_parameters += n;
            if(total_proto_parameters > max_items)return Error{ErrorCode::resource_limit,"Aggregate DEX proto parameters exceed item budget"};
            p.parameters.reserve(n);
            for(std::uint32_t j=0;j<n;++j){std::uint16_t t=0;if(!list.u16(t)||t>=types.size())return Error{ErrorCode::malformed,"DEX proto parameter type is invalid"};p.parameters.push_back(t);}
        }
        protos.push_back(std::move(p));
    }
    std::vector<Method> methods; methods.reserve(method_count);
    for(std::uint32_t i=0;i<method_count;++i){
        ids.seek(method_off+std::size_t(i)*8);Method m;
        if(!ids.u16(m.owner)||!ids.u16(m.proto)||!ids.u32(m.name)||m.owner>=types.size()||m.proto>=protos.size()||m.name>=strings.size())return Error{ErrorCode::malformed,"DEX method_id contains an invalid index"};
        methods.push_back(m);
    }
    std::vector<DexMethodHandle> decoded_method_handles;
    decoded_method_handles.reserve(map.value().method_handle_count);
    for (std::uint32_t i = 0; i < map.value().method_handle_count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX method-handle parsing canceled"};
        Reader handle{bytes};
        if (!handle.seek(map.value().method_handle_off + std::size_t(i) * 8))
            return Error{ErrorCode::malformed, "DEX method_handle_item offset is invalid"};
        std::uint16_t kind=0, unused0=0, member=0, unused1=0;
        if (!handle.u16(kind) || !handle.u16(unused0) || !handle.u16(member) || !handle.u16(unused1) ||
            kind > 8 || unused0 || unused1 ||
            (kind <= 3 ? member >= fields.size() : member >= methods.size()))
            return Error{ErrorCode::malformed, "DEX method_handle_item has invalid reserved fields, kind, or member index"};
        decoded_method_handles.push_back({kind, member,
            std::uint64_t(map.value().method_handle_off) + std::uint64_t(i) * 8});
    }
    auto method_name=[&](std::uint32_t idx){
        const auto&m=methods[idx]; const auto&p=protos[m.proto]; std::string out=types[m.owner]+"->"+strings[m.name]+"(";
        for(auto t:p.parameters)out+=types[t]; return out+")"+types[p.return_type];
    };
    std::vector<Code> code;
    std::vector<DexStaticValue> decoded_static_values;
    std::vector<DexHiddenApiFlag> decoded_hiddenapi_flags;
    std::vector<DexCallSite> decoded_call_sites;
    decoded_call_sites.reserve(map.value().call_site_count);
    std::vector<DexAnnotationItem> decoded_annotations;
    std::vector<DexAnnotationLink> annotation_links;
    std::unordered_map<std::uint32_t, std::uint32_t> annotation_item_indices;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> annotation_set_indices;
    std::uint64_t total_annotation_set_entries = 0;
    std::uint64_t total_annotation_sets = 0;
    std::uint64_t total_annotation_directory_entries = 0;
    std::uint64_t total_annotation_parameter_slots = 0;
    std::uint64_t total_annotation_links = 0;
    std::uint64_t total_annotation_model_bytes = 0;
    std::uint64_t total_hiddenapi_model_bytes = 0;
    std::unordered_set<std::uint32_t> class_data_offsets;
    std::uint64_t total_code_units=0;
    std::uint64_t total_try_items=0, total_catch_handlers=0;
    std::uint64_t total_encoded_value_nodes = 0;
    std::uint64_t total_encoded_value_bytes = 0;
    std::function<Result<DexEncodedValue>(Reader &, std::uint32_t, unsigned)> decode_encoded_value;
    decode_encoded_value = [&](Reader &reader, std::uint32_t name_index, unsigned depth) -> Result<DexEncodedValue> {
        constexpr std::uint64_t max_value_nodes = 250'000;
        constexpr std::uint64_t max_value_bytes = 64ull * 1024 * 1024;
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX encoded-value parsing canceled"};
        if (depth > 64) return Error{ErrorCode::resource_limit, "DEX encoded-value nesting exceeds 64 levels"};
        if (++total_encoded_value_nodes > max_value_nodes)
            return Error{ErrorCode::resource_limit, "DEX encoded values exceed 250,000 nodes"};
        if (total_encoded_value_bytes > max_value_bytes - sizeof(DexEncodedValue))
            return Error{ErrorCode::resource_limit, "DEX encoded-value metadata exceeds 64 MiB"};
        total_encoded_value_bytes += sizeof(DexEncodedValue);
        if (reader.pos >= reader.bytes.size()) return Error{ErrorCode::malformed, "Truncated DEX encoded_value"};
        DexEncodedValue value;
        value.file_offset = reader.pos;
        value.name_index = name_index;
        const auto header = std::to_integer<std::uint8_t>(reader.bytes[reader.pos++]);
        value.type = header & 0x1f;
        value.value_arg = header >> 5;
        auto read_scalar = [&](unsigned width, bool is_signed, bool left_aligned = false) -> bool {
            if (width > 8 || width > reader.bytes.size() - reader.pos) return false;
            std::uint64_t bits = 0;
            for (unsigned i = 0; i < width; ++i)
                bits |= std::uint64_t(std::to_integer<std::uint8_t>(reader.bytes[reader.pos++])) << (8 * i);
            if (left_aligned) bits <<= (8 - width) * 8;
            else if (is_signed && width < 8 && (bits & (UINT64_C(1) << (width * 8 - 1))))
                bits |= (~UINT64_C(0)) << (width * 8);
            value.payload = bits;
            return true;
        };
        const auto bad_arg = [&]() -> Result<DexEncodedValue> {
            return Error{ErrorCode::malformed, "DEX encoded_value has an invalid value_arg"};
        };
        switch (value.type) {
        case 0x00: // VALUE_BYTE
            if (value.value_arg != 0) return bad_arg();
            if (!read_scalar(1, true)) return Error{ErrorCode::malformed, "Truncated DEX byte encoded_value"};
            break;
        case 0x02: case 0x03: case 0x04: case 0x06: // short, char, int, long
        case 0x10: case 0x11: // float, double
        case 0x15: case 0x16: case 0x17: case 0x18: case 0x19: case 0x1a: case 0x1b: {
            if (version < 38 && (value.type == 0x15 || value.type == 0x16))
                return Error{ErrorCode::malformed, "DEX method-type and method-handle values require version 038 or later"};
            const unsigned max_arg = value.type == 0x02 || value.type == 0x03 ? 1 :
                value.type == 0x04 || value.type == 0x10 || value.type == 0x15 || value.type == 0x16 ||
                value.type == 0x17 || value.type == 0x18 || value.type == 0x19 || value.type == 0x1a || value.type == 0x1b ? 3 : 7;
            if (value.value_arg > max_arg) return bad_arg();
            const unsigned width = value.value_arg + 1;
            const bool floating = value.type == 0x10 || value.type == 0x11;
            const bool signed_value = value.type == 0x02 || value.type == 0x04 || value.type == 0x06;
            if (!read_scalar(width, signed_value, floating))
                return Error{ErrorCode::malformed, "Truncated DEX scalar encoded_value"};
            if (!floating) {
                const auto index = value.payload;
                const bool valid = value.type == 0x15 ? index < protos.size() :
                    value.type == 0x16 ? index < map.value().method_handle_count :
                    value.type == 0x17 ? index < strings.size() :
                    value.type == 0x18 ? index < types.size() :
                    (value.type == 0x19 || value.type == 0x1b) ? index < fields.size() :
                    value.type == 0x1a ? index < methods.size() : true;
                if (!valid) return Error{ErrorCode::malformed, "DEX encoded_value references an invalid table index"};
            }
            break;
        }
        case 0x1c: { // VALUE_ARRAY
            if (value.value_arg != 0) return bad_arg();
            std::uint32_t count = 0;
            if (!reader.uleb(count)) return Error{ErrorCode::malformed, "Truncated DEX encoded_array"};
            if (count > max_value_nodes || count > max_value_nodes - total_encoded_value_nodes ||
                count > (max_value_bytes - total_encoded_value_bytes) / sizeof(DexEncodedValue))
                return Error{ErrorCode::resource_limit, "DEX encoded_array exceeds value-node budget"};
            total_encoded_value_bytes += std::uint64_t(count) * sizeof(DexEncodedValue);
            value.children.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                auto child = decode_encoded_value(reader, UINT32_MAX, depth + 1);
                if (!child) return child.error();
                value.children.push_back(std::move(child.value()));
            }
            break;
        }
        case 0x1d: { // VALUE_ANNOTATION
            if (value.value_arg != 0) return bad_arg();
            std::uint32_t type = 0, count = 0;
            if (!reader.uleb(type) || !reader.uleb(count))
                return Error{ErrorCode::malformed, "Truncated DEX encoded_annotation"};
            if (type >= types.size()) return Error{ErrorCode::malformed, "DEX encoded_annotation type index is invalid"};
            value.payload = type;
            if (count > max_value_nodes || count > max_value_nodes - total_encoded_value_nodes ||
                count > (max_value_bytes - total_encoded_value_bytes) / sizeof(DexEncodedValue))
                return Error{ErrorCode::resource_limit, "DEX encoded_annotation exceeds value-node budget"};
            total_encoded_value_bytes += std::uint64_t(count) * sizeof(DexEncodedValue);
            value.children.reserve(count);
            std::uint32_t previous_name = 0;
            for (std::uint32_t i = 0; i < count; ++i) {
                std::uint32_t element_name = 0;
                if (!reader.uleb(element_name) || element_name >= strings.size() || (i && element_name <= previous_name))
                    return Error{ErrorCode::malformed, "DEX encoded_annotation element names are invalid or unordered"};
                previous_name = element_name;
                auto child = decode_encoded_value(reader, element_name, depth + 1);
                if (!child) return child.error();
                value.children.push_back(std::move(child.value()));
            }
            break;
        }
        case 0x1e: // VALUE_NULL
            if (value.value_arg != 0) return bad_arg();
            break;
        case 0x1f: // VALUE_BOOLEAN
            if (value.value_arg > 1) return bad_arg();
            value.payload = value.value_arg;
            break;
        default:
            return Error{ErrorCode::malformed, "DEX encoded_value has an unknown value type"};
        }
        return value;
    };
    const auto dex_data_end = static_cast<std::size_t>(std::uint64_t(data_off) + data_size);
    for (std::uint32_t i = 0; i < map.value().call_site_count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX call-site parsing canceled"};
        Reader call_site_id{bytes};
        if (!call_site_id.seek(map.value().call_site_off + std::size_t(i) * 4))
            return Error{ErrorCode::malformed, "DEX call_site_id_item offset is invalid"};
        std::uint32_t item_off=0;
        if (!call_site_id.u32(item_off) || item_off < data_off || item_off >= dex_data_end)
            return Error{ErrorCode::malformed, "DEX call_site_item offset is outside the data section"};
        Reader item{bytes.first(dex_data_end)};
        if (!item.seek(item_off)) return Error{ErrorCode::malformed, "DEX call_site_item offset is invalid"};
        std::uint32_t value_count=0;
        if (!item.uleb(value_count) || value_count < 3)
            return Error{ErrorCode::malformed, "DEX call_site_item must contain its bootstrap handle, name, and method type"};
        if (value_count > 250'000 || value_count > 250'000 - total_encoded_value_nodes)
            return Error{ErrorCode::resource_limit, "DEX call_site_item values exceed the encoded-value budget"};
        DexCallSite call_site;
        call_site.file_offset = item_off;
        call_site.values.reserve(value_count);
        for (std::uint32_t value_index=0; value_index<value_count; ++value_index) {
            auto value = decode_encoded_value(item, UINT32_MAX, 0);
            if (!value) return value.error();
            const auto expected_type = value_index == 0 ? 0x16 : value_index == 1 ? 0x17 : value_index == 2 ? 0x15 : 0xff;
            if (value_index < 3 && value.value().type != expected_type)
                return Error{ErrorCode::malformed, "DEX call_site_item bootstrap arguments have invalid encoded_value types"};
            call_site.values.push_back(std::move(value.value()));
        }
        decoded_call_sites.push_back(std::move(call_site));
    }
    std::function<Result<std::uint32_t>(std::uint32_t)> read_annotation_item;
    read_annotation_item = [&](std::uint32_t offset) -> Result<std::uint32_t> {
        constexpr std::uint64_t max_annotation_items = 250'000;
        constexpr std::uint64_t max_annotation_bytes = 64ull * 1024 * 1024;
        if (const auto found = annotation_item_indices.find(offset); found != annotation_item_indices.end())
            return found->second;
        if (offset < data_off || offset >= dex_data_end)
            return Error{ErrorCode::malformed, "DEX annotation_item offset is outside the data section"};
        if (decoded_annotations.size() >= max_annotation_items)
            return Error{ErrorCode::resource_limit, "DEX annotation items exceed 250,000"};
        if (total_annotation_model_bytes > max_annotation_bytes - sizeof(DexAnnotationItem))
            return Error{ErrorCode::resource_limit, "DEX annotation metadata exceeds 64 MiB"};
        Reader item{bytes.first(dex_data_end)};
        if (!item.seek(offset)) return Error{ErrorCode::malformed, "DEX annotation_item offset is invalid"};
        const auto visibility = std::to_integer<std::uint8_t>(item.bytes[item.pos++]);
        std::uint32_t type = 0, count = 0;
        if (visibility > 2 || !item.uleb(type) || !item.uleb(count) || type >= types.size())
            return Error{ErrorCode::malformed, "DEX annotation_item visibility, type, or element count is invalid"};
        if (count > 250'000 || count > 250'000 - total_encoded_value_nodes ||
            count > (max_annotation_bytes - total_annotation_model_bytes - sizeof(DexAnnotationItem)) / sizeof(DexEncodedValue))
            return Error{ErrorCode::resource_limit, "DEX annotation elements exceed metadata budget"};
        total_annotation_model_bytes += sizeof(DexAnnotationItem) + std::uint64_t(count) * sizeof(DexEncodedValue);
        DexAnnotationItem annotation;
        annotation.visibility = visibility;
        annotation.type_index = type;
        annotation.file_offset = offset;
        annotation.elements.reserve(count);
        std::uint32_t previous_name = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX annotation parsing canceled"};
            std::uint32_t name = 0;
            if (!item.uleb(name) || name >= strings.size() || (i && name <= previous_name))
                return Error{ErrorCode::malformed, "DEX annotation element names are invalid or unordered"};
            previous_name = name;
            auto value = decode_encoded_value(item, name, 0);
            if (!value) return value.error();
            annotation.elements.push_back(std::move(value.value()));
        }
        const auto index = static_cast<std::uint32_t>(decoded_annotations.size());
        decoded_annotations.push_back(std::move(annotation));
        annotation_item_indices.emplace(offset, index);
        return index;
    };
    std::function<Result<std::vector<std::uint32_t>>(std::uint32_t)> read_annotation_set;
    read_annotation_set = [&](std::uint32_t offset) -> Result<std::vector<std::uint32_t>> {
        constexpr std::uint64_t max_set_entries = 1'000'000;
        constexpr std::uint64_t max_annotation_bytes = 64ull * 1024 * 1024;
        if (!offset || (offset & 3) || offset < data_off || offset >= dex_data_end)
            return Error{ErrorCode::malformed, "DEX annotation_set_item offset is invalid"};
        if (const auto found = annotation_set_indices.find(offset); found != annotation_set_indices.end())
            return found->second;
        if (total_annotation_sets >= 1'000'000)
            return Error{ErrorCode::resource_limit, "DEX annotation sets exceed one million"};
        ++total_annotation_sets;
        Reader set{bytes.first(dex_data_end)};
        if (!set.seek(offset)) return Error{ErrorCode::malformed, "DEX annotation_set_item offset is invalid"};
        std::uint32_t count = 0;
        if (!set.u32(count)) return Error{ErrorCode::malformed, "Truncated DEX annotation_set_item"};
        if (count > max_set_entries || count > max_set_entries - total_annotation_set_entries)
            return Error{ErrorCode::resource_limit, "DEX annotation-set entries exceed one million"};
        if (!extent(set.pos, count, 4, set.bytes.size()))
            return Error{ErrorCode::malformed, "DEX annotation_set_item extent exceeds the data section"};
        if (count > (max_annotation_bytes - std::min(total_annotation_model_bytes, max_annotation_bytes)) / sizeof(std::uint32_t))
            return Error{ErrorCode::resource_limit, "DEX annotation-set metadata exceeds 64 MiB"};
        total_annotation_model_bytes += std::uint64_t(count) * sizeof(std::uint32_t);
        total_annotation_set_entries += count;
        std::vector<std::uint32_t> indices;
        indices.reserve(count);
        std::uint32_t previous_type = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX annotation-set parsing canceled"};
            std::uint32_t item_offset = 0;
            if (!set.u32(item_offset) || !item_offset)
                return Error{ErrorCode::malformed, "DEX annotation_set_item contains a null annotation offset"};
            auto annotation_index = read_annotation_item(item_offset);
            if (!annotation_index) return annotation_index.error();
            const auto type = decoded_annotations[annotation_index.value()].type_index;
            if (i && type <= previous_type)
                return Error{ErrorCode::malformed, "DEX annotation_set_item types are duplicated or unordered"};
            previous_type = type;
            indices.push_back(annotation_index.value());
        }
        annotation_set_indices.emplace(offset, indices);
        return indices;
    };
    auto add_annotation_links = [&](DexAnnotationTargetKind kind, std::uint32_t class_def_index,
                                    std::uint32_t member_index, std::uint32_t parameter_index,
                                    std::uint32_t set_offset, std::uint64_t source_offset) -> Result<bool> {
        if (!set_offset) return true;
        auto indices = read_annotation_set(set_offset);
        if (!indices) return indices.error();
        constexpr std::uint64_t max_annotation_links = 1'000'000;
        constexpr std::uint64_t max_annotation_bytes = 64ull * 1024 * 1024;
        for (const auto annotation_index : indices.value()) {
            if (total_annotation_links >= max_annotation_links ||
                total_annotation_model_bytes > max_annotation_bytes - sizeof(DexAnnotationLink))
                return Error{ErrorCode::resource_limit, "DEX annotation links exceed the one-million/64 MiB budget"};
            ++total_annotation_links;
            total_annotation_model_bytes += sizeof(DexAnnotationLink);
            annotation_links.push_back({kind, class_def_index, member_index, parameter_index, annotation_index, source_offset});
        }
        return true;
    };
    auto parse_annotation_directory = [&](std::uint32_t offset, std::uint32_t class_def_index,
                                          std::uint32_t class_type,
                                          const std::vector<std::uint32_t> &declared_fields,
                                          const std::vector<std::uint32_t> &declared_methods) -> Result<bool> {
        constexpr std::uint64_t max_directory_entries = 1'000'000;
        if (!offset) return true;
        if ((offset & 3) || offset < data_off || offset >= dex_data_end)
            return Error{ErrorCode::malformed, "DEX annotations_directory_item offset is invalid"};
        Reader directory{bytes.first(dex_data_end)};
        if (!directory.seek(offset)) return Error{ErrorCode::malformed, "DEX annotations_directory_item offset is invalid"};
        std::uint32_t class_set = 0, field_count = 0, method_count = 0, parameter_count = 0;
        if (!directory.u32(class_set) || !directory.u32(field_count) || !directory.u32(method_count) || !directory.u32(parameter_count))
            return Error{ErrorCode::malformed, "Truncated DEX annotations_directory_item"};
        const std::uint64_t entry_count = std::uint64_t(field_count) + method_count + parameter_count;
        if (entry_count > max_directory_entries || entry_count > max_directory_entries - total_annotation_directory_entries)
            return Error{ErrorCode::resource_limit, "DEX annotation directory entry count or extent exceeds budget"};
        if (!extent(directory.pos, entry_count, 8, directory.bytes.size()))
            return Error{ErrorCode::malformed, "DEX annotation directory entries exceed the data section"};
        total_annotation_directory_entries += entry_count;
        if (class_set && ((class_set & 3) || class_set < data_off || class_set >= dex_data_end))
            return Error{ErrorCode::malformed, "DEX class annotation set offset is invalid"};
        if (class_set) {
            auto linked = add_annotation_links(DexAnnotationTargetKind::class_def, class_def_index, UINT32_MAX, UINT32_MAX,
                                               class_set, offset);
            if (!linked) return linked.error();
        }
        std::uint32_t previous_index = 0;
        for (std::uint32_t i = 0; i < field_count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX annotation-directory parsing canceled"};
            const auto entry_offset = directory.pos;
            std::uint32_t field_index = 0, set_offset = 0;
            if (!directory.u32(field_index) || !directory.u32(set_offset) || field_index >= fields.size() ||
                fields[field_index].owner != class_type ||
                !std::binary_search(declared_fields.begin(), declared_fields.end(), field_index) ||
                (i && field_index <= previous_index))
                return Error{ErrorCode::malformed, "DEX annotated field index is invalid or unordered for its class"};
            previous_index = field_index;
            if (!set_offset || (set_offset & 3) || set_offset < data_off || set_offset >= dex_data_end)
                return Error{ErrorCode::malformed, "DEX field annotation set offset is invalid"};
            auto linked = add_annotation_links(DexAnnotationTargetKind::field, class_def_index, field_index,
                                               UINT32_MAX, set_offset, entry_offset + 4);
            if (!linked) return linked.error();
        }
        previous_index = 0;
        for (std::uint32_t i = 0; i < method_count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX annotation-directory parsing canceled"};
            const auto entry_offset = directory.pos;
            std::uint32_t method_index = 0, set_offset = 0;
            if (!directory.u32(method_index) || !directory.u32(set_offset) || method_index >= methods.size() ||
                methods[method_index].owner != class_type ||
                !std::binary_search(declared_methods.begin(), declared_methods.end(), method_index) ||
                (i && method_index <= previous_index))
                return Error{ErrorCode::malformed, "DEX annotated method index is invalid or unordered for its class"};
            previous_index = method_index;
            if (!set_offset || (set_offset & 3) || set_offset < data_off || set_offset >= dex_data_end)
                return Error{ErrorCode::malformed, "DEX method annotation set offset is invalid"};
            auto linked = add_annotation_links(DexAnnotationTargetKind::method, class_def_index, method_index,
                                               UINT32_MAX, set_offset, entry_offset + 4);
            if (!linked) return linked.error();
        }
        previous_index = 0;
        for (std::uint32_t i = 0; i < parameter_count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX parameter-annotation parsing canceled"};
            std::uint32_t method_index = 0, ref_list_offset = 0;
            if (!directory.u32(method_index) || !directory.u32(ref_list_offset) || method_index >= methods.size() ||
                methods[method_index].owner != class_type ||
                !std::binary_search(declared_methods.begin(), declared_methods.end(), method_index) ||
                (i && method_index <= previous_index))
                return Error{ErrorCode::malformed, "DEX annotated-parameter method index is invalid or unordered for its class"};
            previous_index = method_index;
            if (!ref_list_offset || (ref_list_offset & 3) || ref_list_offset < data_off || ref_list_offset >= dex_data_end)
                return Error{ErrorCode::malformed, "DEX annotation_set_ref_list offset is invalid"};
            Reader refs{bytes.first(dex_data_end)};
            if (!refs.seek(ref_list_offset)) return Error{ErrorCode::malformed, "DEX annotation_set_ref_list offset is invalid"};
            std::uint32_t count = 0;
            const auto expected = protos[methods[method_index].proto].parameters.size();
            if (!refs.u32(count) || count != expected || !extent(refs.pos, count, 4, refs.bytes.size()))
                return Error{ErrorCode::malformed, "DEX annotation_set_ref_list count or extent disagrees with method prototype"};
            if (count > 1'000'000 || count > 1'000'000 - total_annotation_parameter_slots)
                return Error{ErrorCode::resource_limit, "DEX annotation parameter slots exceed one million"};
            total_annotation_parameter_slots += count;
            for (std::uint32_t parameter_index = 0; parameter_index < count; ++parameter_index) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX parameter-annotation parsing canceled"};
                const auto ref_offset = refs.pos;
                std::uint32_t set_offset = 0;
                if (!refs.u32(set_offset)) return Error{ErrorCode::malformed, "Truncated DEX annotation_set_ref_list"};
                if (set_offset && ((set_offset & 3) || set_offset < data_off || set_offset >= dex_data_end))
                    return Error{ErrorCode::malformed, "DEX parameter annotation set offset is invalid"};
                auto linked = add_annotation_links(DexAnnotationTargetKind::parameter, class_def_index, method_index,
                                                   parameter_index, set_offset, ref_offset);
                if (!linked) return linked.error();
            }
        }
        return true;
    };
    for(std::uint32_t ci=0;ci<class_count;++ci){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"DEX class-data parsing canceled"};
        ids.seek(class_off+std::size_t(ci)*32);std::uint32_t class_type=0,access=0,super=0,interfaces=0,source_file=0,annotations=0,class_data=0,static_values=0;
        if(!ids.u32(class_type)||!ids.u32(access)||!ids.u32(super)||!ids.u32(interfaces)||!ids.u32(source_file)||!ids.u32(annotations)||!ids.u32(class_data)||!ids.u32(static_values)||class_type>=types.size()||(super!=0xffffffffu&&super>=types.size())||(source_file!=0xffffffffu&&source_file>=strings.size()))return Error{ErrorCode::malformed,"DEX class_def contains an invalid index"};
        const auto data_end=std::uint64_t(data_off)+data_size;
        if((interfaces&&((interfaces&3)||interfaces<data_off||interfaces>=data_end))||
           (annotations&&(annotations<data_off||annotations>=data_end))||
           (class_data&&(class_data<data_off||class_data>=data_end))||
           (static_values&&(static_values<data_off||static_values>=data_end)))
            return Error{ErrorCode::malformed,"DEX class_def data offset is outside the data section"};
        std::vector<std::uint32_t> static_field_indices;
        std::vector<std::uint32_t> declared_field_indices;
        std::vector<std::uint32_t> declared_method_indices;
        std::vector<HiddenApiMemberRef> class_member_order;
        if(class_data){
        if(!class_data_offsets.insert(class_data).second)return Error{ErrorCode::malformed,"DEX classes share a class_data_item offset"};
        if(class_data_offsets.size()>max_items)return Error{ErrorCode::resource_limit,"DEX class-data count exceeds item budget"};
        Reader cd{bytes.first(static_cast<std::size_t>(data_end))};cd.seek(class_data);std::uint32_t sf=0,inf=0,dm=0,vm=0;
        if(!cd.uleb(sf)||!cd.uleb(inf)||!cd.uleb(dm)||!cd.uleb(vm)||sf>max_items||inf>max_items||dm>max_items||vm>max_items)return Error{ErrorCode::malformed,"DEX class_data counts are invalid"};
        const auto encoded_field_count=std::uint64_t(sf)+inf, defined=std::uint64_t(dm)+vm;
        if(encoded_field_count>max_items||defined>max_items)return Error{ErrorCode::resource_limit,"DEX class_data exceeds item budget"};
        for(std::uint64_t group=0;group<2;++group){
            const auto count=group?inf:sf;std::uint64_t field_idx=0;
            for(std::uint32_t n=0;n<count;++n){
                std::uint32_t delta=0,flags=0;
                if(!cd.uleb(delta)||!cd.uleb(flags)||(n&&delta==0))return Error{ErrorCode::malformed,"Truncated or unordered DEX encoded field"};
                field_idx+=delta;
                if(field_idx>=fields.size()||fields[field_idx].owner!=class_type)return Error{ErrorCode::malformed,"DEX encoded field index is invalid for its defining class"};
                declared_field_indices.push_back(static_cast<std::uint32_t>(field_idx));
                class_member_order.push_back({DexHiddenApiMemberKind::field, static_cast<std::uint32_t>(field_idx)});
                if(group==0)static_field_indices.push_back(static_cast<std::uint32_t>(field_idx));
            }
        }
        for(std::uint64_t group=0;group<2;++group){
            const auto count=group?vm:dm;std::uint64_t method_idx=0;
            for(std::uint32_t n=0;n<count;++n){std::uint32_t delta=0,flags=0,code_off=0;if(!cd.uleb(delta)||!cd.uleb(flags)||!cd.uleb(code_off))return Error{ErrorCode::malformed,"Truncated DEX encoded method"};method_idx+=delta;
                if(method_idx>=methods.size()||methods[method_idx].owner!=class_type)return Error{ErrorCode::malformed,"DEX encoded method index is invalid for its defining class"};
                declared_method_indices.push_back(static_cast<std::uint32_t>(method_idx));
                class_member_order.push_back({DexHiddenApiMemberKind::method, static_cast<std::uint32_t>(method_idx)});
                if(!code_off)continue;
                if((code_off&3)||code_off<data_off||code_off>=std::uint64_t(data_off)+data_size||!extent(code_off,1,16,file_size))return Error{ErrorCode::malformed,"DEX code_item header offset is invalid"};
                Reader cr{bytes};cr.seek(code_off);std::uint16_t registers=0,ins=0,outs=0,tries=0;std::uint32_t debug=0,insns=0;
                if(!cr.u16(registers)||!cr.u16(ins)||!cr.u16(outs)||!cr.u16(tries)||!cr.u32(debug)||!cr.u32(insns)||ins>registers||!extent(cr.pos,insns,2,file_size))return Error{ErrorCode::malformed,"DEX code_item header or instruction extent is invalid"};
                if(debug&&(debug<data_off||debug>=std::uint64_t(data_off)+data_size))return Error{ErrorCode::malformed,"DEX debug_info offset is outside data section"};
                total_code_units+=insns;if(total_code_units>UINT32_MAX/2)return Error{ErrorCode::resource_limit,"DEX mapped code exceeds the method address-space budget"};
                const auto insns_off=cr.pos; cr.skip(std::size_t(insns)*2);
                std::vector<DexExceptionRegion> exception_regions;
                if(tries){
                    if(insns&1){std::uint16_t padding=0;if(!cr.u16(padding)||padding)return Error{ErrorCode::malformed,"DEX code_item try padding is invalid"};}
                    if(!extent(cr.pos,tries,8,file_size))return Error{ErrorCode::malformed,"DEX try_item table exceeds input"};
                    total_try_items+=tries;if(total_try_items>2'000'000)return Error{ErrorCode::resource_limit,"Aggregate DEX try_item count exceeds two million"};
                    struct TryItem { std::uint32_t start=0; std::uint16_t count=0, handler=0; };
                    std::vector<TryItem> try_items; try_items.reserve(tries);
                    std::uint64_t previous_end=0;
                    for(std::uint16_t n=0;n<tries;++n){std::uint32_t start=0;std::uint16_t count=0,handler=0;if(!cr.u32(start)||!cr.u16(count)||!cr.u16(handler)||!count||std::uint64_t(start)+count>insns||start<previous_end)return Error{ErrorCode::malformed,"DEX try_item ranges are invalid, overlapping, or unordered"};previous_end=std::uint64_t(start)+count;try_items.push_back({start,count,handler});}
                    const auto handlers_base=cr.pos;
                    std::uint32_t handlers=0;if(!cr.uleb(handlers)||handlers>max_items)return Error{ErrorCode::malformed,"DEX catch handler list count is invalid"};
                    std::map<std::uint16_t,std::vector<DexExceptionHandler>> handler_lists;
                    for(std::uint32_t n=0;n<handlers;++n){if(cr.pos-handlers_base>UINT16_MAX)return Error{ErrorCode::resource_limit,"DEX catch handler offsets exceed encoding range"};const auto handler_offset=static_cast<std::uint16_t>(cr.pos-handlers_base);std::int32_t typed=0;if(!cr.sleb(typed))return Error{ErrorCode::malformed,"Truncated DEX catch handler"};const auto typed_count=static_cast<std::uint32_t>(typed<0?-std::int64_t(typed):typed);if(typed_count>max_items)return Error{ErrorCode::resource_limit,"DEX catch handler exceeds item budget"};total_catch_handlers+=typed_count+(typed<=0?1u:0u);if(total_catch_handlers>4'000'000)return Error{ErrorCode::resource_limit,"Aggregate DEX catch handlers exceed four million"};std::vector<DexExceptionHandler> decoded;decoded.reserve(typed_count+(typed<=0?1u:0u));for(std::uint32_t j=0;j<typed_count;++j){std::uint32_t type=0,addr=0;if(!cr.uleb(type)||!cr.uleb(addr)||type>=types.size()||addr>=insns)return Error{ErrorCode::malformed,"DEX typed catch entry is invalid"};decoded.push_back({addr*2,type});}if(typed<=0){std::uint32_t addr=0;if(!cr.uleb(addr)||addr>=insns)return Error{ErrorCode::malformed,"DEX catch-all address is invalid"};decoded.push_back({addr*2,std::nullopt});}handler_lists.emplace(handler_offset,std::move(decoded));}
                    exception_regions.reserve(try_items.size());
                    for(const auto &item:try_items){const auto found=handler_lists.find(item.handler);if(found==handler_lists.end())return Error{ErrorCode::malformed,"DEX try_item references a missing catch handler"};total_catch_handlers+=found->second.size();if(total_catch_handlers>4'000'000)return Error{ErrorCode::resource_limit,"Expanded DEX try/catch associations exceed four million"};exception_regions.push_back({item.start*2,(item.start+item.count)*2,found->second});}
                }
                if(insns==0||cr.pos>data_end)return Error{ErrorCode::malformed,"DEX code_item is empty or extends outside data section"};
                code.push_back({static_cast<std::uint32_t>(method_idx),insns_off,insns*2,debug,registers,ins,std::move(exception_regions)});
            }
        }
        }
        std::sort(declared_field_indices.begin(), declared_field_indices.end());
        std::sort(declared_method_indices.begin(), declared_method_indices.end());
        if(static_values){
            Reader values{bytes.first(static_cast<std::size_t>(data_end))};
            if(!values.seek(static_values))return Error{ErrorCode::malformed,"DEX static_values offset is invalid"};
            std::uint32_t value_count=0;
            if(!values.uleb(value_count))return Error{ErrorCode::malformed,"Truncated DEX encoded_array_item"};
            if(value_count>static_field_indices.size())return Error{ErrorCode::malformed,"DEX static_values has more entries than the class static fields"};
            if(value_count>max_items-decoded_static_values.size())return Error{ErrorCode::resource_limit,"DEX static-value count exceeds item budget"};
            if(value_count>(64ull*1024*1024-total_encoded_value_bytes)/sizeof(DexStaticValue))return Error{ErrorCode::resource_limit,"DEX static-value metadata exceeds 64 MiB"};
            total_encoded_value_bytes+=std::uint64_t(value_count)*sizeof(DexStaticValue);
            for(std::uint32_t i=0;i<value_count;++i){
                auto value=decode_encoded_value(values,UINT32_MAX,0);
                if(!value)return value.error();
                decoded_static_values.push_back({class_type,static_field_indices[i],std::move(value.value())});
            }
            if(values.pos>data_end)return Error{ErrorCode::malformed,"DEX static_values extends outside the data section"};
        }
        if(annotations){
            auto parsed_annotations = parse_annotation_directory(annotations, ci, class_type,
                                                                  declared_field_indices, declared_method_indices);
            if(!parsed_annotations)return parsed_annotations.error();
        }
        if (map.value().has_hiddenapi) {
            const auto relative = hiddenapi_offsets[ci];
            if (relative != 0) {
                if (!class_data || class_member_order.empty())
                    return Error{ErrorCode::malformed, "DEX hidden API flags are present for a class with no encoded members"};
                if (relative != hiddenapi_data_cursor)
                    return Error{ErrorCode::malformed, "DEX hidden API class flag streams are not contiguous and ordered"};
                const auto section_off = map.value().hiddenapi_off;
                Reader flags{bytes.first(std::size_t(section_off) + hiddenapi_size)};
                if (!flags.seek(std::size_t(section_off) + relative))
                    return Error{ErrorCode::malformed, "DEX hidden API class flag offset is invalid"};
                for (const auto &member : class_member_order) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX hidden API flag parsing canceled"};
                    if (decoded_hiddenapi_flags.size() >= 2'000'000 ||
                        total_hiddenapi_model_bytes > 64ull * 1024 * 1024 - sizeof(DexHiddenApiFlag))
                        return Error{ErrorCode::resource_limit, "DEX hidden API metadata exceeds two million flags or 64 MiB"};
                    const auto flag_offset = flags.pos;
                    std::uint32_t value = 0;
                    if (!flags.uleb(value))
                        return Error{ErrorCode::malformed, "Truncated DEX hidden API member flag"};
                    decoded_hiddenapi_flags.push_back({ci, member.kind, member.index, value, flag_offset});
                    total_hiddenapi_model_bytes += sizeof(DexHiddenApiFlag);
                }
                hiddenapi_data_cursor = flags.pos - section_off;
            }
        }
    }
    if (map.value().has_hiddenapi && hiddenapi_data_cursor != hiddenapi_size)
        return Error{ErrorCode::malformed, "DEX hidden API section size does not match its class flag streams"};
    if(code.size()>max_items)return Error{ErrorCode::resource_limit,"DEX defined method count exceeds address-space budget"};
    DexMetadata dex_metadata;
    dex_metadata.static_values = std::move(decoded_static_values);
    dex_metadata.method_handles = std::move(decoded_method_handles);
    dex_metadata.call_sites = std::move(decoded_call_sites);
    dex_metadata.annotations = std::move(decoded_annotations);
    dex_metadata.annotation_links = std::move(annotation_links);
    dex_metadata.hidden_api_flags = std::move(decoded_hiddenapi_flags);
    dex_metadata.code.reserve(code.size());
    for (auto &compiled : code)
        dex_metadata.code.push_back({compiled.method,compiled.registers,compiled.ins,std::move(compiled.exception_regions)});
    std::sort(dex_metadata.code.begin(),dex_metadata.code.end(),[](const DexMethodCode &a,const DexMethodCode &b){return a.method_index<b.method_index;});
    std::uint64_t total_debug_rows = 0;
    std::size_t total_debug_bytes = 0;
    for (const auto &compiled : code) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled,"DEX debug-info parsing canceled"};
        if (!compiled.debug) continue;
        const auto data_end = static_cast<std::size_t>(std::uint64_t(data_off) + data_size);
        Reader dr{bytes.first(data_end)};
        if (!dr.seek(compiled.debug)) return Error{ErrorCode::malformed,"DEX debug_info offset is invalid"};
        DexMethodDebug decoded; decoded.method_index = compiled.method;
        const auto account_debug_bytes = [&](std::size_t amount) -> bool {
            constexpr std::size_t limit = 64ull * 1024 * 1024;
            if (total_debug_bytes > limit || amount > limit - total_debug_bytes) return false;
            total_debug_bytes += amount;
            return true;
        };
        std::uint32_t line_start = 0, parameter_count = 0;
        if (!dr.uleb(line_start) || !dr.uleb(parameter_count) || parameter_count > 255 || parameter_count != protos[methods[compiled.method].proto].parameters.size())
            return Error{ErrorCode::malformed,"DEX debug_info line or parameter header is invalid"};
        decoded.line_start = line_start;
        for (std::uint32_t n = 0; n < parameter_count; ++n) {
            std::uint32_t index = 0;
            if (!dr.uleb(index)) return Error{ErrorCode::malformed,"Truncated DEX debug parameter names"};
            if (index && index - 1 >= strings.size()) return Error{ErrorCode::malformed,"DEX debug parameter name index is invalid"};
            if (!account_debug_bytes(sizeof(std::optional<std::string>) + (index ? strings[index - 1].size() : 0))) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds 64 MiB"};
            decoded.parameter_names.push_back(index ? std::optional<std::string>(strings[index - 1]) : std::nullopt);
        }
        struct ActiveLocal { DexDebugLocal local; };
        std::vector<std::optional<ActiveLocal>> active(compiled.registers);
        std::vector<std::optional<DexDebugLocal>> previous(compiled.registers);
        bool debug_output_overflow = false;
        std::uint32_t pc = 0;
        std::int64_t line = line_start;
        std::uint32_t file_index = UINT32_MAX;
        std::size_t opcode_count = 0;
        bool ended = false;
        auto close_local = [&](std::uint32_t reg) {
            if (!active[reg]) return;
            auto local = std::move(active[reg]->local);
            local.end = pc * 2;
            if (local.begin < local.end) {
                const auto bytes = sizeof(DexDebugLocal) + (local.name ? local.name->size() : 0) +
                    (local.type ? local.type->size() : 0) + (local.signature ? local.signature->size() : 0);
                if (decoded.locals.size() >= 2'000'000 || !account_debug_bytes(bytes)) debug_output_overflow = true;
                else decoded.locals.push_back(local);
            }
            previous[reg] = std::move(local);
            active[reg].reset();
        };
        auto emit_line = [&]() -> bool {
            if (pc > compiled.byte_size / 2 || line < 0 || line > UINT32_MAX) return false;
            DexDebugLine row; row.address = pc * 2; row.line = static_cast<std::uint32_t>(line);
            if (file_index != UINT32_MAX) {
                if (!account_debug_bytes(sizeof(DexDebugLine) + strings[file_index].size())) return false;
                row.source_file = strings[file_index];
            } else if (!account_debug_bytes(sizeof(DexDebugLine))) return false;
            decoded.lines.push_back(std::move(row)); return true;
        };
        while (!dr.bytes.empty() && dr.pos < dr.bytes.size()) {
            if (++opcode_count > 2'000'000) return Error{ErrorCode::resource_limit,"DEX debug program exceeds opcode limit"};
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"DEX debug-info parsing canceled"};
            const auto opcode = std::to_integer<std::uint8_t>(dr.bytes[dr.pos++]);
            std::uint32_t a = 0, b = 0, c = 0;
            if (opcode == 0) {
                ended = true;
                for (std::uint32_t reg = 0; reg < active.size(); ++reg) close_local(reg);
                break;
            } else if (opcode == 1) {
                if (!dr.uleb(a) || a > compiled.byte_size / 2 - std::min(pc, compiled.byte_size / 2)) return Error{ErrorCode::malformed,"DEX debug address exceeds method"};
                pc += a;
            } else if (opcode == 2) {
                std::int32_t delta = 0; if (!dr.sleb(delta) || (delta < 0 && line < -std::int64_t(delta)) || (delta > 0 && line > INT32_MAX - delta)) return Error{ErrorCode::malformed,"DEX debug line adjustment overflows"};
                line += delta;
            } else if (opcode == 3 || opcode == 4) {
                if (!dr.uleb(a) || !dr.uleb(b) || !dr.uleb(c) || a >= compiled.registers || (b && b - 1 >= strings.size()) || (c && c - 1 >= types.size())) return Error{ErrorCode::malformed,"DEX debug local entry is invalid"};
                std::uint32_t signature = 0;
                if (opcode == 4 && (!dr.uleb(signature) || (signature && signature - 1 >= strings.size()))) return Error{ErrorCode::malformed,"DEX debug local signature is invalid"};
                close_local(a);
                DexDebugLocal local; local.register_index = a; local.begin = pc * 2;
                const auto local_bytes = sizeof(DexDebugLocal) + (b ? strings[b - 1].size() : 0) +
                    (c ? types[c - 1].size() : 0) + (signature ? strings[signature - 1].size() : 0);
                if (!account_debug_bytes(local_bytes)) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds 64 MiB"};
                if (b) local.name = strings[b - 1]; if (c) local.type = types[c - 1];
                if (signature) local.signature = strings[signature - 1];
                active[a] = ActiveLocal{std::move(local)};
            } else if (opcode == 5 || opcode == 6) {
                if (!dr.uleb(a) || a >= compiled.registers) return Error{ErrorCode::malformed,"DEX debug local register is invalid"};
                if (opcode == 5) close_local(a);
                else {
                    if (active[a] || !previous[a]) return Error{ErrorCode::malformed,"DEX debug restart_local has no ended local"};
                    auto local = *previous[a]; local.begin = pc * 2; local.end = 0;
                    const auto bytes = sizeof(DexDebugLocal) + (local.name ? local.name->size() : 0) +
                        (local.type ? local.type->size() : 0) + (local.signature ? local.signature->size() : 0);
                    if (!account_debug_bytes(bytes)) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds 64 MiB"};
                    active[a] = ActiveLocal{std::move(local)};
                }
            } else if (opcode == 7 || opcode == 8) {
                // Prologue/epilogue markers do not change the address/line state.
            } else if (opcode == 9) {
                if (!dr.uleb(a) || (a && a - 1 >= strings.size())) return Error{ErrorCode::malformed,"DEX debug source-file index is invalid"};
                file_index = a ? a - 1 : UINT32_MAX;
            } else if (opcode >= 0x0a) {
                constexpr std::uint32_t opcode_base = 0x0a, line_range = 15;
                const auto adjusted = opcode - opcode_base;
                const auto address_delta = adjusted / line_range;
                if (address_delta > compiled.byte_size / 2 - std::min(pc, compiled.byte_size / 2)) return Error{ErrorCode::malformed,"DEX debug special address exceeds method"};
                pc += address_delta; line += -4 + static_cast<std::int32_t>(adjusted % line_range);
                if (!emit_line()) return Error{ErrorCode::malformed,"DEX debug source row is outside the method"};
            } else return Error{ErrorCode::malformed,"Invalid DEX debug opcode"};
            if (pc > compiled.byte_size / 2) return Error{ErrorCode::malformed,"DEX debug address exceeds method"};
        }
        if (!ended) return Error{ErrorCode::malformed,"DEX debug program has no end_sequence"};
        if (debug_output_overflow) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds its output budget"};
        total_debug_rows += decoded.lines.size() + decoded.locals.size();
        if (total_debug_rows > 2'000'000 || decoded.lines.size() > 2'000'000 || decoded.locals.size() > 2'000'000) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds its output budget"};
        dex_metadata.methods.push_back(std::move(decoded));
    }
    std::sort(code.begin(),code.end(),[](const Code&a,const Code&b){return a.method<b.method;});
    ImageLayout layout{{{0},32,2,ByteOrder::little},Architecture::dex,ExecutionMode::dex,{}, {}};
    layout.segments.reserve(code.size());layout.entries.reserve(code.size());layout.domains.reserve(code.size());
    for(const auto &c:code){
        const AddressSpaceId space{c.method+1};
        const DecodeContext context{Architecture::dex,ExecutionMode::dex,ByteOrder::little};
        layout.domains.push_back({AddressSpace{space,32,2,ByteOrder::little},context});
        const Address begin{space,0};
        layout.segments.push_back({method_name(c.method),begin,c.byte_size,{c.file_offset},c.byte_size,true,false,true});
        layout.entries.push_back(begin);
    }
    auto image=Image::create(std::move(storage),std::move(layout));if(!image)return image.error();
    LoadedImage loaded;loaded.image=std::move(image.value());loaded.metadata.format=dex041_single_member?"Dalvik DEX 041 (single-member)":"Dalvik DEX (035-040)";loaded.metadata.image_size=file_size;loaded.metadata_complete=false;
    loaded.metadata.dex = std::move(dex_metadata);
    loaded.diagnostics.push_back({DiagnosticSeverity::info,"DEX methods are mapped to method-relative address spaces; checksum/signature validation and full verifier semantics are not implemented",{}});
    auto read=loaded.metadata_reads.include({0},file_size);if(!read)return read.error();loaded.metadata_reads_complete=true;return loaded;
}
}

Result<LoadedImage> load_dex(std::shared_ptr<const ByteStorage> storage,std::stop_token stop){
    if(!storage)return Error{ErrorCode::invalid_argument,"DEX loader requires input storage"};
    if(stop.stop_requested())return Error{ErrorCode::canceled,"DEX loading canceled"};
    try{return parse(std::move(storage),stop);}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate DEX parser state"};}catch(const std::length_error&){return Error{ErrorCode::resource_limit,"DEX parser state exceeds container limits"};}
}
} // namespace hexlab
