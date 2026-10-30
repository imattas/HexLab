#include "hexlab/loaders/dex.hpp"
#include "hexlab/loaders/dex_container.hpp"
#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hexlab {
namespace {
constexpr std::uint64_t max_file_size = UINT64_C(512) * 1024 * 1024;
constexpr std::uint32_t max_items = 1'000'000;
constexpr std::size_t max_loaded_dex041_members = 256;
constexpr std::uint64_t max_dex041_aggregate_rows = 2'000'000;
constexpr std::uint64_t max_dex041_aggregate_strings = 64ull * 1024 * 1024;
constexpr std::uint64_t max_dex041_aggregate_metadata_capacity = 256ull * 1024 * 1024;
constexpr std::uint64_t max_dex041_aggregate_class_member_rows = 1'000'000;
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

bool next_utf8_codepoint(std::string_view text, std::size_t &cursor, std::uint32_t &codepoint) {
    if (cursor >= text.size()) return false;
    const auto lead = static_cast<std::uint8_t>(text[cursor++]);
    if (lead < 0x80) { codepoint = lead; return true; }
    unsigned continuation_count = 0;
    if ((lead & 0xe0) == 0xc0) { continuation_count = 1; codepoint = lead & 0x1f; }
    else if ((lead & 0xf0) == 0xe0) { continuation_count = 2; codepoint = lead & 0x0f; }
    else if ((lead & 0xf8) == 0xf0) { continuation_count = 3; codepoint = lead & 0x07; }
    else return false;
    if (text.size() - cursor < continuation_count) return false;
    for (unsigned i = 0; i < continuation_count; ++i) {
        const auto next = static_cast<std::uint8_t>(text[cursor++]);
        if ((next & 0xc0) != 0x80) return false;
        codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if ((continuation_count == 1 && codepoint < 0x80) ||
        (continuation_count == 2 && codepoint < 0x800) ||
        (continuation_count == 3 && codepoint < 0x10000) || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) return false;
    return true;
}

bool dex_utf16_key(std::string_view text, std::vector<std::uint16_t> &key) {
    key.clear();
    for (std::size_t cursor = 0; cursor < text.size();) {
        std::uint32_t cp = 0;
        if (!next_utf8_codepoint(text, cursor, cp)) return false;
        if (cp <= 0xffff) key.push_back(static_cast<std::uint16_t>(cp));
        else {
            cp -= 0x10000;
            key.push_back(static_cast<std::uint16_t>(0xd800 + (cp >> 10)));
            key.push_back(static_cast<std::uint16_t>(0xdc00 + (cp & 0x3ff)));
        }
    }
    return true;
}

bool dex_simple_name_codepoint(std::uint32_t cp, unsigned version) {
    if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') ||
        (cp >= '0' && cp <= '9') || cp == '$' || cp == '-' || cp == '_') return true;
    if (version >= 40 && (cp == ' ' || cp == 0x00a0 || (cp >= 0x2000 && cp <= 0x200a))) return true;
    return (cp >= 0x00a1 && cp <= 0x1fff) || (cp >= 0x2010 && cp <= 0x2027) || cp == 0x202f ||
           (cp >= 0x2030 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xffef) ||
           (cp >= 0x10000 && cp <= 0x10ffff);
}

bool valid_dex_simple_name(std::string_view name, unsigned version) {
    if (name.empty()) return false;
    std::size_t cursor = 0;
    while (cursor < name.size()) {
        std::uint32_t cp = 0;
        if (!next_utf8_codepoint(name, cursor, cp) || !dex_simple_name_codepoint(cp, version)) return false;
    }
    return true;
}

bool valid_dex_member_name(std::string_view name, unsigned version) {
    if (name.size() >= 2 && name.front() == '<' && name.back() == '>')
        return valid_dex_simple_name(name.substr(1, name.size() - 2), version);
    return valid_dex_simple_name(name, version);
}

bool valid_dex_full_class_name(std::string_view name, unsigned version) {
    if (name.empty()) return false;
    std::size_t cursor = 0;
    std::size_t segment_begin = 0;
    while (cursor < name.size()) {
        std::uint32_t cp = 0;
        if (!next_utf8_codepoint(name, cursor, cp)) return false;
        if (cp == '/') {
            if (!valid_dex_simple_name(name.substr(segment_begin, cursor - segment_begin - 1), version)) return false;
            segment_begin = cursor;
        }
    }
    return valid_dex_simple_name(name.substr(segment_begin), version);
}

bool valid_dex_type_descriptor(std::string_view descriptor, unsigned version, bool allow_void) {
    if (descriptor == "V") return allow_void;
    std::size_t cursor = 0;
    while (cursor < descriptor.size() && descriptor[cursor] == '[') {
        if (++cursor > 255) return false;
    }
    if (cursor >= descriptor.size()) return false;
    const auto kind = descriptor[cursor++];
    if (kind == 'L') {
        if (descriptor.back() != ';' || cursor + 1 > descriptor.size()) return false;
        return valid_dex_full_class_name(descriptor.substr(cursor, descriptor.size() - cursor - 1), version);
    }
    if (cursor != descriptor.size() || kind == 'V') return false;
    return kind == 'Z' || kind == 'B' || kind == 'S' || kind == 'C' || kind == 'I' ||
           kind == 'J' || kind == 'F' || kind == 'D';
}

char dex_shorty_type(std::string_view descriptor) {
    if (descriptor.empty()) return '\0';
    return descriptor.front() == 'L' || descriptor.front() == '[' ? 'L' : descriptor.front();
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
    std::vector<DexMapItem> items;
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
    result.items.reserve(count);
    result.offsets.reserve(count);
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint16_t type = 0, unused = 0; std::uint32_t size = 0, item_off = 0;
        if (!r.u16(type) || !r.u16(unused) || !r.u32(size) || !r.u32(item_off) || unused || type >= seen.size() || seen[type] ||
            item_off > bytes.size() || (i && (item_off < previous ||
                (item_off == previous && (size || result.items.back().size)))))
            return Error{ErrorCode::malformed, "DEX map entry is invalid, duplicated, or out of order"};
        seen[type] = true; previous = item_off; result.offsets.push_back(item_off);
        result.items.push_back({type, size, item_off});
        if (type == 0x0007) { result.has_call_sites = true; result.call_site_count = size; result.call_site_off = item_off; }
        if (type == 0x0008) { result.has_method_handles = true; result.method_handle_count = size; result.method_handle_off = item_off; }
        if (type == 0xf000) { result.has_hiddenapi = true; result.hiddenapi_count = size; result.hiddenapi_off = item_off; }
        if (size && item_off == bytes.size()) return Error{ErrorCode::malformed, "DEX map entry starts at end of file"};
    }
    return result;
}

Result<LoadedImage> parse(std::shared_ptr<const ByteStorage> storage, std::span<const std::byte> bytes,
                          std::uint32_t member_header_offset, std::stop_token stop) {
    const auto file_size = bytes.size();
    if (file_size < header_bytes) return Error{ErrorCode::malformed, "Truncated DEX header"};
    if (file_size > max_file_size || file_size > SIZE_MAX)
        return Error{ErrorCode::resource_limit, "DEX input exceeds the 512 MiB parser limit"};
    if (member_header_offset > file_size || file_size - member_header_offset < header_bytes)
        return Error{ErrorCode::malformed, "DEX member header is outside the physical container"};
    if (std::memcmp(bytes.data() + member_header_offset, "dex\n", 4) != 0 || bytes[member_header_offset + 7] != std::byte{0})
        return Error{ErrorCode::malformed, "Invalid DEX magic"};
    for (std::size_t i = 4; i <= 6; ++i)
        if (bytes[member_header_offset + i] < std::byte{'0'} || bytes[member_header_offset + i] > std::byte{'9'})
            return Error{ErrorCode::malformed, "DEX version field is not decimal"};
    const auto version = (std::to_integer<unsigned>(bytes[member_header_offset + 4]) - '0') * 100 +
                         (std::to_integer<unsigned>(bytes[member_header_offset + 5]) - '0') * 10 +
                         (std::to_integer<unsigned>(bytes[member_header_offset + 6]) - '0');
    bool dex041_single_member = false;
    std::uint32_t dex041_logical_size = 0;
    if (version == 41) {
        if (file_size - member_header_offset < dex041_header_bytes)
            return Error{ErrorCode::malformed, "Truncated DEX 041 header"};
        Reader container_header{bytes}; container_header.seek(member_header_offset + 32);
        std::uint32_t declared_header=0, endian=0;
        if (!container_header.u32(dex041_logical_size) || !container_header.u32(declared_header) ||
            !container_header.u32(endian) || !container_header.seek(member_header_offset + 0x70))
            return Error{ErrorCode::malformed, "Truncated DEX 041 container header fields"};
        std::uint32_t container_size=0, declared_header_offset=0;
        if (!container_header.u32(container_size) || !container_header.u32(declared_header_offset))
            return Error{ErrorCode::malformed, "Truncated DEX 041 container bounds"};
        if (declared_header != dex041_header_bytes || endian != 0x12345678 ||
            container_size != file_size || declared_header_offset != member_header_offset || dex041_logical_size < dex041_header_bytes ||
            dex041_logical_size > container_size - member_header_offset)
            return Error{ErrorCode::malformed, "DEX 041 header or container bounds are inconsistent with the physical input"};
        dex041_single_member = true;
    } else if (member_header_offset != 0) {
        return Error{ErrorCode::malformed, "Only DEX 041 members may have a nonzero header offset"};
    }
    if (version < 35 || (version > 40 && !dex041_single_member))
        return Error{ErrorCode::unsupported, "DEX versions 035 through 040 and DEX 041 members are supported"};
    Reader h{bytes}; h.seek(member_header_offset + 32);
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
    if ((link_size == 0) != (link_off == 0) ||
        (link_size && link_off < member_header_offset + (dex041_single_member ? dex041_header_bytes : header_bytes)))
        return Error{ErrorCode::malformed, "DEX link_size and link_off must both be zero or both be nonzero"};
    bool hash_canceled = false;
    const auto logical_size = dex041_single_member ? dex041_logical_size : static_cast<std::uint32_t>(file_size);
    if (logical_size > file_size - member_header_offset)
        return Error{ErrorCode::malformed, "DEX logical file extent exceeds the physical input"};
    const auto signature = sha1(bytes.subspan(member_header_offset + 32, logical_size - 32), stop, hash_canceled);
    if (hash_canceled) return Error{ErrorCode::canceled, "DEX signature validation canceled"};
    if (!std::equal(signature.begin(), signature.end(), bytes.begin() + member_header_offset + 12))
        return Error{ErrorCode::malformed, "DEX SHA-1 signature mismatch at file offset 0x0c"};
    const auto stored_checksum = std::uint32_t(std::to_integer<std::uint8_t>(bytes[member_header_offset + 8])) |
                                 (std::uint32_t(std::to_integer<std::uint8_t>(bytes[member_header_offset + 9])) << 8) |
                                 (std::uint32_t(std::to_integer<std::uint8_t>(bytes[member_header_offset + 10])) << 16) |
                                 (std::uint32_t(std::to_integer<std::uint8_t>(bytes[member_header_offset + 11])) << 24);
    const auto computed_checksum = adler32(bytes.subspan(member_header_offset + 12, logical_size - 12), stop);
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX checksum validation canceled"};
    if (computed_checksum != stored_checksum)
        return Error{ErrorCode::malformed, "DEX Adler-32 checksum mismatch at file offset 0x08"};
    if (string_count > max_items || type_count > max_items || proto_count > max_items || method_count > max_items || class_count > max_items || field_count > max_items)
        return Error{ErrorCode::resource_limit, "DEX identifier table exceeds one million items"};
    if (dex041_single_member) {
        // DEX 041 offsets address the physical container and data may be
        // shared by members. Treat all bytes after this member's header as
        // candidates, then use each mapped section's own extent checks.
        data_off = member_header_offset + dex041_header_bytes;
        data_size = static_cast<std::uint32_t>(file_size - data_off);
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
    if (map_off < data_off)
        return Error{ErrorCode::malformed, "DEX map_list is outside the data section"};
    // The map_list is a directory over the physical file. Apart from the
    // header and fixed identifier tables, mapped sections belong to the data
    // area. Check their start and the format-defined alignment even when a
    // section is not otherwise decoded by this loader.
    const auto data_end = std::uint64_t(data_off) + data_size;
    for (const auto &item : map.value().items) {
        if (item.type <= 0x0008 || item.type == 0x1000) continue;
        if (item.offset < data_off || item.offset >= data_end)
            return Error{ErrorCode::malformed, "DEX mapped data section starts outside the declared data area"};
        const bool word_aligned = item.type == 0x1001 || item.type == 0x1002 ||
            item.type == 0x1003 || item.type == 0x1005 || item.type == 0x100a || item.type == 0xf000;
        if (word_aligned && (item.offset & 3))
            return Error{ErrorCode::malformed, "DEX mapped data section violates its four-byte alignment"};
    }
    auto map_item = [&](std::uint16_t type) -> const DexMapItem * {
        const auto found = std::find_if(map.value().items.begin(), map.value().items.end(),
            [&](const DexMapItem &item) { return item.type == type; });
        return found == map.value().items.end() ? nullptr : &*found;
    };
    const auto header_item = map_item(0x0000);
    const auto map_list_item = map_item(0x1000);
    if (!header_item || header_item->size != 1 || header_item->offset != member_header_offset ||
        !map_list_item || map_list_item->size != 1 || map_list_item->offset != map_off)
        return Error{ErrorCode::malformed, "DEX map_list must describe the header and its own map section"};
    auto fixed_section_matches = [&](std::uint16_t type, std::uint32_t count,
                                     std::uint32_t offset, std::uint32_t item_size) {
        const auto *item = map_item(type);
        if (count == 0)
            return !item || item->size == 0;
        if (!item || item->size != count || item->offset != offset ||
            (type != 0x0000 && offset < member_header_offset +
                (dex041_single_member ? dex041_header_bytes : header_bytes)))
            return false;
        const auto extent_end = std::uint64_t(offset) + std::uint64_t(count) * item_size;
        const auto next = std::upper_bound(map.value().offsets.begin(), map.value().offsets.end(), offset);
        const auto section_end = next == map.value().offsets.end() ? file_size : *next;
        return extent_end <= section_end;
    };
    if (!fixed_section_matches(0x0000, 1, member_header_offset,
                               dex041_single_member ? dex041_header_bytes : header_bytes) ||
        !fixed_section_matches(0x0001, string_count, string_off, 4) ||
        !fixed_section_matches(0x0002, type_count, type_off, 4) ||
        !fixed_section_matches(0x0003, proto_count, proto_off, 12) ||
        !fixed_section_matches(0x0004, field_count, field_off, 8) ||
        !fixed_section_matches(0x0005, method_count, method_off, 8) ||
        !fixed_section_matches(0x0006, class_count, class_off, 32) ||
        !fixed_section_matches(0x0007, map.value().call_site_count, map.value().call_site_off, 4) ||
        !fixed_section_matches(0x0008, map.value().method_handle_count, map.value().method_handle_off, 8))
        return Error{ErrorCode::malformed, "DEX map entries disagree with header table extents or overlap the next section"};
    const auto map_list_end = std::uint64_t(map_off) + 4 + map.value().items.size() * 12;
    const auto next_map_section = std::upper_bound(map.value().offsets.begin(), map.value().offsets.end(), map_off);
    if (map_list_end > (next_map_section == map.value().offsets.end() ? file_size : *next_map_section))
        return Error{ErrorCode::malformed, "DEX map_list overlaps the next mapped section"};
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

    constexpr std::uint64_t max_identifier_model_bytes = 64ull * 1024 * 1024;
    const auto identifier_row_bytes = std::uint64_t(string_count) * (sizeof(std::string) + sizeof(DexStringSource)) +
        std::uint64_t(field_count) * sizeof(DexFieldIdentifier) + std::uint64_t(method_count) * sizeof(DexMethodIdentifier);
    if (identifier_row_bytes > max_identifier_model_bytes)
        return Error{ErrorCode::resource_limit, "DEX identifier catalogs exceed 64 MiB"};
    std::vector<std::string> strings; strings.reserve(string_count);
    std::vector<DexStringSource> string_sources; string_sources.reserve(string_count);
    std::uint64_t decoded_string_bytes = 0;
    std::vector<std::uint16_t> previous_string_key, current_string_key;
    Reader ids{bytes};
    for (std::uint32_t i=0;i<string_count;++i) {
        if ((i & 0xffu) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "DEX identifier parsing canceled"};
        if (!ids.seek(string_off + std::size_t(i)*4)) return Error{ErrorCode::malformed,"DEX string_ids offset is invalid"};
        std::uint32_t off=0; if(!ids.u32(off)||off<data_off||off>=std::uint64_t(data_off)+data_size) return Error{ErrorCode::malformed,"DEX string_data offset is outside data section"};
        Reader str{bytes}; str.seek(off); std::uint32_t utf16_size=0;
        if(!str.uleb(utf16_size)||utf16_size>1'000'000) return Error{ErrorCode::malformed,"DEX string length is invalid"};
        const auto begin=str.pos; while(str.pos<bytes.size()&&str.pos-begin<=3'000'000&&bytes[str.pos]!=std::byte{0}) ++str.pos;
        if(str.pos==bytes.size()||str.pos-begin>3'000'000) return Error{ErrorCode::malformed,"DEX string terminator is missing or exceeds the string budget"};
        std::string value; if(!decode_mutf8(bytes.subspan(begin,str.pos-begin),utf16_size,value)) return Error{ErrorCode::malformed,"DEX string is not valid modified UTF-8 or its UTF-16 length disagrees"};
        if(value.size()>4'000'000) return Error{ErrorCode::resource_limit,"Decoded DEX string exceeds the size budget"};
        if (!dex_utf16_key(value, current_string_key) ||
            (i && !(previous_string_key < current_string_key)))
            return Error{ErrorCode::malformed, "DEX string_ids are not uniquely sorted by UTF-16 contents"};
        previous_string_key = current_string_key;
        decoded_string_bytes += value.size();
        if(decoded_string_bytes > max_identifier_model_bytes - identifier_row_bytes)
            return Error{ErrorCode::resource_limit,"DEX identifier catalogs and strings exceed 64 MiB"};
        string_sources.push_back({string_off + i * 4, off, static_cast<std::uint32_t>(str.pos + 1 - off), utf16_size});
        strings.push_back(std::move(value));
    }
    std::vector<std::string> types; types.reserve(type_count);
    std::uint32_t previous_type_descriptor = 0;
    for(std::uint32_t i=0;i<type_count;++i){
        ids.seek(type_off+std::size_t(i)*4);std::uint32_t string_idx=0;
        if(!ids.u32(string_idx)||string_idx>=strings.size())return Error{ErrorCode::malformed,"DEX type_id references an invalid string"};
        if (i && string_idx <= previous_type_descriptor)
            return Error{ErrorCode::malformed, "DEX type_ids are not uniquely sorted by descriptor_idx"};
        previous_type_descriptor = string_idx;
        types.push_back(strings[string_idx]);
    }
    for (const auto &descriptor : types)
        if (!valid_dex_type_descriptor(descriptor, version, true))
            return Error{ErrorCode::malformed, "DEX type_id contains an invalid TypeDescriptor"};
    std::vector<Field> fields; fields.reserve(field_count);
    std::optional<std::tuple<std::uint16_t, std::uint32_t, std::uint16_t>> previous_field_key;
    for(std::uint32_t i=0;i<field_count;++i){
        ids.seek(field_off+std::size_t(i)*8);Field f;
        if(!ids.u16(f.owner)||!ids.u16(f.type)||!ids.u32(f.name)||f.owner>=types.size()||f.type>=types.size()||f.name>=strings.size())
            return Error{ErrorCode::malformed,"DEX field_id contains an invalid index"};
        if (types[f.owner].front() != 'L' || types[f.type] == "V" ||
            !valid_dex_member_name(strings[f.name], version))
            return Error{ErrorCode::malformed, "DEX field_id has an invalid owner, void field type, or member name"};
        const auto key = std::tuple{f.owner, f.name, f.type};
        if (previous_field_key && !(*previous_field_key < key))
            return Error{ErrorCode::malformed, "DEX field_ids are not uniquely sorted by class, name, and type"};
        previous_field_key = key;
        fields.push_back(f);
    }
    std::vector<Proto> protos; protos.reserve(proto_count);
    std::uint32_t previous_proto_return = 0;
    std::vector<std::uint16_t> previous_proto_parameters;
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
            for(std::uint32_t j=0;j<n;++j){std::uint16_t t=0;if(!list.u16(t)||t>=types.size()||types[t]=="V")return Error{ErrorCode::malformed,"DEX proto parameter type is invalid or void"};p.parameters.push_back(t);}
        }
        const auto &shorty_descriptor = strings[shorty];
        if (shorty_descriptor.size() != p.parameters.size() + 1 ||
            shorty_descriptor.front() != dex_shorty_type(types[ret]))
            return Error{ErrorCode::malformed, "DEX proto shorty descriptor disagrees with its return type or parameter count"};
        for (std::size_t parameter = 0; parameter < p.parameters.size(); ++parameter)
            if (shorty_descriptor[parameter + 1] != dex_shorty_type(types[p.parameters[parameter]]))
                return Error{ErrorCode::malformed, "DEX proto shorty descriptor disagrees with a parameter type"};
        if (i && (ret < previous_proto_return ||
                  (ret == previous_proto_return && !(previous_proto_parameters < p.parameters))))
            return Error{ErrorCode::malformed, "DEX proto_ids are not uniquely sorted by return type and argument list"};
        previous_proto_return = ret;
        previous_proto_parameters = p.parameters;
        protos.push_back(std::move(p));
    }
    std::vector<Method> methods; methods.reserve(method_count);
    std::optional<std::tuple<std::uint16_t, std::uint32_t, std::uint16_t>> previous_method_key;
    for(std::uint32_t i=0;i<method_count;++i){
        ids.seek(method_off+std::size_t(i)*8);Method m;
        if(!ids.u16(m.owner)||!ids.u16(m.proto)||!ids.u32(m.name)||m.owner>=types.size()||m.proto>=protos.size()||m.name>=strings.size())return Error{ErrorCode::malformed,"DEX method_id contains an invalid index"};
        if ((types[m.owner].front() != 'L' && types[m.owner].front() != '[') ||
            !valid_dex_member_name(strings[m.name], version))
            return Error{ErrorCode::malformed, "DEX method_id owner or member name is invalid"};
        const auto key = std::tuple{m.owner, m.name, m.proto};
        if (previous_method_key && !(*previous_method_key < key))
            return Error{ErrorCode::malformed, "DEX method_ids are not uniquely sorted by class, name, and prototype"};
        previous_method_key = key;
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
    std::uint32_t previous_call_site_offset = 0;
    std::vector<DexAnnotationItem> decoded_annotations;
    std::vector<DexAnnotationLink> annotation_links;
    std::vector<DexAnnotationSet> decoded_annotation_sets;
    std::vector<DexAnnotationSetRefList> decoded_annotation_ref_lists;
    std::vector<DexAnnotationDirectory> decoded_annotation_directories;
    std::unordered_map<std::uint32_t, std::uint32_t> annotation_item_indices;
    std::unordered_map<std::uint32_t, std::uint32_t> annotation_set_indices;
    std::unordered_map<std::uint32_t, std::uint32_t> annotation_ref_list_indices;
    std::uint64_t total_annotation_set_entries = 0;
    std::uint64_t total_annotation_sets = 0;
    std::uint64_t total_annotation_directory_entries = 0;
    std::uint64_t total_annotation_parameter_slots = 0;
    std::uint64_t total_annotation_links = 0;
    std::uint64_t total_annotation_model_bytes = 0;
    std::uint64_t total_hiddenapi_model_bytes = 0;
    std::unordered_set<std::uint32_t> class_data_offsets;
    std::uint64_t total_code_units=0;
    std::uint64_t total_type_flow_cells=0;
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
            if (type >= types.size() || types[type].front() != 'L')
                return Error{ErrorCode::malformed, "DEX encoded_annotation type must reference a class type"};
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
        value.byte_size = reader.pos - value.file_offset;
        return value;
    };
    const auto dex_data_end = static_cast<std::size_t>(std::uint64_t(data_off) + data_size);
    for (std::uint32_t i = 0; i < map.value().call_site_count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX call-site parsing canceled"};
        Reader call_site_id{bytes};
        if (!call_site_id.seek(map.value().call_site_off + std::size_t(i) * 4))
            return Error{ErrorCode::malformed, "DEX call_site_id_item offset is invalid"};
        std::uint32_t item_off=0;
        if (!call_site_id.u32(item_off) || item_off < data_off || item_off >= dex_data_end ||
            (i && item_off <= previous_call_site_offset))
            return Error{ErrorCode::malformed, "DEX call_site_ids are invalid or not strictly sorted by call_site_off"};
        previous_call_site_offset = item_off;
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
            if (value_index == 0 && decoded_method_handles[value.value().payload].kind != 4)
                return Error{ErrorCode::malformed,
                    "DEX call_site_item bootstrap handle must use the invoke-static method-handle kind"};
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
        if (visibility > 2 || !item.uleb(type) || !item.uleb(count) || type >= types.size() || types[type].front() != 'L')
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
            if (!item.uleb(name) || name >= strings.size() || (i && name <= previous_name) ||
                !valid_dex_member_name(strings[name], version))
                return Error{ErrorCode::malformed, "DEX annotation element names are invalid or unordered"};
            previous_name = name;
            auto value = decode_encoded_value(item, name, 0);
            if (!value) return value.error();
            annotation.elements.push_back(std::move(value.value()));
        }
        annotation.byte_size=item.pos-offset;
        const auto index = static_cast<std::uint32_t>(decoded_annotations.size());
        decoded_annotations.push_back(std::move(annotation));
        annotation_item_indices.emplace(offset, index);
        return index;
    };
    std::function<Result<std::uint32_t>(std::uint32_t)> read_annotation_set;
    read_annotation_set = [&](std::uint32_t offset) -> Result<std::uint32_t> {
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
        const auto set_bytes=sizeof(DexAnnotationSet)+std::uint64_t(count)*sizeof(std::uint32_t);
        if (total_annotation_model_bytes>max_annotation_bytes || set_bytes>max_annotation_bytes-total_annotation_model_bytes)
            return Error{ErrorCode::resource_limit, "DEX annotation-set metadata exceeds 64 MiB"};
        total_annotation_model_bytes += set_bytes;
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
        const auto index=static_cast<std::uint32_t>(decoded_annotation_sets.size());
        decoded_annotation_sets.push_back({offset,4+std::uint64_t(count)*4,std::move(indices)});
        annotation_set_indices.emplace(offset,index);
        return index;
    };
    auto add_annotation_links = [&](DexAnnotationTargetKind kind, std::uint32_t class_def_index,
                                    std::uint32_t member_index, std::uint32_t parameter_index,
                                    std::uint32_t set_offset, std::uint64_t source_offset) -> Result<bool> {
        if (!set_offset) return true;
        auto set_index = read_annotation_set(set_offset);
        if (!set_index) return set_index.error();
        constexpr std::uint64_t max_annotation_links = 1'000'000;
        constexpr std::uint64_t max_annotation_bytes = 64ull * 1024 * 1024;
        for (const auto annotation_index : decoded_annotation_sets[set_index.value()].annotation_indices) {
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
        constexpr std::uint64_t max_annotation_bytes=64ull*1024*1024;
        const auto directory_bytes=sizeof(DexAnnotationDirectory)+entry_count*sizeof(DexAnnotationDirectoryEntry);
        if(total_annotation_model_bytes>max_annotation_bytes||directory_bytes>max_annotation_bytes-total_annotation_model_bytes)
            return Error{ErrorCode::resource_limit,"DEX annotation-directory metadata exceeds 64 MiB"};
        total_annotation_model_bytes+=directory_bytes;
        DexAnnotationDirectory retained_directory;
        retained_directory.class_def_index=class_def_index;retained_directory.class_annotations_offset=class_set;
        retained_directory.file_offset=offset;retained_directory.byte_size=16+entry_count*8;
        retained_directory.fields.reserve(field_count);retained_directory.methods.reserve(method_count);retained_directory.parameters.reserve(parameter_count);
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
            retained_directory.fields.push_back({field_index,set_offset,entry_offset});
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
            retained_directory.methods.push_back({method_index,set_offset,entry_offset});
        }
        previous_index = 0;
        for (std::uint32_t i = 0; i < parameter_count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX parameter-annotation parsing canceled"};
            const auto entry_offset=directory.pos;
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
            const bool new_list=!annotation_ref_list_indices.contains(ref_list_offset);
            DexAnnotationSetRefList retained_refs;
            if(new_list){
                const auto refs_bytes=sizeof(DexAnnotationSetRefList)+std::uint64_t(count)*sizeof(std::uint32_t);
                if(total_annotation_model_bytes>max_annotation_bytes||refs_bytes>max_annotation_bytes-total_annotation_model_bytes)
                    return Error{ErrorCode::resource_limit,"DEX annotation set-ref metadata exceeds 64 MiB"};
                total_annotation_model_bytes+=refs_bytes;retained_refs.file_offset=ref_list_offset;
                retained_refs.byte_size=4+std::uint64_t(count)*4;retained_refs.set_offsets.reserve(count);
            }
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
                if(new_list)retained_refs.set_offsets.push_back(set_offset);
            }
            if(new_list){annotation_ref_list_indices.emplace(ref_list_offset,static_cast<std::uint32_t>(decoded_annotation_ref_lists.size()));decoded_annotation_ref_lists.push_back(std::move(retained_refs));}
            retained_directory.parameters.push_back({method_index,ref_list_offset,entry_offset});
        }
        decoded_annotation_directories.push_back(std::move(retained_directory));
        return true;
    };
    if (class_count > 250'000)
        return Error{ErrorCode::resource_limit, "DEX class definitions exceed 250,000"};
    std::vector<DexClassDefinition> decoded_classes;
    decoded_classes.reserve(class_count);
    std::uint64_t total_class_model_bytes = 0, total_class_interfaces = 0, total_class_members = 0;
    const auto account_class_model_bytes = [&](std::uint64_t amount) {
        constexpr std::uint64_t max_class_model_bytes = 64ull * 1024 * 1024;
        if (amount > max_class_model_bytes || total_class_model_bytes > max_class_model_bytes - amount)
            return false;
        total_class_model_bytes += amount;
        return true;
    };
    for(std::uint32_t ci=0;ci<class_count;++ci){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"DEX class-data parsing canceled"};
        ids.seek(class_off+std::size_t(ci)*32);std::uint32_t class_type=0,access=0,super=0,interfaces=0,source_file=0,annotations=0,class_data=0,static_values=0;
        if(!ids.u32(class_type)||!ids.u32(access)||!ids.u32(super)||!ids.u32(interfaces)||!ids.u32(source_file)||!ids.u32(annotations)||!ids.u32(class_data)||!ids.u32(static_values)||class_type>=types.size()||(super!=0xffffffffu&&super>=types.size())||(source_file!=0xffffffffu&&source_file>=strings.size()))return Error{ErrorCode::malformed,"DEX class_def contains an invalid index"};
        if (access & 0x00020000u)
            return Error{ErrorCode::malformed, "DEX class_def sets ACC_DECLARED_SYNCHRONIZED, which is forbidden on class definitions"};
        constexpr std::uint32_t class_access_mask = 0x00007631u;
        if (access & ~class_access_mask)
            return Error{ErrorCode::malformed, "DEX class_def contains access flags that are not defined for classes"};
        if ((access & 0x00002000u) && !(access & 0x00000200u))
            return Error{ErrorCode::malformed, "DEX annotation class is not marked as an interface"};
        if ((access & 0x00000200u) && !(access & 0x00000400u))
            return Error{ErrorCode::malformed, "DEX interface class is not marked abstract"};
        if (types[class_type].front() != 'L' || (super != UINT32_MAX && types[super].front() != 'L'))
            return Error{ErrorCode::malformed, "DEX class_def and superclass indexes must reference class types"};
        const auto data_end=std::uint64_t(data_off)+data_size;
        if((interfaces&&((interfaces&3)||interfaces<data_off||interfaces>=data_end))||
           (annotations&&(annotations<data_off||annotations>=data_end))||
           (class_data&&(class_data<data_off||class_data>=data_end))||
           (static_values&&(static_values<data_off||static_values>=data_end)))
            return Error{ErrorCode::malformed,"DEX class_def data offset is outside the data section"};
        DexClassDefinition class_definition;
        class_definition.class_index = class_type;
        class_definition.access_flags = access;
        if (super != UINT32_MAX) class_definition.superclass_index = super;
        if (source_file != UINT32_MAX) class_definition.source_file_index = source_file;
        class_definition.class_data_offset = class_data;
        class_definition.annotations_offset = annotations;
        if (interfaces) {
            Reader interface_list{bytes.first(static_cast<std::size_t>(data_end))};
            if (!interface_list.seek(interfaces)) return Error{ErrorCode::malformed, "DEX interface list offset is invalid"};
            std::uint32_t count = 0;
            if (!interface_list.u32(count) || count > max_items || !extent(interface_list.pos, count, 2, data_end))
                return Error{ErrorCode::malformed, "DEX interface list extent is invalid"};
            if (count > max_items - total_class_interfaces ||
                std::uint64_t(count) > (64ull * 1024 * 1024 - total_class_model_bytes) / sizeof(std::uint32_t))
                return Error{ErrorCode::resource_limit, "DEX class interface metadata exceeds one million rows or 64 MiB"};
            total_class_interfaces += count;
            total_class_model_bytes += std::uint64_t(count) * sizeof(std::uint32_t);
            class_definition.interface_indices.reserve(count);
            std::unordered_set<std::uint16_t> seen_interfaces;
            for (std::uint32_t i = 0; i < count; ++i) {
                std::uint16_t type = 0;
                if (!interface_list.u16(type) || type >= types.size() || types[type].front() != 'L')
                    return Error{ErrorCode::malformed, "DEX interface type index must reference a class type"};
                if (!seen_interfaces.insert(type).second)
                    return Error{ErrorCode::malformed, "DEX class_def interface list contains a duplicate type"};
                class_definition.interface_indices.push_back(type);
            }
        }
        if (total_class_model_bytes > 64ull * 1024 * 1024 - sizeof(DexClassDefinition))
            return Error{ErrorCode::resource_limit, "DEX class metadata exceeds 64 MiB"};
        total_class_model_bytes += sizeof(DexClassDefinition);
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
                constexpr std::uint32_t field_access_mask = 0x000050dfu;
                if (flags & ~field_access_mask)
                    return Error{ErrorCode::malformed, "DEX encoded field contains flags that are not defined for fields"};
                if (((flags & 0x00000008u) != 0) != (group == 0))
                    return Error{ErrorCode::malformed, "DEX encoded field static flag disagrees with its static/instance list"};
                if ((flags & 0x00000007u) && ((flags & 0x00000007u) & ((flags & 0x00000007u) - 1)))
                    return Error{ErrorCode::malformed, "DEX encoded field has conflicting visibility flags"};
                if ((flags & 0x00000050u) == 0x00000050u)
                    return Error{ErrorCode::malformed, "DEX encoded field cannot be both final and volatile"};
                field_idx+=delta;
                if(field_idx>=fields.size()||fields[field_idx].owner!=class_type)return Error{ErrorCode::malformed,"DEX encoded field index is invalid for its defining class"};
                declared_field_indices.push_back(static_cast<std::uint32_t>(field_idx));
                const auto &field = fields[field_idx];
                const auto name_bytes = strings[field.name].size();
                if (++total_class_members > max_items ||
                    !account_class_model_bytes(sizeof(DexDeclaredField) + name_bytes))
                    return Error{ErrorCode::resource_limit, "DEX declared member metadata exceeds one million rows or 64 MiB"};
                (group == 0 ? class_definition.static_fields : class_definition.instance_fields)
                    .push_back({static_cast<std::uint32_t>(field_idx), flags, strings[field.name]});
                class_member_order.push_back({DexHiddenApiMemberKind::field, static_cast<std::uint32_t>(field_idx)});
                if(group==0)static_field_indices.push_back(static_cast<std::uint32_t>(field_idx));
            }
        }
        for(std::uint64_t group=0;group<2;++group){
            const auto count=group?vm:dm;std::uint64_t method_idx=0;
            for(std::uint32_t n=0;n<count;++n){std::uint32_t delta=0,flags=0,code_off=0;if(!cd.uleb(delta)||!cd.uleb(flags)||!cd.uleb(code_off))return Error{ErrorCode::malformed,"Truncated DEX encoded method"};
                constexpr std::uint32_t method_access_mask = 0x00031dffu;
                if (flags & ~method_access_mask)
                    return Error{ErrorCode::malformed, "DEX encoded method contains flags that are not defined for methods"};
                if ((flags & 0x00000007u) && ((flags & 0x00000007u) & ((flags & 0x00000007u) - 1)))
                    return Error{ErrorCode::malformed, "DEX encoded method has conflicting visibility flags"};
                const bool direct = (flags & (0x00000008u | 0x00000002u | 0x00010000u)) != 0;
                if (direct != (group == 0))
                    return Error{ErrorCode::malformed, "DEX encoded method static/private/constructor flags disagree with its direct/virtual list"};
                const bool no_code = (flags & (0x00000100u | 0x00000400u)) != 0;
                if ((code_off == 0) != no_code)
                    return Error{ErrorCode::malformed, "DEX native/abstract method code offset is inconsistent"};
                if ((flags & 0x00000100u) && (flags & 0x00000400u))
                    return Error{ErrorCode::malformed, "DEX method cannot be both native and abstract"};
                if ((flags & 0x00000400u) &&
                    (flags & (0x00000002u | 0x00000008u | 0x00000010u | 0x00000020u |
                              0x00000800u | 0x00000100u | 0x00020000u)))
                    return Error{ErrorCode::malformed, "DEX abstract method has incompatible private/static/final/synchronized/native flags"};
                method_idx+=delta;
                if(method_idx>=methods.size()||methods[method_idx].owner!=class_type)return Error{ErrorCode::malformed,"DEX encoded method index is invalid for its defining class"};
                declared_method_indices.push_back(static_cast<std::uint32_t>(method_idx));
                const auto &method_id = methods[method_idx];
                const auto name_bytes = strings[method_id.name].size();
                if (++total_class_members > max_items ||
                    !account_class_model_bytes(sizeof(DexDeclaredMethod) + name_bytes))
                    return Error{ErrorCode::resource_limit, "DEX declared member metadata exceeds one million rows or 64 MiB"};
                (group == 0 ? class_definition.direct_methods : class_definition.virtual_methods)
                    .push_back({static_cast<std::uint32_t>(method_idx), flags, code_off, strings[method_id.name]});
                class_member_order.push_back({DexHiddenApiMemberKind::method, static_cast<std::uint32_t>(method_idx)});
                if(!code_off)continue;
                if((code_off&3)||code_off<data_off||code_off>=std::uint64_t(data_off)+data_size||!extent(code_off,1,16,file_size))return Error{ErrorCode::malformed,"DEX code_item header offset is invalid"};
                Reader cr{bytes};cr.seek(code_off);std::uint16_t registers=0,ins=0,outs=0,tries=0;std::uint32_t debug=0,insns=0;
                if(!cr.u16(registers)||!cr.u16(ins)||!cr.u16(outs)||!cr.u16(tries)||!cr.u32(debug)||!cr.u32(insns)||ins>registers||!extent(cr.pos,insns,2,file_size))return Error{ErrorCode::malformed,"DEX code_item header or instruction extent is invalid"};
                const auto &method = methods[method_idx];
                const auto &prototype = protos[method.proto];
                std::uint32_t expected_ins = (flags & 0x8u) ? 0u : 1u;
                for (const auto parameter_type : prototype.parameters) {
                    const auto &descriptor = types[parameter_type];
                    expected_ins += (descriptor == "J" || descriptor == "D") ? 2u : 1u;
                }
                if (ins != expected_ins)
                    return Error{ErrorCode::malformed, "DEX code_item ins_size does not match the method prototype and static flag"};
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
                // The shared decoder already exposes every register slot used
                // by its supported instructions. Reject references outside
                // this method's register file while leaving unknown opcodes to
                // the decoder's conservative unsupported path.
                std::uint32_t instruction_offset = 0;
                std::unordered_set<std::uint32_t> instruction_starts;
                std::unordered_set<std::uint32_t> payload_starts;
                std::vector<std::uint32_t> branch_targets, data_payload_targets, move_result_offsets;
                std::vector<std::tuple<std::uint32_t, std::uint32_t, bool>> switch_sources;
                struct DexControlInstruction {
                    std::uint32_t offset = 0, length = 0;
                    FlowKind flow = FlowKind::fallthrough;
                    std::optional<std::uint32_t> target;
                };
                std::vector<DexControlInstruction> control_instructions;
                std::unordered_set<std::uint32_t> handler_starts;
                for (const auto &region : exception_regions)
                    for (const auto &handler : region.handlers)
                        handler_starts.insert(handler.address);
                enum class PendingDexResult { none, void_value, scalar, wide, object, unknown };
                PendingDexResult previous_result = PendingDexResult::none;
                std::string_view previous_result_descriptor;
                std::unordered_map<std::uint32_t, std::string_view> move_result_descriptors;
                bool instruction_stream_complete = true;
                while (instruction_offset < insns * 2) {
                    if (stop.stop_requested())
                        return Error{ErrorCode::canceled, "DEX register validation canceled"};
                    const auto remaining = std::span<const std::byte>(bytes).subspan(
                        static_cast<std::size_t>(insns_off + instruction_offset),
                        static_cast<std::size_t>(insns * 2 - instruction_offset));
                    auto decoded = decode_dex(remaining, {{0}, instruction_offset});
                    if (decoded.status != DecodeStatus::decoded || !decoded.instruction) {
                        instruction_stream_complete = false;
                        break;
                    }
                    const auto &instruction = *decoded.instruction;
                    instruction_starts.insert(instruction_offset);
                    DexControlInstruction control{instruction_offset, instruction.length, instruction.flow, {}};
                    if (instruction.direct_target)
                        control.target = static_cast<std::uint32_t>(instruction.direct_target->offset);
                    control_instructions.push_back(control);
                    if (instruction.flow == FlowKind::data)
                        payload_starts.insert(instruction_offset);
                    if (instruction.direct_target) {
                        if (instruction.direct_target->space != AddressSpaceId{0} ||
                            instruction.direct_target->offset > UINT32_MAX)
                            return Error{ErrorCode::malformed, "DEX branch target exceeds the method address space"};
                        branch_targets.push_back(static_cast<std::uint32_t>(instruction.direct_target->offset));
                    } else if (instruction.flow == FlowKind::jump ||
                               instruction.flow == FlowKind::conditional_branch) {
                        return Error{ErrorCode::malformed, "DEX branch target overflows its method address space"};
                    }
                    if (instruction.dex_switch)
                        data_payload_targets.push_back(static_cast<std::uint32_t>(instruction.dex_switch->payload.offset));
                    const auto instruction_source = remaining.first(instruction.length);
                    const auto operand_word = [&](std::size_t index) {
                        const auto offset = index * 2;
                        return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(instruction_source[offset]) |
                            (std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[offset + 1])) << 8));
                    };
                    const auto index16 = operand_word(1);
                    bool reference_valid = true;
                    const auto within = [&](std::uint64_t index, std::size_t count) { return index < count; };
                    const auto opcode = std::to_integer<std::uint8_t>(instruction_source[0]);
                    if (opcode == 0x2b || opcode == 0x2c)
                        switch_sources.emplace_back(instruction_offset,
                            static_cast<std::uint32_t>(instruction.dex_switch->payload.offset), opcode == 0x2b);
                    if (opcode >= 0x0a && opcode <= 0x0c)
                        move_result_offsets.push_back(instruction_offset);
                    const auto &method_return_type = types[protos[methods[method_idx].proto].return_type];
                    bool return_matches = true;
                    if (opcode == 0x0e || opcode == 0xf1)
                        return_matches = method_return_type == "V";
                    else if (opcode == 0x0f)
                        return_matches = method_return_type != "V" && method_return_type != "J" &&
                            method_return_type != "D" && !method_return_type.empty() &&
                            method_return_type.front() != 'L' && method_return_type.front() != '[';
                    else if (opcode == 0x10)
                        return_matches = method_return_type == "J" || method_return_type == "D";
                    else if (opcode == 0x11)
                        return_matches = !method_return_type.empty() &&
                            (method_return_type.front() == 'L' || method_return_type.front() == '[');
                    if ((opcode >= 0x0e && opcode <= 0x11 || opcode == 0xf1) && !return_matches)
                        return Error{ErrorCode::malformed,
                            "DEX return instruction disagrees with its method prototype"};
                    if (opcode == 0x0d && !handler_starts.contains(instruction_offset))
                        return Error{ErrorCode::malformed,
                            "DEX move-exception is not the first instruction of a catch handler"};
                    if (opcode >= 0x0a && opcode <= 0x0c) {
                        if (!previous_result_descriptor.empty())
                            move_result_descriptors.emplace(instruction_offset, previous_result_descriptor);
                        if (previous_result == PendingDexResult::none ||
                            previous_result == PendingDexResult::void_value)
                            return Error{ErrorCode::malformed,
                                "DEX move-result is not adjacent to a value-producing instruction"};
                        const auto expected = opcode == 0x0a ? PendingDexResult::scalar
                            : opcode == 0x0b ? PendingDexResult::wide : PendingDexResult::object;
                        if (previous_result != PendingDexResult::unknown && previous_result != expected)
                            return Error{ErrorCode::malformed,
                                "DEX move-result variant disagrees with the preceding result type"};
                    }
                    if (opcode == 0x26) {
                        const auto units = std::bit_cast<std::int32_t>(
                            std::uint32_t(operand_word(1)) | (std::uint32_t(operand_word(2)) << 16));
                        const auto target = std::int64_t(instruction_offset) + std::int64_t(units) * 2;
                        if (target < 0 || target > UINT32_MAX)
                            return Error{ErrorCode::malformed,
                                "DEX fill-array-data payload target exceeds its method address space"};
                        data_payload_targets.push_back(static_cast<std::uint32_t>(target));
                    }
                    if (opcode == 0x1a)
                        reference_valid = within(index16, strings.size());
                    else if (opcode == 0x1b)
                        reference_valid = within(std::uint32_t(index16) |
                            (std::uint32_t(operand_word(2)) << 16), strings.size());
                    else if (opcode == 0x1c || opcode == 0x1f || opcode == 0x20 || opcode == 0x22 ||
                             opcode == 0x23 || opcode == 0x24 || opcode == 0x25)
                        reference_valid = within(index16, types.size());
                    else if ((opcode >= 0x52 && opcode <= 0x6d) || (opcode >= 0xe3 && opcode <= 0xeb))
                        reference_valid = within(index16, fields.size());
                    else if ((opcode >= 0x6e && opcode <= 0x72) || (opcode >= 0x74 && opcode <= 0x78) ||
                             opcode == 0xf0)
                        reference_valid = within(index16, methods.size());
                    else if (opcode == 0xfa || opcode == 0xfb)
                        reference_valid = within(index16, methods.size()) && within(operand_word(3), protos.size());
                    else if (opcode == 0xfc || opcode == 0xfd)
                        reference_valid = within(index16, map.value().call_site_count);
                    else if (opcode == 0xfe)
                        reference_valid = within(index16, map.value().method_handle_count);
                    else if (opcode == 0xff)
                        reference_valid = within(index16, protos.size());
                    if (!reference_valid)
                        return Error{ErrorCode::malformed,
                            "DEX instruction references an index outside its identifier table"};
                    std::optional<std::uint32_t> encoded_argument_words;
                    std::optional<std::uint32_t> invoke_proto;
                    bool implicit_receiver = false;
                    if ((opcode >= 0x6e && opcode <= 0x72) || (opcode >= 0x74 && opcode <= 0x78)) {
                        const bool range = opcode >= 0x74;
                        encoded_argument_words = range ? std::to_integer<std::uint8_t>(instruction_source[1])
                                                       : ((std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[0])) |
                                                          (std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[1])) << 8)) >> 12) & 15;
                        invoke_proto = methods[index16].proto;
                        implicit_receiver = opcode != 0x71 && opcode != 0x77;
                    } else if (opcode == 0xfa || opcode == 0xfb) {
                        const auto first_word = std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[0])) |
                            (std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[1])) << 8);
                        encoded_argument_words = opcode == 0xfb ? std::to_integer<std::uint8_t>(instruction_source[1])
                            : (first_word >> 12) & 15;
                        invoke_proto = operand_word(3);
                        implicit_receiver = true;
                    } else if (opcode == 0xfc || opcode == 0xfd) {
                        const auto first_word = std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[0])) |
                            (std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[1])) << 8);
                        encoded_argument_words = opcode == 0xfd ? std::to_integer<std::uint8_t>(instruction_source[1])
                            : (first_word >> 12) & 15;
                        const auto &call_site = decoded_call_sites[index16];
                        if (call_site.values.size() >= 3 && call_site.values[2].type == 0x15 &&
                            call_site.values[2].payload <= UINT32_MAX)
                            invoke_proto = static_cast<std::uint32_t>(call_site.values[2].payload);
                    } else if (opcode == 0xf0) {
                        encoded_argument_words = 1;
                        invoke_proto = methods[index16].proto;
                        implicit_receiver = true;
                    } else if (opcode == 0xee || opcode == 0xef || opcode == 0xf8 || opcode == 0xf9) {
                        const bool range = opcode == 0xef || opcode == 0xf9;
                        const auto first_word = std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[0])) |
                            (std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[1])) << 8);
                        encoded_argument_words = range ? std::to_integer<std::uint8_t>(instruction_source[1])
                                                       : (first_word >> 12) & 15;
                    }
                    if (encoded_argument_words) {
                        if (*encoded_argument_words > outs)
                            return Error{ErrorCode::malformed,
                                "DEX invoke argument words exceed code_item outs_size"};
                        if (invoke_proto) {
                            if (*invoke_proto >= protos.size())
                                return Error{ErrorCode::malformed,
                                    "DEX invoke prototype index is outside the prototype table"};
                            std::uint32_t expected_words = implicit_receiver ? 1u : 0u;
                            for (const auto parameter_type : protos[*invoke_proto].parameters) {
                                const auto &descriptor = types[parameter_type];
                                const auto width = descriptor == "J" || descriptor == "D" ? 2u : 1u;
                                if (expected_words > UINT32_MAX - width)
                                    return Error{ErrorCode::resource_limit,
                                        "DEX invoke prototype argument count overflows"};
                                expected_words += width;
                            }
                            if (*encoded_argument_words != expected_words)
                                return Error{ErrorCode::malformed,
                                    "DEX invoke argument words disagree with its prototype"};
                            const bool range_form = opcode == 0xfb || opcode == 0xfd ||
                                (opcode >= 0x74 && opcode <= 0x78);
                            const auto encoded_register = [&](std::uint32_t argument) -> std::uint32_t {
                                if (range_form) return std::uint32_t(operand_word(2)) + argument;
                                const auto packed = operand_word(2);
                                const auto first_word = std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[0])) |
                                    (std::uint16_t(std::to_integer<std::uint8_t>(instruction_source[1])) << 8);
                                const std::array<std::uint32_t, 5> listed{
                                    std::uint32_t(packed & 15), std::uint32_t((packed >> 4) & 15),
                                    std::uint32_t((packed >> 8) & 15), std::uint32_t((packed >> 12) & 15),
                                    std::uint32_t((first_word >> 8) & 15)};
                                return argument < listed.size() ? listed[argument] : UINT32_MAX;
                            };
                            std::uint32_t argument_word = implicit_receiver ? 1u : 0u;
                            for (const auto parameter_type : protos[*invoke_proto].parameters) {
                                const auto &descriptor = types[parameter_type];
                                if (descriptor == "J" || descriptor == "D") {
                                    if (argument_word + 1 >= *encoded_argument_words ||
                                        encoded_register(argument_word + 1) != encoded_register(argument_word) + 1)
                                        return Error{ErrorCode::malformed,
                                            "DEX wide invoke parameter does not use an adjacent register pair"};
                                    argument_word += 2;
                                } else {
                                    ++argument_word;
                                }
                            }
                        }
                    }
                    const auto check_registers = [&](const auto &registers_used) {
                        return std::all_of(registers_used.begin(), registers_used.end(),
                            [&](const RegisterOperand &reg) { return reg.index < registers; });
                    };
                    if (!check_registers(instruction.register_reads) ||
                        !check_registers(instruction.register_writes))
                        return Error{ErrorCode::malformed,
                            "DEX instruction references a register outside its code_item register file"};
                    const auto check_wide_pair = [&](std::uint32_t first) {
                        return first < registers && first + 1 < registers;
                    };
                    const auto first_word = operand_word(0);
                    const auto check_wide_at = [&](std::uint32_t reg) {
                        return check_wide_pair(reg);
                    };
                    const auto bad_wide_pair = [] {
                        return Error{ErrorCode::malformed,
                            "DEX wide register pair exceeds its code_item register file"};
                    };
                    if (opcode >= 0x04 && opcode <= 0x06) {
                        const auto destination = opcode == 0x06 ? operand_word(1) : (first_word >> 8) & 0xf;
                        const auto source = opcode == 0x04 ? (first_word >> 12) & 0xf :
                            opcode == 0x05 ? operand_word(1) : operand_word(2);
                        if (!check_wide_at(destination) || !check_wide_at(source))
                            return bad_wide_pair();
                    } else if (opcode == 0x0b || opcode == 0x10 ||
                               (opcode >= 0x16 && opcode <= 0x19) || opcode == 0x61 || opcode == 0x68) {
                        const auto reg = (first_word >> 8) & 0xff;
                        if (!check_wide_at(reg))
                            return bad_wide_pair();
                    } else if (opcode >= 0x2f && opcode <= 0x31) {
                        const auto registers_bc = operand_word(1);
                        if (!check_wide_at(registers_bc & 0xff) || !check_wide_at(registers_bc >> 8))
                            return bad_wide_pair();
                    } else if (opcode == 0x45 || opcode == 0x4c) {
                        if (!check_wide_at((first_word >> 8) & 0xff))
                            return bad_wide_pair();
                    } else if (opcode == 0x53 || opcode == 0x5a) {
                        if (!check_wide_at((first_word >> 8) & 0xf))
                            return bad_wide_pair();
                    } else if (opcode == 0x7d || opcode == 0x7e || opcode == 0x80) {
                        if (!check_wide_at((first_word >> 8) & 0xf) || !check_wide_at((first_word >> 12) & 0xf))
                            return bad_wide_pair();
                    } else if (opcode >= 0x81 && opcode <= 0x8c) {
                        const auto destination = (first_word >> 8) & 0xf;
                        const auto source = (first_word >> 12) & 0xf;
                        const bool destination_wide = opcode == 0x81 || opcode == 0x83 || opcode == 0x86 ||
                            opcode == 0x88 || opcode == 0x89 || opcode == 0x8b;
                        const bool source_wide = opcode == 0x84 || opcode == 0x85 || opcode == 0x86 ||
                            opcode == 0x8a || opcode == 0x8b || opcode == 0x8c;
                        if ((destination_wide && !check_wide_at(destination)) ||
                            (source_wide && !check_wide_at(source)))
                            return bad_wide_pair();
                    } else if ((opcode >= 0x9b && opcode <= 0xa5) ||
                               (opcode >= 0xab && opcode <= 0xaf)) {
                        const auto registers_bc = operand_word(1);
                        const auto destination = (first_word >> 8) & 0xff;
                        const auto left = registers_bc & 0xff;
                        const auto right = registers_bc >> 8;
                        const bool is_long = opcode <= 0xa5;
                        if (!check_wide_at(destination) || !check_wide_at(left) ||
                            ((is_long && opcode < 0xa3) || !is_long) && !check_wide_at(right))
                            return bad_wide_pair();
                    } else if ((opcode >= 0xbb && opcode <= 0xc5) ||
                               (opcode >= 0xcb && opcode <= 0xcf)) {
                        const auto destination = (first_word >> 8) & 0xf;
                        const auto source = (first_word >> 12) & 0xf;
                        const bool is_long = opcode <= 0xc5;
                        if (!check_wide_at(destination) ||
                            ((is_long && opcode < 0xc3) || !is_long) && !check_wide_at(source))
                            return bad_wide_pair();
                    }
                    if (!instruction.length || instruction.length > insns * 2 - instruction_offset)
                        return Error{ErrorCode::malformed, "DEX decoder returned an invalid instruction extent"};
                    previous_result = PendingDexResult::none;
                    previous_result_descriptor = {};
                    if (opcode == 0x24 || opcode == 0x25) {
                        previous_result = PendingDexResult::object;
                    } else if (invoke_proto || opcode == 0xee || opcode == 0xef ||
                               opcode == 0xf8 || opcode == 0xf9) {
                        if (!invoke_proto) {
                            previous_result = PendingDexResult::unknown;
                        } else {
                            const auto &result_type = types[protos[*invoke_proto].return_type];
                            previous_result_descriptor = result_type;
                            previous_result = result_type == "V" ? PendingDexResult::void_value
                                : result_type == "J" || result_type == "D" ? PendingDexResult::wide
                                : (!result_type.empty() &&
                                   (result_type.front() == 'L' || result_type.front() == '['))
                                    ? PendingDexResult::object : PendingDexResult::scalar;
                        }
                    }
                    instruction_offset += instruction.length;
                }
                instruction_stream_complete = instruction_stream_complete && instruction_offset == insns * 2;
                if (instruction_stream_complete) {
                    const auto method_bytes = std::span<const std::byte>(bytes).subspan(
                        static_cast<std::size_t>(insns_off), static_cast<std::size_t>(insns * 2));
                    const auto method_word = [&](std::uint32_t byte_offset) {
                        return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(method_bytes[byte_offset]) |
                            (std::uint16_t(std::to_integer<std::uint8_t>(method_bytes[byte_offset + 1])) << 8));
                    };
                    std::vector<std::uint32_t> switch_case_targets;
                    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> switch_cases_by_source;
                    for (const auto &[source_offset, payload_offset, packed_switch] : switch_sources) {
                        const auto expected_ident = packed_switch ? 0x0100 : 0x0200;
                        if (method_word(payload_offset) != expected_ident)
                            return Error{ErrorCode::malformed,
                                "DEX switch instruction references the wrong payload kind"};
                        const auto count = method_word(payload_offset + 2);
                        const auto target_words = payload_offset + (packed_switch
                            ? 8u : 4u + std::uint32_t(count) * 4u);
                        if (std::uint64_t(target_words) + std::uint64_t(count) * 4 > method_bytes.size())
                            return Error{ErrorCode::malformed, "DEX switch payload targets exceed the method extent"};
                        for (std::uint32_t i = 0; i < count; ++i) {
                            const auto at = target_words + i * 4;
                            const auto units = std::bit_cast<std::int32_t>(
                                std::uint32_t(method_word(at)) | (std::uint32_t(method_word(at + 2)) << 16));
                            const auto target = std::int64_t(source_offset) + std::int64_t(units) * 2;
                            if (target < 0 || target >= insns * 2)
                                return Error{ErrorCode::malformed,
                                    "DEX switch case target exceeds its method address space"};
                            switch_case_targets.push_back(static_cast<std::uint32_t>(target));
                            switch_cases_by_source[source_offset].push_back(static_cast<std::uint32_t>(target));
                        }
                    }
                    std::unordered_set<std::uint32_t> control_entries;
                    control_entries.reserve(branch_targets.size() + switch_case_targets.size());
                    for (const auto target : branch_targets) {
                        if (!instruction_starts.contains(target) || payload_starts.contains(target))
                            return Error{ErrorCode::malformed,
                                "DEX branch target is not an executable instruction boundary"};
                        control_entries.insert(target);
                    }
                    for (const auto target : switch_case_targets) {
                        if (!instruction_starts.contains(target) || payload_starts.contains(target))
                            return Error{ErrorCode::malformed,
                                "DEX switch case target is not an executable instruction boundary"};
                        control_entries.insert(target);
                    }
                    for (const auto target : move_result_offsets)
                        if (control_entries.contains(target) || handler_starts.contains(target))
                            return Error{ErrorCode::malformed,
                                "DEX control flow enters a move-result instruction without its invoke result"};
                    for (const auto payload : data_payload_targets)
                        if (!instruction_starts.contains(payload) || !payload_starts.contains(payload))
                            return Error{ErrorCode::malformed,
                                "DEX switch target does not identify an instruction-aligned payload"};
                    std::unordered_map<std::uint32_t, const DexControlInstruction *> control_by_offset;
                    control_by_offset.reserve(control_instructions.size());
                    for (const auto &instruction : control_instructions)
                        control_by_offset.emplace(instruction.offset, &instruction);
                    std::deque<std::uint32_t> reachable;
                    std::unordered_set<std::uint32_t> visited;
                    reachable.push_back(0);
                    for (const auto handler : handler_starts) reachable.push_back(handler);
                    while (!reachable.empty()) {
                        const auto offset = reachable.front();
                        reachable.pop_front();
                        if (!visited.insert(offset).second) continue;
                        const auto found = control_by_offset.find(offset);
                        if (found == control_by_offset.end())
                            return Error{ErrorCode::malformed,
                                "DEX control flow does not land on a decoded instruction"};
                        const auto &instruction = *found->second;
                        if (instruction.flow == FlowKind::data)
                            return Error{ErrorCode::malformed,
                                "DEX data payload is reachable by control flow"};
                        const auto next = instruction.offset + instruction.length;
                        const auto add_fallthrough = [&]() {
                            if (next >= insns * 2) return false;
                            reachable.push_back(next);
                            return true;
                        };
                        if (instruction.flow == FlowKind::fallthrough || instruction.flow == FlowKind::call) {
                            if (!add_fallthrough())
                                return Error{ErrorCode::malformed,
                                    "DEX reachable control flow falls off the end of the method"};
                        } else if (instruction.flow == FlowKind::conditional_branch) {
                            if (!instruction.target || !add_fallthrough())
                                return Error{ErrorCode::malformed,
                                    "DEX conditional branch has an invalid target or falls off the method"};
                            reachable.push_back(*instruction.target);
                        } else if (instruction.flow == FlowKind::jump) {
                            if (!instruction.target)
                                return Error{ErrorCode::malformed, "DEX jump has no direct target"};
                            reachable.push_back(*instruction.target);
                        } else if (instruction.flow == FlowKind::switch_dispatch) {
                            if (!add_fallthrough())
                                return Error{ErrorCode::malformed,
                                    "DEX switch default path falls off the end of the method"};
                            if (const auto cases = switch_cases_by_source.find(instruction.offset);
                                cases != switch_cases_by_source.end())
                                for (const auto target : cases->second) reachable.push_back(target);
                        }
                    }
                    for (const auto &region : exception_regions) {
                        if (!instruction_starts.contains(region.begin) || payload_starts.contains(region.begin) ||
                            (region.end != insns * 2 && !instruction_starts.contains(region.end)))
                            return Error{ErrorCode::malformed,
                                "DEX try range does not begin and end on instruction boundaries"};
                        for (const auto &handler : region.handlers)
                            if (!instruction_starts.contains(handler.address) || payload_starts.contains(handler.address))
                                return Error{ErrorCode::malformed,
                                    "DEX exception handler does not target an executable instruction boundary"};
                    }

                    // Bounded category propagation through normal control
                    // flow, including polymorphic constants and typed invoke
                    // results. Unsupported instruction families kill written
                    // facts and remain outside this partial verifier.
                    const auto cells = std::uint64_t(control_instructions.size()) * registers;
                    if (cells > 1'000'000 || total_type_flow_cells > 8'000'000 - cells)
                        return Error{ErrorCode::resource_limit,
                            "Aggregate DEX verifier register-state budget exceeded"};
                    total_type_flow_cells += cells;
                    enum class RegType : std::uint8_t {
                        unknown, conflict, zero, int32, float32, scalar32, reference, wide_low, wide_high,
                        wide_int_low, wide_int_high, wide_float_low, wide_float_high
                    };
                    using TypeState = std::vector<RegType>;
                    std::unordered_map<std::uint32_t, TypeState> incoming_states;
                    std::deque<std::uint32_t> type_work;
                    TypeState initial(registers, RegType::unknown);
                    const auto merge_type = [](RegType a, RegType b) {
                        if (a == b) return a;
                        if (a == RegType::conflict || b == RegType::conflict) return RegType::conflict;
                        if (a == RegType::unknown || b == RegType::unknown) return RegType::unknown;
                        // Constants carry a set of permitted interpretations.
                        // Joining with a typed value constrains that set; it
                        // must not manufacture a conflict for zero/null or a
                        // raw scalar/wide constant on the other predecessor.
                        const auto accepts_constant = [](RegType constant, RegType typed) {
                            if (constant == RegType::zero)
                                return typed == RegType::scalar32 || typed == RegType::int32 ||
                                    typed == RegType::float32 || typed == RegType::reference;
                            if (constant == RegType::scalar32)
                                return typed == RegType::int32 || typed == RegType::float32;
                            if (constant == RegType::wide_low)
                                return typed == RegType::wide_int_low || typed == RegType::wide_float_low;
                            if (constant == RegType::wide_high)
                                return typed == RegType::wide_int_high || typed == RegType::wide_float_high;
                            return false;
                        };
                        if (accepts_constant(a, b)) return b;
                        if (accepts_constant(b, a)) return a;
                        return RegType::conflict;
                    };
                    const auto descriptor_type = [](std::string_view descriptor) {
                        if (descriptor.empty()) return RegType::unknown;
                        if (descriptor == "J") return RegType::wide_int_low;
                        if (descriptor == "D") return RegType::wide_float_low;
                        if (descriptor == "F") return RegType::float32;
                        if (descriptor.front() == 'L' || descriptor.front() == '[') return RegType::reference;
                        if (descriptor == "V") return RegType::unknown;
                        return RegType::int32;
                    };
                    const auto &prototype = protos[methods[method_idx].proto];
                    std::uint32_t prototype_words = 0;
                    for (const auto parameter_type : prototype.parameters)
                        prototype_words += types[parameter_type] == "J" || types[parameter_type] == "D" ? 2u : 1u;
                    std::uint32_t parameter_register = registers - ins;
                    if (ins == prototype_words + 1 && parameter_register < registers)
                        initial[parameter_register++] = RegType::reference;
                    for (const auto parameter_type : prototype.parameters) {
                        const auto type = descriptor_type(types[parameter_type]);
                        if (type == RegType::wide_int_low || type == RegType::wide_float_low) {
                            if (parameter_register + 1 >= registers)
                                return Error{ErrorCode::malformed, "DEX verifier method parameters exceed the register file"};
                            initial[parameter_register] = type;
                            initial[parameter_register + 1] = type == RegType::wide_int_low
                                ? RegType::wide_int_high : RegType::wide_float_high;
                            parameter_register += 2;
                        } else {
                            if (parameter_register >= registers)
                                return Error{ErrorCode::malformed, "DEX verifier method parameters exceed the register file"};
                            initial[parameter_register++] = type;
                        }
                    }
                    incoming_states.emplace(0, initial);
                    type_work.push_back(0);
                    for (const auto handler : handler_starts) {
                        if (!incoming_states.contains(handler)) {
                            // Per-instruction exceptional edges are not yet
                            // modeled, so a handler cannot inherit entry
                            // parameter facts from an invented predecessor.
                            incoming_states.emplace(handler, TypeState(registers, RegType::unknown));
                            type_work.push_back(handler);
                        }
                    }
                    const auto max_type_steps = control_instructions.size() * 8 + 1024;
                    std::size_t type_steps = 0;
                    while (!type_work.empty()) {
                        if (stop.stop_requested())
                            return Error{ErrorCode::canceled, "DEX verifier register type-flow canceled"};
                        if (++type_steps > max_type_steps)
                            return Error{ErrorCode::resource_limit, "DEX verifier type-flow iteration budget exceeded"};
                        const auto offset = type_work.front();
                        type_work.pop_front();
                        auto instruction_it = control_by_offset.find(offset);
                        if (instruction_it == control_by_offset.end())
                            return Error{ErrorCode::malformed, "DEX verifier state targets a missing instruction"};
                        const auto &control = *instruction_it->second;
                        auto state = incoming_states.at(offset);
                        const auto before = state;
                        const auto instruction_bytes = method_bytes.subspan(offset, control.length);
                        const auto word = [&](std::size_t index) {
                            return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(instruction_bytes[index * 2]) |
                                (std::uint16_t(std::to_integer<std::uint8_t>(instruction_bytes[index * 2 + 1])) << 8));
                        };
                        const auto opcode = std::to_integer<std::uint8_t>(instruction_bytes[0]);
                        const auto first = word(0);
                        const auto reg8 = (first >> 8) & 0xff;
                        const auto reg4a = (first >> 8) & 0xf;
                        const auto reg4b = (first >> 12) & 0xf;
                        const auto set_type = [&](std::uint32_t reg, RegType type) {
                            if (reg < state.size()) state[reg] = type;
                        };
                        const auto expect_type = [&](std::uint32_t reg, RegType expected) {
                            if (reg >= before.size()) return false;
                            const auto actual = before[reg];
                            return actual == RegType::unknown || actual == expected ||
                                (actual == RegType::zero && (expected == RegType::int32 ||
                                    expected == RegType::float32 || expected == RegType::reference)) ||
                                (actual == RegType::scalar32 &&
                                 (expected == RegType::int32 || expected == RegType::float32));
                        };
                        const auto expect_wide = [&](std::uint32_t reg, bool floating) {
                            if (reg + 1 >= before.size()) return false;
                            const auto low = floating ? RegType::wide_float_low : RegType::wide_int_low;
                            const auto high = floating ? RegType::wide_float_high : RegType::wide_int_high;
                            return (before[reg] == RegType::unknown || before[reg] == low || before[reg] == RegType::wide_low) &&
                                   (before[reg + 1] == RegType::unknown || before[reg + 1] == high || before[reg + 1] == RegType::wide_high);
                        };
                        const auto expect_any_wide = [&](std::uint32_t reg) {
                            // Both halves must admit the same interpretation.
                            return expect_wide(reg, false) || expect_wide(reg, true);
                        };
                        const auto expect_descriptor = [&](std::uint32_t reg, std::string_view descriptor) {
                            const auto expected = descriptor_type(descriptor);
                            if (expected == RegType::wide_int_low || expected == RegType::wide_float_low)
                                return expect_wide(reg, expected == RegType::wide_float_low);
                            return expected == RegType::unknown || expect_type(reg, expected);
                        };
                        const auto set_descriptor = [&](std::uint32_t reg, std::string_view descriptor) {
                            const auto type = descriptor_type(descriptor);
                            if (type == RegType::wide_int_low || type == RegType::wide_float_low) {
                                set_type(reg, type);
                                set_type(reg + 1, type == RegType::wide_int_low
                                    ? RegType::wide_int_high : RegType::wide_float_high);
                            } else set_type(reg, type);
                        };
                        // Unsupported writes invalidate only their register
                        // facts, preventing stale values from crossing them.
                        auto decoded_for_flow = decode_dex(instruction_bytes, {{0}, offset});
                        if (!decoded_for_flow.instruction)
                            return Error{ErrorCode::malformed, "DEX verifier could not decode an instruction boundary"};
                        const auto &writes = decoded_for_flow.instruction->register_writes;
                        const auto writes_slot = [&](std::uint32_t reg) {
                            return std::any_of(writes.begin(), writes.end(), [&](const auto &written) {
                                return written.index == reg;
                            });
                        };
                        // A single-slot write destroys the adjacent half of
                        // an existing wide value. Keep an unusable fact there
                        // until that slot is explicitly redefined. Read all
                        // sources from `before` so overlapping move-wide is
                        // still valid and both destination slots are atomic.
                        for (const auto written : writes) {
                            const auto reg = written.index;
                            const auto old = before[reg];
                            const bool low = old == RegType::wide_low || old == RegType::wide_int_low ||
                                old == RegType::wide_float_low;
                            const bool high = old == RegType::wide_high || old == RegType::wide_int_high ||
                                old == RegType::wide_float_high;
                            if (low && reg + 1 < state.size() && !writes_slot(reg + 1))
                                set_type(reg + 1, RegType::conflict);
                            if (high && reg && !writes_slot(reg - 1))
                                set_type(reg - 1, RegType::conflict);
                            set_type(reg, RegType::unknown);
                        }
                        if (opcode >= 0x12 && opcode <= 0x15) {
                            const bool zero = opcode == 0x12 ? ((first >> 12) & 0xf) == 0
                                : opcode == 0x13 || opcode == 0x15 ? word(1) == 0
                                : (std::uint32_t(word(1)) | (std::uint32_t(word(2)) << 16)) == 0;
                            set_type(opcode == 0x12 ? reg4a : reg8,
                                     zero ? RegType::zero : RegType::scalar32);
                        } else if (opcode >= 0x16 && opcode <= 0x19) {
                            set_type(reg8, RegType::wide_low);
                            set_type(reg8 + 1, RegType::wide_high);
                        } else if (opcode == 0x1a || opcode == 0x1b || opcode == 0x1c || opcode == 0x22) {
                            set_type(reg8, RegType::reference);
                        } else if (opcode >= 0x01 && opcode <= 0x03) {
                            const auto destination = opcode == 0x01 ? reg4a : opcode == 0x02 ? reg8 : word(1);
                            const auto source = opcode == 0x01 ? reg4b : opcode == 0x02 ? word(1) : word(2);
                            const auto type = before[source];
                            if (type == RegType::reference || type == RegType::wide_int_low ||
                                type == RegType::wide_int_high || type == RegType::wide_float_low ||
                                type == RegType::wide_float_high || type == RegType::wide_low ||
                                type == RegType::wide_high || type == RegType::conflict)
                                return Error{ErrorCode::malformed, "DEX move transfers a non-scalar value"};
                            set_type(destination, type);
                        } else if (opcode >= 0x04 && opcode <= 0x06) {
                            const auto destination = opcode == 0x04 ? reg4a : opcode == 0x05 ? reg8 : word(1);
                            const auto source = opcode == 0x04 ? reg4b : opcode == 0x05 ? word(1) : word(2);
                            if (!expect_any_wide(source))
                                return Error{ErrorCode::malformed, "DEX move-wide source is not a compatible wide pair"};
                            if (before[source] == RegType::unknown && before[source + 1] == RegType::unknown) {
                                set_type(destination, RegType::wide_low);
                                set_type(destination + 1, RegType::wide_high);
                            } else {
                                set_type(destination, before[source]);
                                set_type(destination + 1, before[source + 1]);
                            }
                        } else if (opcode >= 0x07 && opcode <= 0x09) {
                            const auto destination = opcode == 0x07 ? reg4a : opcode == 0x08 ? reg8 : word(1);
                            const auto source = opcode == 0x07 ? reg4b : opcode == 0x08 ? word(1) : word(2);
                            if (!expect_type(source, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX move-object source is not a reference"};
                            set_type(destination, before[source]);
                        } else if (opcode >= 0x0a && opcode <= 0x0c && move_result_descriptors.contains(offset)) {
                            set_descriptor(reg8, move_result_descriptors.at(offset));
                        } else if (opcode == 0x0b) {
                            set_type(reg8, RegType::wide_low);
                            set_type(reg8 + 1, RegType::wide_high);
                        } else if (opcode == 0x0c || opcode == 0xfe || opcode == 0xff) {
                            set_type(reg8, RegType::reference);
                        } else if (opcode == 0x0d) {
                            set_type(reg8, RegType::reference);
                        } else if (opcode == 0x1d || opcode == 0x1e || opcode == 0x27) {
                            if (!expect_type(reg8, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX monitor or throw operand is not a reference"};
                        } else if (opcode == 0x1f) {
                            if (!expect_type(reg8, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX check-cast operand is not a reference"};
                            set_type(reg8, RegType::reference);
                        } else if (opcode == 0x20) {
                            if (!expect_type(reg4b, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX instance-of operand is not a reference"};
                            set_type(reg4a, RegType::int32);
                        } else if (opcode == 0x21) {
                            if (!expect_type(reg4b, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX array-length operand is not a reference"};
                            set_type(reg4a, RegType::int32);
                        } else if (opcode == 0x23) {
                            if (!expect_type(reg4b, RegType::int32))
                                return Error{ErrorCode::malformed, "DEX new-array size is not an integer"};
                            set_type(reg4a, RegType::reference);
                        } else if (opcode == 0x26) {
                            if (!expect_type(reg8, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX fill-array-data operand is not a reference"};
                        } else if (opcode >= 0x44 && opcode <= 0x51) {
                            const auto value = reg8;
                            const auto array = word(1) & 0xff;
                            const auto index = word(1) >> 8;
                            const auto get = opcode <= 0x4a;
                            const bool wide = opcode == 0x45 || opcode == 0x4c;
                            const bool object = opcode == 0x46 || opcode == 0x4d;
                            if (!expect_type(array, RegType::reference) || !expect_type(index, RegType::int32))
                                return Error{ErrorCode::malformed, "DEX array access has an incompatible array or index type"};
                            if (get) {
                                if (wide) set_type(value, RegType::wide_low), set_type(value + 1, RegType::wide_high);
                                else set_type(value, object ? RegType::reference : RegType::int32);
                            } else if (wide ? !expect_any_wide(value) :
                                       !expect_type(value, object ? RegType::reference : RegType::int32)) {
                                return Error{ErrorCode::malformed, "DEX array store value has an incompatible type"};
                            }
                        } else if (opcode >= 0x52 && opcode <= 0x6d) {
                            const auto instance = opcode < 0x60;
                            const auto get = opcode <= 0x58 || (opcode >= 0x60 && opcode <= 0x66);
                            const auto value = instance ? reg4a : reg8;
                            const auto receiver = reg4b;
                            const auto field_index = word(1);
                            if (instance && !expect_type(receiver, RegType::reference))
                                return Error{ErrorCode::malformed, "DEX instance field receiver is not a reference"};
                            if (field_index < fields.size()) {
                                const auto &field_type = types[fields[field_index].type];
                                if (get) set_descriptor(value, field_type);
                                else if (!expect_descriptor(value, field_type))
                                    return Error{ErrorCode::malformed, "DEX field store value disagrees with the field descriptor"};
                            }
                        } else if (opcode >= 0x7b && opcode <= 0x8f) {
                            const auto destination = reg4a;
                            const auto source = reg4b;
                            RegType source_type = RegType::int32;
                            RegType destination_type = RegType::int32;
                            bool source_wide = false, destination_wide = false;
                            switch (opcode) {
                            case 0x7d: case 0x7e: source_type = RegType::wide_int_low; source_wide = true; destination_type = RegType::wide_int_low; destination_wide = true; break;
                            case 0x7f: source_type = RegType::float32; destination_type = RegType::float32; break;
                            case 0x80: source_type = RegType::wide_float_low; source_wide = true; destination_type = RegType::wide_float_low; destination_wide = true; break;
                            case 0x81: destination_type = RegType::wide_int_low; destination_wide = true; break;
                            case 0x82: destination_type = RegType::float32; break;
                            case 0x83: destination_type = RegType::wide_float_low; destination_wide = true; break;
                            case 0x84: source_type = RegType::wide_int_low; source_wide = true; break;
                            case 0x85: source_type = RegType::wide_int_low; source_wide = true; destination_type = RegType::float32; break;
                            case 0x86: source_type = RegType::wide_int_low; source_wide = true; destination_type = RegType::wide_float_low; destination_wide = true; break;
                            case 0x87: source_type = RegType::float32; break;
                            case 0x88: source_type = RegType::float32; destination_type = RegType::wide_int_low; destination_wide = true; break;
                            case 0x89: source_type = RegType::float32; destination_type = RegType::wide_float_low; destination_wide = true; break;
                            case 0x8a: source_type = RegType::wide_float_low; source_wide = true; destination_type = RegType::int32; break;
                            case 0x8b: source_type = RegType::wide_float_low; source_wide = true; destination_type = RegType::wide_int_low; destination_wide = true; break;
                            case 0x8c: source_type = RegType::wide_float_low; source_wide = true; destination_type = RegType::float32; break;
                            case 0x8d: source_type = RegType::int32; break;
                            case 0x8e: source_type = RegType::int32; break;
                            case 0x8f: source_type = RegType::int32; break;
                            default: break;
                            }
                            if (opcode == 0x7b || opcode == 0x7c) source_type = RegType::int32;
                            if (opcode >= 0x8d) source_type = RegType::int32;
                            const bool source_is_wide = source_wide;
                            const bool dest_is_wide = destination_wide;
                            if (source_is_wide ? !expect_wide(source, source_type == RegType::wide_float_low)
                                               : !expect_type(source, source_type))
                                return Error{ErrorCode::malformed, "DEX conversion source has an incompatible type"};
                            if (dest_is_wide) set_descriptor(destination, destination_type == RegType::wide_float_low ? "D" : "J");
                            else set_type(destination, destination_type);
                        } else if (opcode >= 0x90 && opcode <= 0xcf) {
                            const bool two_address = opcode >= 0xb0;
                            const auto op = two_address ? opcode - 0x20 : opcode;
                            const bool is_long = op >= 0x9b && op <= 0xa5;
                            const bool is_float = op >= 0xa6 && op <= 0xaa;
                            const bool is_double = op >= 0xab && op <= 0xaf;
                            const bool wide = is_long || is_double;
                            const bool shift = (op >= 0xa3 && op <= 0xa5);
                            const auto destination = two_address ? reg4a : reg8;
                            const auto left = two_address ? reg4a : (word(1) & 0xff);
                            const auto right = two_address ? reg4b : (word(1) >> 8);
                            const auto category = is_float ? RegType::float32 : is_double ? RegType::wide_float_low :
                                is_long ? RegType::wide_int_low : RegType::int32;
                            if (wide ? (!expect_wide(left, category == RegType::wide_float_low) ||
                                        (shift ? !expect_type(right, RegType::int32)
                                               : !expect_wide(right, category == RegType::wide_float_low)))
                                     : (!expect_type(left, category) || !expect_type(right,
                                         (is_float || is_double) ? category : RegType::int32)))
                                return Error{ErrorCode::malformed, "DEX arithmetic operand has an incompatible type"};
                            if (wide) set_descriptor(destination, category == RegType::wide_float_low ? "D" : "J");
                            else set_type(destination, category);
                        } else if (opcode >= 0xd0 && opcode <= 0xe2) {
                            const auto destination = opcode <= 0xd7 ? reg4a : reg8;
                            const auto source = opcode <= 0xd7 ? reg4b : (word(1) & 0xff);
                            if (!expect_type(source, RegType::int32))
                                return Error{ErrorCode::malformed, "DEX literal arithmetic source is not an integer"};
                            set_type(destination, RegType::int32);
                        } else if ((opcode >= 0x6e && opcode <= 0x72) ||
                                   (opcode >= 0x74 && opcode <= 0x78) ||
                                   opcode == 0xfa || opcode == 0xfb || opcode == 0xfc || opcode == 0xfd) {
                            std::optional<std::uint32_t> proto_index;
                            bool receiver = false;
                            if (opcode >= 0x6e && opcode <= 0x72) {
                                const auto method_index = word(1);
                                if (method_index < methods.size()) proto_index = methods[method_index].proto;
                                receiver = opcode != 0x71;
                            } else if (opcode >= 0x74 && opcode <= 0x78) {
                                const auto method_index = word(1);
                                if (method_index < methods.size()) proto_index = methods[method_index].proto;
                                receiver = opcode != 0x77;
                            } else if (opcode == 0xfa || opcode == 0xfb) {
                                proto_index = word(3);
                                receiver = true;
                            } else {
                                const auto call_site_index = word(1);
                                if (call_site_index < decoded_call_sites.size()) {
                                    const auto &site = decoded_call_sites[call_site_index];
                                    if (site.values.size() >= 3 && site.values[2].type == 0x15 &&
                                        site.values[2].payload < protos.size())
                                        proto_index = static_cast<std::uint32_t>(site.values[2].payload);
                                }
                            }
                            if (proto_index && *proto_index < protos.size()) {
                                const bool range = opcode == 0xfb || opcode == 0xfd ||
                                    (opcode >= 0x74 && opcode <= 0x78);
                                const auto first_word = word(0);
                                const auto packed = word(2);
                                const std::array<std::uint32_t, 5> listed{
                                    std::uint32_t(packed & 15), std::uint32_t((packed >> 4) & 15),
                                    std::uint32_t((packed >> 8) & 15), std::uint32_t((packed >> 12) & 15),
                                    std::uint32_t((first_word >> 8) & 15)};
                                const auto argument_reg = [&](std::uint32_t word_index) {
                                    return range ? std::uint32_t(packed) + word_index :
                                        word_index < listed.size() ? listed[word_index] : UINT32_MAX;
                                };
                                std::uint32_t word_index = 0;
                                if (receiver) {
                                    if (!expect_type(argument_reg(word_index++), RegType::reference))
                                        return Error{ErrorCode::malformed, "DEX invoke receiver is not a reference"};
                                }
                                for (const auto parameter_type : protos[*proto_index].parameters) {
                                    const auto &descriptor = types[parameter_type];
                                    const auto reg = argument_reg(word_index);
                                    if (!expect_descriptor(reg, descriptor))
                                        return Error{ErrorCode::malformed, "DEX invoke argument disagrees with its prototype"};
                                    word_index += descriptor == "J" || descriptor == "D" ? 2u : 1u;
                                }
                            }
                        } else if (opcode >= 0x2d && opcode <= 0x31) {
                            const auto packed = word(1);
                            const auto left = packed & 0xff;
                            const auto right = packed >> 8;
                            const bool wide = opcode >= 0x2f;
                            const bool floating = opcode != 0x31;
                            if (wide ? (!expect_wide(left, floating) || !expect_wide(right, floating))
                                     : (!expect_type(left, RegType::float32) ||
                                        !expect_type(right, RegType::float32)))
                                return Error{ErrorCode::malformed,
                                    "DEX compare operands have incompatible register types"};
                            set_type(reg8, RegType::int32);
                        } else if (opcode >= 0x32 && opcode <= 0x37) {
                            const auto left = reg4a;
                            const auto right = reg4b;
                            if (opcode <= 0x33) {
                                const auto comparable = [](RegType type) {
                                    return type == RegType::unknown || type == RegType::zero || type == RegType::int32 ||
                                        type == RegType::scalar32 || type == RegType::reference;
                                };
                                const auto integer_like = [](RegType type) {
                                    return type == RegType::int32 || type == RegType::scalar32;
                                };
                                const auto left_type = before[left];
                                const auto right_type = before[right];
                                if (!comparable(before[left]) || !comparable(before[right]) ||
                                    (left_type != RegType::unknown && right_type != RegType::unknown &&
                                     left_type != RegType::zero && right_type != RegType::zero &&
                                     !((integer_like(left_type) && integer_like(right_type)) ||
                                       (left_type == RegType::reference && right_type == RegType::reference))))
                                    return Error{ErrorCode::malformed,
                                        "DEX equality branch operands have incompatible register types"};
                            } else if (!expect_type(left, RegType::int32) ||
                                       !expect_type(right, RegType::int32)) {
                                return Error{ErrorCode::malformed,
                                    "DEX ordered branch operands are not integers"};
                            }
                        } else if (opcode >= 0x38 && opcode <= 0x3d) {
                            const bool zero_compare = opcode <= 0x39;
                            const auto compared = reg8;
                            if (zero_compare) {
                                if (before[compared] != RegType::unknown && before[compared] != RegType::zero &&
                                    before[compared] != RegType::int32 &&
                                    before[compared] != RegType::float32 && before[compared] != RegType::scalar32 &&
                                    before[compared] != RegType::reference)
                                    return Error{ErrorCode::malformed, "DEX if-eqz/if-nez operand has an incompatible type"};
                            } else if (!expect_type(compared, RegType::int32)) {
                                return Error{ErrorCode::malformed, "DEX ordered zero-branch operand is not an integer"};
                            }
                        } else if (opcode >= 0x0e && opcode <= 0x11) {
                            const auto &return_descriptor = types[protos[methods[method_idx].proto].return_type];
                            const auto expected = descriptor_type(return_descriptor);
                            if (opcode == 0x0e) {
                                if (expected != RegType::unknown)
                                    return Error{ErrorCode::malformed, "DEX return-void disagrees with its method prototype"};
                            } else if (opcode == 0x10) {
                                const bool floating = expected == RegType::wide_float_low;
                                if ((expected != RegType::wide_int_low && !floating) || !expect_wide(reg8, floating))
                                    return Error{ErrorCode::malformed, "DEX return-wide register type disagrees with its method prototype"};
                            } else {
                                const auto required = opcode == 0x11 ? RegType::reference : expected;
                                const bool return_form_matches = opcode == 0x11
                                    ? expected == RegType::reference
                                    : (expected == RegType::int32 || expected == RegType::float32);
                                if (!return_form_matches || !expect_type(reg8, required))
                                    return Error{ErrorCode::malformed, "DEX return register type disagrees with its method prototype"};
                            }
                        }

                        std::vector<std::uint32_t> successors;
                        const auto next = control.offset + control.length;
                        const auto add_next = [&] { if (next < insns * 2) successors.push_back(next); };
                        if (control.flow == FlowKind::fallthrough || control.flow == FlowKind::call) add_next();
                        else if (control.flow == FlowKind::conditional_branch) {
                            add_next(); if (control.target) successors.push_back(*control.target);
                        } else if (control.flow == FlowKind::jump) {
                            if (control.target) successors.push_back(*control.target);
                        } else if (control.flow == FlowKind::switch_dispatch) {
                            add_next();
                            if (const auto cases = switch_cases_by_source.find(control.offset);
                                cases != switch_cases_by_source.end())
                                successors.insert(successors.end(), cases->second.begin(), cases->second.end());
                        }
                        for (const auto successor : successors) {
                            auto [target, inserted] = incoming_states.try_emplace(successor, state);
                            if (inserted) { type_work.push_back(successor); continue; }
                            bool changed = false;
                            for (std::size_t reg = 0; reg < state.size(); ++reg) {
                                const auto merged = merge_type(target->second[reg], state[reg]);
                                if (merged != target->second[reg]) { target->second[reg] = merged; changed = true; }
                            }
                            if (changed) type_work.push_back(successor);
                        }
                    }
                }
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
            const auto compatible_static_value = [&](const DexEncodedValue &value, const Field &field) {
                if (field.type >= types.size()) return false;
                const auto &descriptor = types[field.type];
                switch (value.type) {
                case 0x00: return descriptor == "B";
                case 0x02: return descriptor == "S";
                case 0x03: return descriptor == "C";
                case 0x04: return descriptor == "I";
                case 0x06: return descriptor == "J";
                case 0x10: return descriptor == "F";
                case 0x11: return descriptor == "D";
                case 0x17: return descriptor == "Ljava/lang/String;";
                case 0x18: return descriptor == "Ljava/lang/Class;";
                case 0x15: return version >= 38 && descriptor == "Ljava/lang/invoke/MethodType;";
                case 0x16: return version >= 38 && descriptor == "Ljava/lang/invoke/MethodHandle;";
                case 0x1b:
                    return value.payload < fields.size() &&
                        fields[static_cast<std::size_t>(value.payload)].owner == field.type &&
                        fields[static_cast<std::size_t>(value.payload)].type == field.type;
                case 0x1e: return !descriptor.empty() && (descriptor.front() == 'L' || descriptor.front() == '[');
                case 0x1f: return descriptor == "Z" && value.payload <= 1;
                default: return false;
                }
            };
            for(std::uint32_t i=0;i<value_count;++i){
                auto value=decode_encoded_value(values,UINT32_MAX,0);
                if(!value)return value.error();
                const auto field_index=static_field_indices[i];
                if(field_index>=fields.size() || !compatible_static_value(value.value(),fields[field_index]))
                    return Error{ErrorCode::malformed,"DEX static encoded_value is incompatible with its FieldId descriptor"};
                decoded_static_values.push_back({class_type,field_index,std::move(value.value())});
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
        decoded_classes.push_back(std::move(class_definition));
    }
    std::unordered_set<std::uint32_t> all_defined_class_types;
    all_defined_class_types.reserve(decoded_classes.size());
    for (const auto &class_definition : decoded_classes)
        if (!all_defined_class_types.insert(class_definition.class_index).second)
            return Error{ErrorCode::malformed, "DEX class_defs contain a duplicate class type"};
    std::unordered_set<std::uint32_t> seen_class_types;
    seen_class_types.reserve(decoded_classes.size());
    for (const auto &class_definition : decoded_classes) {
        const auto dependency_must_precede = [&](std::uint32_t type) {
            return !all_defined_class_types.contains(type) || seen_class_types.contains(type);
        };
        if ((class_definition.superclass_index && !dependency_must_precede(*class_definition.superclass_index)) ||
            std::any_of(class_definition.interface_indices.begin(), class_definition.interface_indices.end(),
                [&](std::uint32_t type) { return !dependency_must_precede(type); }))
            return Error{ErrorCode::malformed, "DEX class_defs do not place defined superclasses and interfaces first"};
        seen_class_types.insert(class_definition.class_index);
    }
    // Method-handle kinds encode static/instance dispatch independently of
    // the identifier table. Cross-check locally defined targets against their
    // class_data access flags, while leaving external references unresolved.
    std::unordered_map<std::uint32_t, std::uint32_t> local_field_flags;
    std::unordered_map<std::uint32_t, std::uint32_t> local_method_flags;
    std::unordered_map<std::uint32_t, std::uint32_t> local_class_flags;
    for (const auto &class_definition : decoded_classes) {
        local_class_flags.emplace(class_definition.class_index, class_definition.access_flags);
        for (const auto &field : class_definition.static_fields)
            local_field_flags.emplace(field.field_index, field.access_flags);
        for (const auto &field : class_definition.instance_fields)
            local_field_flags.emplace(field.field_index, field.access_flags);
        for (const auto &method : class_definition.direct_methods)
            local_method_flags.emplace(method.method_index, method.access_flags);
        for (const auto &method : class_definition.virtual_methods)
            local_method_flags.emplace(method.method_index, method.access_flags);
    }
    for (const auto &handle : decoded_method_handles) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "DEX method-handle target validation canceled"};
        if (handle.kind <= 3) {
            const auto found = local_field_flags.find(handle.member_index);
            if (found != local_field_flags.end()) {
                const bool requires_static = handle.kind <= 1;
                if (((found->second & 0x0008u) != 0) != requires_static)
                    return Error{ErrorCode::malformed,
                        "DEX method_handle_item field kind disagrees with the locally defined field's static flag"};
            }
            continue;
        }
        const auto &method = methods[handle.member_index];
        const auto &method_name_value = strings[method.name];
        const bool constructor = method_name_value == "<init>";
        if ((handle.kind == 6) != constructor ||
            (handle.kind == 6 && types[protos[method.proto].return_type] != "V"))
            return Error{ErrorCode::malformed,
                "DEX method_handle_item constructor kind disagrees with the referenced method name or return type"};
        const auto found = local_method_flags.find(handle.member_index);
        if (found != local_method_flags.end()) {
            const bool requires_static = handle.kind == 4;
            if (((found->second & 0x0008u) != 0) != requires_static)
                return Error{ErrorCode::malformed,
                    "DEX method_handle_item invocation kind disagrees with the locally defined method's static flag"};
        }
        if (handle.kind == 8) {
            const auto owner_flags = local_class_flags.find(method.owner);
            if (owner_flags != local_class_flags.end() && (owner_flags->second & 0x0200u) == 0)
                return Error{ErrorCode::malformed,
                    "DEX invoke-interface method handle refers to a locally defined non-interface class"};
        }
    }
    if (map.value().has_hiddenapi && hiddenapi_data_cursor != hiddenapi_size)
        return Error{ErrorCode::malformed, "DEX hidden API section size does not match its class flag streams"};
    if(code.size()>max_items)return Error{ErrorCode::resource_limit,"DEX defined method count exceeds address-space budget"};
    std::vector<DexMethodParameterMetadata> decoded_method_parameters;
    constexpr std::uint64_t max_method_parameter_metadata_bytes = 64ull * 1024 * 1024;
    if (total_annotation_model_bytes > max_method_parameter_metadata_bytes ||
        methods.size() > max_method_parameter_metadata_bytes - total_annotation_model_bytes)
        return Error{ErrorCode::resource_limit, "DEX MethodParameters ownership index exceeds 64 MiB"};
    total_annotation_model_bytes += methods.size();
    std::vector<std::uint8_t> methods_with_parameter_annotations(methods.size());
    for (const auto &link : annotation_links) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX MethodParameters decoding canceled"};
        if (link.kind != DexAnnotationTargetKind::method || link.annotation_index >= decoded_annotations.size()) continue;
        const auto &annotation = decoded_annotations[link.annotation_index];
        if (annotation.type_index >= types.size() || types[annotation.type_index] != "Ldalvik/annotation/MethodParameters;") continue;
        if (link.member_index >= methods.size() || methods_with_parameter_annotations[link.member_index])
            return Error{ErrorCode::malformed, "DEX MethodParameters annotation has an invalid or duplicate method target"};
        methods_with_parameter_annotations[link.member_index] = 1;
        const auto &prototype = protos[methods[link.member_index].proto];
        const DexEncodedValue *names_value = nullptr, *flags_value = nullptr;
        for (const auto &element : annotation.elements) {
            if (element.name_index >= strings.size()) return Error{ErrorCode::malformed, "DEX MethodParameters element name is invalid"};
            const auto &name = strings[element.name_index];
            if (name == "names") names_value = &element;
            else if (name == "accessFlags") flags_value = &element;
        }
        if (!names_value || !flags_value || names_value->type != 0x1c || flags_value->type != 0x1c ||
            names_value->children.size() != prototype.parameters.size() ||
            flags_value->children.size() != prototype.parameters.size())
            return Error{ErrorCode::malformed, "DEX MethodParameters arrays do not match the method prototype"};
        for (std::uint32_t parameter = 0; parameter < prototype.parameters.size(); ++parameter) {
            const auto &name = names_value->children[parameter];
            const auto &flags = flags_value->children[parameter];
            if ((name.type != 0x1e && name.type != 0x17) || flags.type != 0x04)
                return Error{ErrorCode::malformed, "DEX MethodParameters contains a non-string name or non-int access flag"};
            std::optional<std::uint32_t> name_index;
            if (name.type == 0x17) {
                if (name.payload >= strings.size()) return Error{ErrorCode::malformed, "DEX MethodParameters name index is invalid"};
                const auto &text = strings[static_cast<std::size_t>(name.payload)];
                if (text.empty() || text.find_first_of(".;[/") != std::string::npos)
                    return Error{ErrorCode::malformed, "DEX MethodParameters name is empty or contains a forbidden character"};
                name_index = static_cast<std::uint32_t>(name.payload);
            }
            const auto access_flags = static_cast<std::uint32_t>(flags.payload);
            if (access_flags & ~std::uint32_t{0x9010})
                return Error{ErrorCode::malformed, "DEX MethodParameters access flags contain undefined bits"};
            if (decoded_method_parameters.size() >= 1'000'000 ||
                total_annotation_model_bytes > max_method_parameter_metadata_bytes - sizeof(DexMethodParameterMetadata))
                return Error{ErrorCode::resource_limit, "DEX MethodParameters metadata exceeds one million rows or 64 MiB"};
            total_annotation_model_bytes += sizeof(DexMethodParameterMetadata);
            decoded_method_parameters.push_back({link.member_index, parameter, name_index, access_flags,
                name.file_offset, flags.file_offset});
        }
    }

    if (methods.size() > max_method_parameter_metadata_bytes - total_annotation_model_bytes)
        return Error{ErrorCode::resource_limit, "DEX Throws target index exceeds the 64 MiB metadata limit"};
    total_annotation_model_bytes += methods.size();
    std::vector<DexMethodThrows> decoded_method_throws;
    std::vector<std::uint8_t> methods_with_throws(methods.size());
    for (const auto &link : annotation_links) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX Throws annotation decoding canceled"};
        if (link.kind != DexAnnotationTargetKind::method || link.annotation_index >= decoded_annotations.size()) continue;
        const auto &annotation = decoded_annotations[link.annotation_index];
        if (annotation.type_index >= types.size() || types[annotation.type_index] != "Ldalvik/annotation/Throws;" ||
            annotation.visibility != 2) continue;
        if (link.member_index >= methods.size() || methods_with_throws[link.member_index])
            return Error{ErrorCode::malformed, "DEX Throws annotation has an invalid or duplicate method target"};
        methods_with_throws[link.member_index] = 1;
        const DexEncodedValue *value = nullptr;
        for (const auto &element : annotation.elements) {
            if (element.name_index >= strings.size())
                return Error{ErrorCode::malformed, "DEX Throws element name is invalid"};
            if (strings[element.name_index] != "value" || value)
                return Error{ErrorCode::malformed, "DEX Throws annotation has an unexpected or duplicate element"};
            value = &element;
        }
        if (!value || value->type != 0x1c || value->children.size() > max_items)
            return Error{ErrorCode::malformed, "DEX Throws annotation value must be a bounded class array"};
        if (decoded_method_throws.size() >= 1'000'000 ||
            total_annotation_model_bytes > max_method_parameter_metadata_bytes - sizeof(DexMethodThrows))
            return Error{ErrorCode::resource_limit, "DEX Throws metadata exceeds one million rows or 64 MiB"};
        DexMethodThrows row;
        row.method_index = link.member_index;
        row.value_file_offset = value->file_offset;
        row.annotation_link_file_offset = link.file_offset;
        row.type_indices.reserve(value->children.size());
        total_annotation_model_bytes += sizeof(DexMethodThrows);
        for (const auto &entry : value->children) {
            if (entry.type != 0x18 || entry.payload >= types.size())
                return Error{ErrorCode::malformed, "DEX Throws array contains an invalid class type index"};
            if (total_annotation_model_bytes > max_method_parameter_metadata_bytes - sizeof(std::uint32_t))
                return Error{ErrorCode::resource_limit, "DEX Throws type rows exceed the 64 MiB metadata limit"};
            total_annotation_model_bytes += sizeof(std::uint32_t);
            row.type_indices.push_back(static_cast<std::uint32_t>(entry.payload));
        }
        decoded_method_throws.push_back(std::move(row));
    }

    DexMetadata dex_metadata;
    dex_metadata.map_items = std::move(map.value().items);
    dex_metadata.link_data_offset = link_off;
    dex_metadata.link_data_size = link_size;
    dex_metadata.field_identifiers.reserve(fields.size());
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if ((i & 0xffu) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "DEX identifier inventory canceled"};
        const auto &field = fields[i];
        dex_metadata.field_identifiers.push_back({field.owner, field.type, field.name, std::uint64_t(field_off) + i * 8});
    }
    dex_metadata.method_identifiers.reserve(methods.size());
    for (std::size_t i = 0; i < methods.size(); ++i) {
        if ((i & 0xffu) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "DEX identifier inventory canceled"};
        const auto &method = methods[i];
        dex_metadata.method_identifiers.push_back({method.owner, method.proto, method.name, std::uint64_t(method_off) + i * 8});
    }
    dex_metadata.prototype_return_kinds.reserve(protos.size());
    dex_metadata.prototype_return_type_indices.reserve(protos.size());
    dex_metadata.prototype_parameter_word_counts.reserve(protos.size());
    dex_metadata.prototype_parameter_offsets.reserve(protos.size() + 1);
    dex_metadata.prototype_parameter_offsets.push_back(0);
    dex_metadata.prototype_parameter_type_indices.reserve(static_cast<std::size_t>(total_proto_parameters));
    for (const auto &proto : protos) {
        const auto &descriptor = types[proto.return_type];
        const auto kind = descriptor == "V" ? DexReturnKind::void_value :
            descriptor == "F" ? DexReturnKind::float32 :
            descriptor == "D" ? DexReturnKind::float64 :
            descriptor == "J" ? DexReturnKind::integer64 :
            descriptor == "Z" || descriptor == "B" || descriptor == "C" || descriptor == "S" || descriptor == "I"
                ? DexReturnKind::integer32 :
            !descriptor.empty() && (descriptor.front() == 'L' || descriptor.front() == '[')
                ? DexReturnKind::reference : DexReturnKind::unknown;
        dex_metadata.prototype_return_kinds.push_back(kind);
        dex_metadata.prototype_return_type_indices.push_back(proto.return_type);
        std::uint32_t parameter_words = 0;
        for (const auto parameter : proto.parameters) {
            const auto &parameter_descriptor = types[parameter];
            const std::uint32_t width = parameter_descriptor == "J" || parameter_descriptor == "D" ? 2u : 1u;
            if (parameter_words > UINT32_MAX - width)
                return Error{ErrorCode::resource_limit, "DEX prototype parameter word count overflows"};
            parameter_words += width;
            dex_metadata.prototype_parameter_type_indices.push_back(parameter);
        }
        dex_metadata.prototype_parameter_word_counts.push_back(parameter_words);
        dex_metadata.prototype_parameter_offsets.push_back(static_cast<std::uint32_t>(
            dex_metadata.prototype_parameter_type_indices.size()));
    }
    dex_metadata.method_prototype_indices.reserve(methods.size());
    for (const auto &method : methods)
        dex_metadata.method_prototype_indices.push_back(method.proto);
    dex_metadata.classes = std::move(decoded_classes);
    dex_metadata.static_values = std::move(decoded_static_values);
    dex_metadata.method_handles = std::move(decoded_method_handles);
    dex_metadata.call_sites = std::move(decoded_call_sites);
    dex_metadata.annotations = std::move(decoded_annotations);
    dex_metadata.annotation_links = std::move(annotation_links);
    dex_metadata.annotation_sets = std::move(decoded_annotation_sets);
    dex_metadata.annotation_set_ref_lists = std::move(decoded_annotation_ref_lists);
    dex_metadata.annotation_directories = std::move(decoded_annotation_directories);
    dex_metadata.hidden_api_flags = std::move(decoded_hiddenapi_flags);
    dex_metadata.method_parameters = std::move(decoded_method_parameters);
    dex_metadata.method_throws = std::move(decoded_method_throws);
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
        bool prologue_end = false, epilogue_begin = false;
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
            row.prologue_end = prologue_end;
            row.epilogue_begin = epilogue_begin;
            prologue_end = false;
            epilogue_begin = false;
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
                // These flags annotate the next emitted source position.
                if (opcode == 7) prologue_end = true;
                else epilogue_begin = true;
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
    // Method labels above are the final users of the temporary type/string
    // tables. Preserve them once without leaving those users with moved data.
    dex_metadata.type_descriptors = std::move(types);
    dex_metadata.strings = std::move(strings);
    dex_metadata.string_sources = std::move(string_sources);
    auto image=Image::create(std::move(storage),std::move(layout));if(!image)return image.error();
    LoadedImage loaded;loaded.image=std::move(image.value());loaded.metadata.format=dex041_single_member?"Dalvik DEX 041 (container member)":"Dalvik DEX (035-040)";loaded.metadata.image_size=file_size;loaded.metadata_complete=false;
    loaded.metadata.dex = std::move(dex_metadata);
    loaded.diagnostics.push_back({DiagnosticSeverity::info,"DEX methods are mapped to method-relative address spaces; full verifier semantics and external member resolution are not implemented",{}});
    auto read=loaded.metadata_reads.include({0},file_size);if(!read)return read.error();loaded.metadata_reads_complete=true;return loaded;
}

struct Dex041RetainedUsage {
    std::uint64_t rows = 0;
    std::uint64_t string_capacity = 0;
    std::uint64_t retained_capacity_bytes = 0;
    std::uint64_t class_member_rows = 0;

    static void add(std::uint64_t &total, std::uint64_t value) {
        total = value > UINT64_MAX - total ? UINT64_MAX : total + value;
    }
    template <typename T> void vector(const std::vector<T> &items) {
        add(rows, items.size());
        const auto capacity = static_cast<std::uint64_t>(items.capacity());
        const auto bytes = capacity > UINT64_MAX / sizeof(T) ? UINT64_MAX : capacity * sizeof(T);
        add(retained_capacity_bytes, bytes);
    }
    void string(const std::string &value) {
        const auto capacity = static_cast<std::uint64_t>(value.capacity());
        add(string_capacity, capacity);
        add(retained_capacity_bytes, capacity);
    }
    void optional_string(const std::optional<std::string> &value) {
        if (value) string(*value);
    }
    void encoded_values(const std::vector<DexEncodedValue> &values, std::stop_token stop) {
        vector(values);
        for (const auto &value : values) {
            if (stop.stop_requested()) return;
            encoded_values(value.children, stop);
        }
    }
    void encoded_value(const DexEncodedValue &value, std::stop_token stop) {
        add(rows, 1);
        encoded_values(value.children, stop);
    }
};

Dex041RetainedUsage measure_dex041_retained_usage(const DexMetadata &dex, std::stop_token stop) {
    Dex041RetainedUsage usage;
    usage.vector(dex.map_items);
    usage.vector(dex.strings);
    for (const auto &value : dex.strings) { if (stop.stop_requested()) return usage; usage.string(value); }
    usage.vector(dex.string_sources);
    usage.vector(dex.field_identifiers);
    usage.vector(dex.method_identifiers);
    usage.vector(dex.type_descriptors);
    for (const auto &value : dex.type_descriptors) { if (stop.stop_requested()) return usage; usage.string(value); }
    usage.vector(dex.prototype_return_kinds);
    usage.vector(dex.prototype_return_type_indices);
    usage.vector(dex.prototype_parameter_offsets);
    usage.vector(dex.prototype_parameter_type_indices);
    usage.vector(dex.prototype_parameter_word_counts);
    usage.vector(dex.method_prototype_indices);
    usage.vector(dex.classes);
    usage.class_member_rows = dex.classes.size();
    for (const auto &item : dex.classes) {
        if (stop.stop_requested()) return usage;
        usage.vector(item.interface_indices); usage.class_member_rows += item.interface_indices.size();
        usage.vector(item.static_fields); usage.class_member_rows += item.static_fields.size();
        usage.vector(item.instance_fields); usage.class_member_rows += item.instance_fields.size();
        usage.vector(item.direct_methods); usage.class_member_rows += item.direct_methods.size();
        usage.vector(item.virtual_methods); usage.class_member_rows += item.virtual_methods.size();
        for (const auto &field : item.static_fields) { if (stop.stop_requested()) return usage; usage.string(field.name); }
        for (const auto &field : item.instance_fields) { if (stop.stop_requested()) return usage; usage.string(field.name); }
        for (const auto &method : item.direct_methods) { if (stop.stop_requested()) return usage; usage.string(method.name); }
        for (const auto &method : item.virtual_methods) { if (stop.stop_requested()) return usage; usage.string(method.name); }
    }
    usage.vector(dex.methods);
    for (const auto &method : dex.methods) {
        if (stop.stop_requested()) return usage;
        usage.vector(method.parameter_names);
        for (const auto &name : method.parameter_names) { if (stop.stop_requested()) return usage; usage.optional_string(name); }
        usage.vector(method.lines);
        for (const auto &line : method.lines) { if (stop.stop_requested()) return usage; usage.string(line.source_file); }
        usage.vector(method.locals);
        for (const auto &local : method.locals) {
            if (stop.stop_requested()) return usage;
            usage.optional_string(local.name); usage.optional_string(local.type); usage.optional_string(local.signature);
        }
    }
    usage.vector(dex.code);
    for (const auto &code : dex.code) {
        if (stop.stop_requested()) return usage;
        usage.vector(code.exception_regions);
        for (const auto &region : code.exception_regions) usage.vector(region.handlers);
    }
    usage.vector(dex.static_values);
    for (const auto &value : dex.static_values) { if (stop.stop_requested()) return usage; usage.encoded_value(value.value, stop); }
    usage.vector(dex.method_handles);
    usage.vector(dex.call_sites);
    for (const auto &site : dex.call_sites) { if (stop.stop_requested()) return usage; usage.encoded_values(site.values, stop); }
    usage.vector(dex.annotations);
    for (const auto &annotation : dex.annotations) { if (stop.stop_requested()) return usage; usage.encoded_values(annotation.elements, stop); }
    usage.vector(dex.annotation_links);
    usage.vector(dex.annotation_sets);
    for (const auto &set : dex.annotation_sets) usage.vector(set.annotation_indices);
    usage.vector(dex.annotation_set_ref_lists);
    for (const auto &list : dex.annotation_set_ref_lists) usage.vector(list.set_offsets);
    usage.vector(dex.annotation_directories);
    for (const auto &directory : dex.annotation_directories) {
        usage.vector(directory.fields); usage.vector(directory.methods); usage.vector(directory.parameters);
    }
    usage.vector(dex.hidden_api_flags);
    usage.vector(dex.method_parameters);
    usage.vector(dex.method_throws);
    for (const auto &throws_row : dex.method_throws) usage.vector(throws_row.type_indices);
    return usage;
}
}

DexMetadataUsage measure_dex_metadata_usage(const DexMetadata &dex, std::stop_token stop) {
    const auto usage = measure_dex041_retained_usage(dex, stop);
    return {usage.rows, usage.string_capacity, usage.retained_capacity_bytes, usage.class_member_rows};
}

Result<std::vector<LoadedImage>> load_dex041_container(std::shared_ptr<const ByteStorage> storage,
                                                        std::stop_token stop) {
    if (!storage) return Error{ErrorCode::invalid_argument, "DEX 041 loader requires input storage"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX loading canceled"};
    try {
        auto members = inspect_dex041_container(*storage, stop);
        if (!members) return members.error();
        if (members.value().size() > max_loaded_dex041_members)
            return Error{ErrorCode::resource_limit, "DEX 041 loading is limited to 256 logical members"};
        if (storage->size() > max_file_size || storage->size() > SIZE_MAX)
            return Error{ErrorCode::resource_limit, "DEX input exceeds the 512 MiB parser limit"};
        std::uint64_t total_member_bytes = 0;
        for (const auto &member : members.value()) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX container preflight canceled"};
            if (member.logical_file_size > max_file_size - total_member_bytes)
                return Error{ErrorCode::resource_limit, "DEX 041 cumulative logical member bytes exceed 512 MiB"};
            total_member_bytes += member.logical_file_size;
        }
        if (total_member_bytes != storage->size())
            return Error{ErrorCode::malformed, "DEX 041 logical member byte extents do not cover the physical container exactly"};
        const auto physical_size = static_cast<std::size_t>(storage->size());
        auto source = storage->read_at({0}, physical_size);
        if (!source) return source.error();
        if (source.value().bytes.size() != physical_size)
            return Error{ErrorCode::io, "DEX source returned an incomplete container read"};
        const auto bytes = std::span<const std::byte>(source.value().bytes);
        std::uint64_t total_declared_rows = 0;
        std::uint64_t total_mapped_rows = 0;
        for (const auto &member : members.value()) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX container parsing canceled"};
            Reader map_header{bytes};
            if (!map_header.seek(member.header_offset + 52))
                return Error{ErrorCode::malformed, "DEX 041 member map offset field is truncated"};
            std::uint32_t map_offset = 0;
            if (!map_header.u32(map_offset))
                return Error{ErrorCode::malformed, "DEX 041 member map offset field is truncated"};
            auto map = parse_map(bytes, map_offset);
            if (!map) return map.error();
            for (const auto &item : map.value().items) {
                Dex041RetainedUsage::add(total_mapped_rows, item.size);
                if (total_mapped_rows > max_dex041_aggregate_rows)
                    return Error{ErrorCode::resource_limit,
                        "DEX 041 mapped section item counts exceed the aggregate two-million-row limit"};
            }
            Reader header{bytes};
            if (!header.seek(member.header_offset + 56))
                return Error{ErrorCode::malformed, "DEX 041 member table header is truncated"};
            std::uint32_t strings = 0, ignored = 0, types = 0, ignored2 = 0, protos = 0, ignored3 = 0;
            std::uint32_t fields = 0, ignored4 = 0, methods = 0, ignored5 = 0, classes = 0;
            if (!header.u32(strings) || !header.u32(ignored) || !header.u32(types) || !header.u32(ignored2) ||
                !header.u32(protos) || !header.u32(ignored3) || !header.u32(fields) || !header.u32(ignored4) ||
                !header.u32(methods) || !header.u32(ignored5) || !header.u32(classes))
                return Error{ErrorCode::malformed, "DEX 041 member table header is truncated"};
            total_declared_rows += std::uint64_t(strings) + types + protos + fields + methods + classes;
            if (total_declared_rows > max_items)
                return Error{ErrorCode::resource_limit, "DEX 041 container identifier tables exceed one million rows in aggregate"};
        }
        std::vector<LoadedImage> loaded;
        loaded.reserve(members.value().size());
        Dex041RetainedUsage aggregate_usage;
        for (const auto &member : members.value()) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX container parsing canceled"};
            auto parsed = parse(storage, bytes, member.header_offset, stop);
            if (!parsed) return parsed.error();
            if (!parsed.value().metadata.dex)
                return Error{ErrorCode::malformed, "DEX 041 member parser did not produce typed metadata"};
            const auto member_usage = measure_dex041_retained_usage(*parsed.value().metadata.dex, stop);
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX container metadata accounting canceled"};
            Dex041RetainedUsage::add(aggregate_usage.rows, member_usage.rows);
            Dex041RetainedUsage::add(aggregate_usage.string_capacity, member_usage.string_capacity);
            Dex041RetainedUsage::add(aggregate_usage.retained_capacity_bytes, member_usage.retained_capacity_bytes);
            Dex041RetainedUsage::add(aggregate_usage.class_member_rows, member_usage.class_member_rows);
            if (aggregate_usage.rows > max_dex041_aggregate_rows)
                return Error{ErrorCode::resource_limit, "DEX 041 retained metadata exceeds the aggregate two-million-row limit"};
            if (aggregate_usage.string_capacity > max_dex041_aggregate_strings)
                return Error{ErrorCode::resource_limit, "DEX 041 decoded string capacities exceed the aggregate 64 MiB limit"};
            if (aggregate_usage.retained_capacity_bytes > max_dex041_aggregate_metadata_capacity)
                return Error{ErrorCode::resource_limit, "DEX 041 retained metadata vector/string capacities exceed the aggregate 256 MiB limit"};
            if (aggregate_usage.class_member_rows > max_dex041_aggregate_class_member_rows)
                return Error{ErrorCode::resource_limit, "DEX 041 class, interface, and declared member rows exceed the aggregate one-million-row limit"};
            parsed.value().diagnostics.push_back({DiagnosticSeverity::info,
                "Loaded logical DEX 041 member at physical container offset 0x" +
                    [&] { std::ostringstream text; text << std::hex << member.header_offset; return text.str(); }() +
                    "; offsets and shared data remain container-relative", {}});
            loaded.push_back(std::move(parsed.value()));
        }
        return loaded;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate DEX 041 container parser state"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "DEX 041 container parser state exceeds limits"};
    }
}

Result<LoadedImage> load_dex(std::shared_ptr<const ByteStorage> storage,std::stop_token stop){
    if(!storage)return Error{ErrorCode::invalid_argument,"DEX loader requires input storage"};
    if(stop.stop_requested())return Error{ErrorCode::canceled,"DEX loading canceled"};
    try {
        if (storage->size() > max_file_size || storage->size() > SIZE_MAX)
            return Error{ErrorCode::resource_limit,"DEX input exceeds the 512 MiB parser limit"};
        auto source = storage->read_at({0}, static_cast<std::size_t>(storage->size()));
        if (!source) return source.error();
        if (source.value().bytes.size() != storage->size())
            return Error{ErrorCode::io,"DEX source returned an incomplete read"};
        const auto bytes = std::span<const std::byte>(source.value().bytes);
        if (bytes.size() >= 8 && std::memcmp(bytes.data(), "dex\n041\0", 8) == 0) {
            auto members = inspect_dex041_container(*storage, stop);
            if (!members) return members.error();
            if (members.value().size() != 1)
                return Error{ErrorCode::unsupported,
                    "DEX 041 container has multiple logical members; use load_dex041_container to load them all"};
        }
        return parse(std::move(storage), bytes, 0, stop);
    } catch(const std::bad_alloc&) { return Error{ErrorCode::resource_limit,"Cannot allocate DEX parser state"}; }
      catch(const std::length_error&) { return Error{ErrorCode::resource_limit,"DEX parser state exceeds container limits"}; }
}
} // namespace hexlab
