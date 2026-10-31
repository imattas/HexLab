#include "hexlab/loaders/ar.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <unordered_set>

namespace hexlab {
Result<ArMemberSymbols> summarize_xcoff64_ar_member(const ByteStorage &, std::size_t,
                                                    std::stop_token, ArObjectLimits);
Result<ArMemberSymbols> summarize_xcoff32_ar_member(const ByteStorage &, std::size_t,
                                                    std::stop_token, ArObjectLimits);
namespace {
struct Failure { Error error; };
void require(bool ok, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "COFF archive member scan canceled", ErrorCode::canceled);
}
std::uint64_t le(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    require(at <= bytes.size() && width <= bytes.size() - at, "Truncated COFF archive record");
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i) v |= std::to_integer<std::uint64_t>(bytes[at + i]) << (i * 8);
    return v;
}
std::vector<std::byte> read(const ByteStorage &storage, std::uint64_t offset, std::uint64_t size,
                            std::uint64_t &budget, const ArObjectLimits &limits, std::stop_token stop) {
    canceled(stop);
    require(size <= limits.max_metadata_bytes - budget, "COFF archive metadata limit exceeded", ErrorCode::resource_limit);
    require(offset <= storage.size() && size <= storage.size() - offset, "COFF archive record exceeds member extent");
    require(size <= std::numeric_limits<std::size_t>::max(), "COFF archive record exceeds host address space", ErrorCode::resource_limit);
    budget += size;
    auto view = storage.read_at({offset}, static_cast<std::size_t>(size));
    if (!view) throw Failure{view.error()};
    require(view.value().bytes.size() == size, "Incomplete COFF archive member view", ErrorCode::io);
    canceled(stop);
    return {view.value().bytes.begin(), view.value().bytes.end()};
}
std::string symbol_name(std::span<const std::byte> row, std::span<const std::byte> strings,
                        std::size_t max_name_bytes) {
    const auto zeroes = le(row, 0, 4);
    const auto offset = le(row, 4, 4);
    std::size_t begin = 0, limit = 8;
    if (zeroes == 0) {
        require(offset >= 4 && offset < strings.size(), "COFF long symbol name is outside string table");
        begin = static_cast<std::size_t>(offset);
        limit = strings.size();
    }
    std::size_t end = begin;
    while (end < limit && (zeroes == 0 ? strings[end] : row[end]) != std::byte{0}) ++end;
    // Inline names may occupy all eight bytes without a NUL terminator.
    // String-table names must terminate inside the declared table extent.
    require(zeroes != 0 || end < limit, "Unterminated COFF symbol name");
    const auto length = end - begin;
    require(length <= max_name_bytes, "COFF symbol name exceeds limit", ErrorCode::resource_limit);
    if (length == 0) return {};
    const auto *data = zeroes == 0 ? strings.data() + begin : row.data() + begin;
    return {reinterpret_cast<const char *>(data), length};
}
std::string nul_string(std::span<const std::byte> bytes, std::size_t &at, std::size_t limit,
                       std::size_t max_name_bytes, const char *description) {
    require(at < limit && limit <= bytes.size(), "Import-object string extent is invalid");
    const auto begin = at;
    while (at < limit && bytes[at] != std::byte{0}) {
        require(at - begin < max_name_bytes, description, ErrorCode::resource_limit);
        ++at;
    }
    require(at < limit, "Unterminated COFF import-object string");
    const auto size = at - begin;
    ++at;
    require(size != 0, "Empty COFF import-object string");
    return {reinterpret_cast<const char *>(bytes.data() + begin), size};
}
void summarize_import_object(const ByteStorage &storage, std::size_t member_index,
                             std::uint64_t &budget, const ArObjectLimits &limits,
                             ArMemberSymbols &result, std::stop_token stop) {
    require(storage.size() >= 20, "Truncated COFF import-object header");
    const auto header = read(storage, 0, 20, budget, limits, stop);
    require(le(header, 0, 2) == 0 && le(header, 2, 2) == 0xffff,
            "Invalid COFF import-object signature");
    require(le(header, 4, 2) == 0, "Unsupported COFF import-object version", ErrorCode::unsupported);
    const auto size = le(header, 12, 4);
    require(size > 0 && size == storage.size() - 20,
            "COFF import-object payload size disagrees with its member extent");
    require(size <= limits.max_metadata_bytes - budget,
            "COFF archive metadata limit exceeded", ErrorCode::resource_limit);
    const auto payload = read(storage, 20, size, budget, limits, stop);
    const auto type_info = le(header, 18, 2);
    const auto import_type = type_info & 3;
    const auto name_type = (type_info >> 2) & 7;
    require((type_info >> 5) == 0, "COFF import-object reserved bits must be zero");
    require(import_type <= 2 && name_type <= 4,
            "COFF import-object type is invalid", ErrorCode::unsupported);
    std::size_t at = 0;
    auto imported = nul_string(payload, at, payload.size(), limits.max_name_bytes,
                               "COFF import symbol name exceeds limit");
    const auto dll = nul_string(payload, at, payload.size(), limits.max_name_bytes,
                                "COFF import DLL name exceeds limit");
    if (name_type == 4) {
        const auto export_as = nul_string(payload, at, payload.size(), limits.max_name_bytes,
                                          "COFF import export alias exceeds limit");
        (void)export_as;
    }
    require(at == payload.size(), "COFF import-object payload has trailing data");
    result.member_index = member_index;
    if (import_type == 0)
        result.definitions.push_back(imported);
    {
        std::string iat = "__imp_" + imported;
        require(iat.size() <= limits.max_name_bytes,
                "COFF import address symbol exceeds limit", ErrorCode::resource_limit);
        result.definitions.push_back(std::move(iat));
    }
    (void)dll;
}
}

Result<ArMemberSymbols> summarize_coff_ar_member(const ByteStorage &storage, std::size_t member_index,
                                                std::stop_token stop, ArObjectLimits limits) {
    try {
        require(limits.max_metadata_bytes > 0 && limits.max_sections > 0 && limits.max_symbols > 0 && limits.max_name_bytes > 0,
                "COFF archive object limits must be positive", ErrorCode::invalid_argument);
        canceled(stop);
        std::uint64_t budget = 0;
        auto header = read(storage, 0, std::min<std::uint64_t>(storage.size(), 20), budget, limits, stop);
        require(header.size() >= 4, "Truncated COFF archive object");
        if (header[0] == std::byte{0x01} && header[1] == std::byte{0xf7})
            return summarize_xcoff64_ar_member(storage, member_index, stop, limits);
        if (header[0] == std::byte{0x01} && header[1] == std::byte{0xdf})
            return summarize_xcoff32_ar_member(storage, member_index, stop, limits);
        const bool anon = le(header, 0, 2) == 0 && le(header, 2, 2) == 0xffff;
        if (anon && header.size() >= 6 && le(header, 4, 2) >= 2) {
            require(storage.size() >= 56, "Truncated bigobj COFF header");
            auto extension = read(storage, 20, 36, budget, limits, stop);
            header.insert(header.end(), extension.begin(), extension.end());
        }
        if (anon) {
            static constexpr std::array<std::uint8_t,16> bigobj_class_id{
                0xc7,0xa1,0xba,0xd1,0xee,0xba,0xa9,0x4b,0xaf,0x20,0xfa,0xf6,0x6a,0xa4,0xdc,0xb8};
            const bool bigobj = header.size() >= 56 && le(header, 4, 2) >= 2 &&
                std::equal(bigobj_class_id.begin(), bigobj_class_id.end(), header.begin() + 12,
                    [](std::uint8_t a, std::byte b) { return a == std::to_integer<std::uint8_t>(b); });
            if (!bigobj) {
                ArMemberSymbols result;
                summarize_import_object(storage, member_index, budget, limits, result, stop);
                return result;
            }
        }
        const bool bigobj = anon && header.size() >= 56 && le(header, 4, 2) >= 2;
        const auto header_size = bigobj ? 56u : 20u;
        require(header.size() >= header_size, "Truncated COFF object header");
        const auto section_count = bigobj ? le(header, 44, 4) : le(header, 2, 2);
        const auto optional_size = bigobj ? 0 : le(header, 16, 2);
        const auto symbol_offset = bigobj ? le(header, 48, 4) : le(header, 8, 4);
        const auto symbol_count = bigobj ? le(header, 52, 4) : le(header, 12, 4);
        require(optional_size == 0, "COFF archive member must be an object without an optional header", ErrorCode::unsupported);
        require(section_count <= limits.max_sections, "COFF archive section count limit exceeded", ErrorCode::resource_limit);
        require(symbol_count <= limits.max_symbols, "COFF archive symbol count limit exceeded", ErrorCode::resource_limit);
        // Validate the section table even though symbol classification only needs section ordinals.
        const auto section_at = static_cast<std::uint64_t>(header_size);
        (void)read(storage, section_at, section_count * 40, budget, limits, stop);
        ArMemberSymbols result;
        result.member_index = member_index;
        if (symbol_count == 0) return result;
        const auto symbol_size = bigobj ? 20u : 18u;
        require(symbol_count == 0 || symbol_offset >= section_at + section_count * 40,
                "COFF symbol table overlaps the section table");
        require(symbol_count <= (UINT64_MAX - symbol_offset) / symbol_size, "COFF symbol table extent overflows", ErrorCode::overflow);
        auto symbols = read(storage, symbol_offset, symbol_count * symbol_size, budget, limits, stop);
        const auto strings_at = symbol_offset + symbol_count * symbol_size;
        const auto string_size_bytes = read(storage, strings_at, 4, budget, limits, stop);
        const auto string_size = le(string_size_bytes, 0, 4);
        require(string_size >= 4, "COFF string table size is smaller than its header");
        std::vector<std::byte> strings = string_size == 4 ? string_size_bytes :
            read(storage, strings_at, string_size, budget, limits, stop);

        std::unordered_set<std::string> defined, undefined;
        for (std::uint64_t i = 0; i < symbol_count;) {
            canceled(stop);
            const auto row = std::span<const std::byte>(symbols).subspan(static_cast<std::size_t>(i * symbol_size), symbol_size);
            const auto value = le(row, 8, 4);
            const auto section = bigobj ? static_cast<std::int32_t>(le(row, 12, 4)) :
                static_cast<std::int16_t>(le(row, 12, 2));
            const auto storage_class = le(row, bigobj ? 18 : 16, 1);
            const auto aux_count = le(row, bigobj ? 19 : 17, 1);
            require(aux_count <= symbol_count - i - 1, "COFF auxiliary symbol count exceeds table");
            require(section >= -2 && (section <= 0 || static_cast<std::uint32_t>(section) <= section_count),
                    "COFF symbol section number is invalid");
            // External symbols define a name in a section or absolute scope.
            // A zero-section, nonzero-value external is a COFF common symbol:
            // it can satisfy an unresolved reference and pull this member.
            // Undefined weak externals do not pull archive members.
            if (storage_class == 2 && (section != 0)) {
                auto name = symbol_name(row, strings, limits.max_name_bytes);
                if (!name.empty() && defined.emplace(name).second) result.definitions.push_back(std::move(name));
            } else if (storage_class == 2 && section == 0) {
                auto name = symbol_name(row, strings, limits.max_name_bytes);
                if (value != 0) {
                    if (!name.empty() && defined.emplace(name).second) result.definitions.push_back(std::move(name));
                } else if (!name.empty() && undefined.emplace(name).second) {
                    result.undefined.push_back(std::move(name));
                }
            }
            i += 1 + aux_count;
        }
        result.undefined.erase(std::remove_if(result.undefined.begin(), result.undefined.end(),
                                              [&](const auto &name) { return defined.contains(name); }), result.undefined.end());
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate COFF archive symbol summary"}; }
}
} // namespace hexlab
