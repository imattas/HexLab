#include "hexlab/loaders/ar.hpp"
#include <algorithm>
#include <limits>
#include <unordered_set>

namespace hexlab {
namespace {
struct Failure { Error error; };

void require(bool ok, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, message}};
}

std::uint64_t be(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    require(at <= bytes.size() && width <= bytes.size() - at, "Truncated XCOFF64 record");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value = (value << 8) | std::to_integer<std::uint8_t>(bytes[at + i]);
    return value;
}

std::vector<std::byte> read(const ByteStorage &storage, std::uint64_t offset, std::uint64_t size,
                            std::uint64_t &budget, const ArObjectLimits &limits,
                            std::stop_token stop) {
    require(!stop.stop_requested(), "XCOFF64 archive member scan canceled", ErrorCode::canceled);
    require(budget <= limits.max_metadata_bytes && size <= limits.max_metadata_bytes - budget,
            "XCOFF64 archive metadata limit exceeded", ErrorCode::resource_limit);
    require(offset <= storage.size() && size <= storage.size() - offset,
            "XCOFF64 archive record exceeds member extent");
    require(size <= std::numeric_limits<std::size_t>::max(),
            "XCOFF64 archive record exceeds host address space", ErrorCode::resource_limit);
    budget += size;
    auto view = storage.read_at({offset}, static_cast<std::size_t>(size));
    if (!view) throw Failure{view.error()};
    require(view.value().bytes.size() == size, "Incomplete XCOFF64 archive member view", ErrorCode::io);
    require(!stop.stop_requested(), "XCOFF64 archive member scan canceled", ErrorCode::canceled);
    return {view.value().bytes.begin(), view.value().bytes.end()};
}

std::string symbol_name(std::span<const std::byte> row, std::span<const std::byte> strings,
                        std::size_t max_name_bytes) {
    // XCOFF64 stores a string-table offset in n_offset64; unlike XCOFF32,
    // the fixed symbol row has no inline-name representation.
    const auto offset = be(row, 8, 4);
    require(offset >= 4 && offset < strings.size(), "XCOFF64 symbol name offset is outside string table");
    auto end = static_cast<std::size_t>(offset);
    while (end < strings.size() && strings[end] != std::byte{0}) ++end;
    require(end < strings.size(), "Unterminated XCOFF64 symbol name");
    const auto length = end - static_cast<std::size_t>(offset);
    require(length <= max_name_bytes, "XCOFF64 symbol name exceeds limit", ErrorCode::resource_limit);
    if (length == 0) return {};
    return {reinterpret_cast<const char *>(strings.data() + offset), length};
}
}

Result<ArMemberSymbols> summarize_xcoff32_ar_member(const ByteStorage &storage,
                                                    std::size_t member_index,
                                                    std::stop_token stop,
                                                    ArObjectLimits limits) {
    try {
        require(limits.max_metadata_bytes > 0 && limits.max_sections > 0 &&
                    limits.max_symbols > 0 && limits.max_name_bytes > 0,
                "XCOFF32 archive object limits must be positive", ErrorCode::invalid_argument);
        require(!stop.stop_requested(), "XCOFF32 archive member scan canceled", ErrorCode::canceled);
        require(storage.size() >= 20, "Truncated XCOFF32 file header");
        std::uint64_t budget = 0;
        const auto header = read(storage, 0, 20, budget, limits, stop);
        require(be(header, 0, 2) == 0x01df, "Invalid XCOFF32 magic");
        const auto section_count = be(header, 2, 2);
        const auto symbol_offset = be(header, 8, 4);
        const auto symbol_count = be(header, 12, 4);
        const auto optional_size = be(header, 16, 2);
        require((be(header, 18, 2) & 0x0002u) == 0,
                "XCOFF32 archive member is an F_EXEC image", ErrorCode::unsupported);
        require(optional_size == 0,
                "XCOFF32 archive member must be a relocatable object without an auxiliary header",
                ErrorCode::unsupported);
        require(section_count <= limits.max_sections,
                "XCOFF32 archive section count limit exceeded", ErrorCode::resource_limit);
        require(symbol_count <= limits.max_symbols,
                "XCOFF32 archive symbol count limit exceeded", ErrorCode::resource_limit);
        constexpr std::uint64_t file_header_size = 20;
        constexpr std::uint64_t section_header_size = 40;
        require(section_count <= (UINT64_MAX - file_header_size) / section_header_size,
                "XCOFF32 section table extent overflows", ErrorCode::overflow);
        const auto section_end = file_header_size + section_count * section_header_size;
        require(section_end <= storage.size(), "XCOFF32 section table exceeds member extent");
        (void)read(storage, file_header_size, section_count * section_header_size, budget, limits, stop);

        ArMemberSymbols result;
        result.member_index = member_index;
        if (symbol_count == 0) return result;
        constexpr std::uint64_t symbol_size = 18;
        require(symbol_offset >= section_end, "XCOFF32 symbol table overlaps headers");
        require(symbol_count <= (UINT64_MAX - symbol_offset) / symbol_size,
                "XCOFF32 symbol table extent overflows", ErrorCode::overflow);
        const auto symbol_bytes = symbol_count * symbol_size;
        const auto strings_offset = symbol_offset + symbol_bytes;
        const auto string_header = read(storage, strings_offset, 4, budget, limits, stop);
        const auto string_size = be(string_header, 0, 4);
        require(string_size >= 4, "XCOFF32 string table size is smaller than its header");
        const auto strings = string_size == 4 ? string_header :
            read(storage, strings_offset, string_size, budget, limits, stop);
        const auto symbols = read(storage, symbol_offset, symbol_bytes, budget, limits, stop);

        constexpr std::uint8_t c_ext = 2;
        std::unordered_set<std::string> definitions, undefined;
        for (std::uint64_t i = 0; i < symbol_count;) {
            require(!stop.stop_requested(), "XCOFF32 archive member scan canceled", ErrorCode::canceled);
            const auto row = std::span<const std::byte>(symbols).subspan(
                static_cast<std::size_t>(i * symbol_size), static_cast<std::size_t>(symbol_size));
            const auto value = be(row, 8, 4);
            const auto section = static_cast<std::int16_t>(be(row, 12, 2));
            const auto storage_class = static_cast<std::uint8_t>(be(row, 16, 1));
            const auto aux_count = be(row, 17, 1);
            require(aux_count <= symbol_count - i - 1,
                    "XCOFF32 auxiliary symbol count exceeds table");
            require(section >= -2 && (section <= 0 || static_cast<std::uint16_t>(section) <= section_count),
                    "XCOFF32 symbol section number is invalid");
            if (storage_class == c_ext) {
                const auto zeroes = be(row, 0, 4);
                const auto name_offset = be(row, 4, 4);
                std::size_t begin = 0, end = 8;
                if (zeroes == 0) {
                    require(name_offset >= 4 && name_offset < strings.size(),
                            "XCOFF32 symbol name offset is outside string table");
                    begin = static_cast<std::size_t>(name_offset);
                    end = strings.size();
                }
                auto terminator = begin;
                while (terminator < end && (zeroes == 0 ? strings[terminator] : row[terminator]) != std::byte{0})
                    ++terminator;
                require(zeroes != 0 || terminator < end, "Unterminated XCOFF32 symbol name");
                const auto length = terminator - begin;
                require(length <= limits.max_name_bytes,
                        "XCOFF32 symbol name exceeds limit", ErrorCode::resource_limit);
                require(length <= limits.max_metadata_bytes - budget,
                        "XCOFF32 decoded symbol names exceed metadata budget", ErrorCode::resource_limit);
                budget += length;
                if (length != 0) {
                    const auto *data = zeroes == 0 ? strings.data() + begin : row.data() + begin;
                    std::string name(reinterpret_cast<const char *>(data), length);
                    if (section > 0 || section == -1 || (section == 0 && value != 0)) {
                        if (definitions.emplace(name).second) result.definitions.push_back(std::move(name));
                    } else if (section == 0 && undefined.emplace(name).second) {
                        result.undefined.push_back(std::move(name));
                    }
                }
            }
            i += 1 + aux_count;
        }
        result.undefined.erase(std::remove_if(result.undefined.begin(), result.undefined.end(),
            [&](const auto &name) { return definitions.contains(name); }), result.undefined.end());
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate XCOFF32 archive symbol summary"};
    }
}

Result<ArMemberSymbols> summarize_xcoff64_ar_member(const ByteStorage &storage,
                                                    std::size_t member_index,
                                                    std::stop_token stop,
                                                    ArObjectLimits limits) {
    try {
        require(limits.max_metadata_bytes > 0 && limits.max_sections > 0 &&
                    limits.max_symbols > 0 && limits.max_name_bytes > 0,
                "XCOFF64 archive object limits must be positive", ErrorCode::invalid_argument);
        require(!stop.stop_requested(), "XCOFF64 archive member scan canceled", ErrorCode::canceled);
        require(storage.size() >= 24, "Truncated XCOFF64 file header");
        std::uint64_t budget = 0;
        const auto header = read(storage, 0, 24, budget, limits, stop);
        require(be(header, 0, 2) == 0x01f7, "Invalid XCOFF64 magic");
        const auto section_count = be(header, 2, 2);
        const auto symbol_offset = be(header, 8, 8);
        const auto optional_size = be(header, 16, 2);
        const auto symbol_count = be(header, 20, 4);
        require((be(header, 18, 2) & 0x0002u) == 0,
                "XCOFF64 archive member is an F_EXEC image", ErrorCode::unsupported);
        require(optional_size == 0,
                "XCOFF64 archive member must be a relocatable object without an auxiliary header",
                ErrorCode::unsupported);
        require(section_count <= limits.max_sections,
                "XCOFF64 archive section count limit exceeded", ErrorCode::resource_limit);
        require(symbol_count <= limits.max_symbols,
                "XCOFF64 archive symbol count limit exceeded", ErrorCode::resource_limit);
        constexpr std::uint64_t file_header_size = 24;
        constexpr std::uint64_t section_header_size = 72;
        require(section_count <= (UINT64_MAX - file_header_size) / section_header_size,
                "XCOFF64 section table extent overflows", ErrorCode::overflow);
        const auto section_end = file_header_size + section_count * section_header_size;
        require(section_end <= storage.size(), "XCOFF64 section table exceeds member extent");
        (void)read(storage, file_header_size, section_count * section_header_size, budget, limits, stop);

        ArMemberSymbols result;
        result.member_index = member_index;
        if (symbol_count == 0) return result;
        constexpr std::uint64_t symbol_size = 18;
        require(symbol_offset >= section_end, "XCOFF64 symbol table overlaps headers");
        require(symbol_count <= (UINT64_MAX - symbol_offset) / symbol_size,
                "XCOFF64 symbol table extent overflows", ErrorCode::overflow);
        const auto symbol_bytes = symbol_count * symbol_size;
        const auto strings_offset = symbol_offset + symbol_bytes;
        const auto symbols = read(storage, symbol_offset, symbol_bytes, budget, limits, stop);
        const auto string_size_bytes = read(storage, strings_offset, 4, budget, limits, stop);
        const auto string_size = be(string_size_bytes, 0, 4);
        require(string_size >= 4, "XCOFF64 string table size is smaller than its header");
        const auto strings = string_size == 4 ? string_size_bytes :
            read(storage, strings_offset, string_size, budget, limits, stop);

        // C_EXT rows are the strong global symbol records used by archive
        // extraction. C_WEAKEXT definitions are intentionally omitted because
        // weak references must not pull an archive member into the link.
        constexpr std::uint8_t c_ext = 2;
        constexpr std::uint8_t c_weakext = 111;
        std::unordered_set<std::string> definitions, undefined;
        for (std::uint64_t i = 0; i < symbol_count;) {
            require(!stop.stop_requested(), "XCOFF64 archive member scan canceled", ErrorCode::canceled);
            const auto row = std::span<const std::byte>(symbols).subspan(
                static_cast<std::size_t>(i * symbol_size), static_cast<std::size_t>(symbol_size));
            const auto value = be(row, 0, 8);
            const auto raw_section = be(row, 12, 2);
            const auto section = static_cast<std::int16_t>(raw_section);
            const auto storage_class = be(row, 16, 1);
            const auto aux_count = be(row, 17, 1);
            require(aux_count <= symbol_count - i - 1,
                    "XCOFF64 auxiliary symbol count exceeds table");
            require(section >= -2 && (section <= 0 || static_cast<std::uint16_t>(section) <= section_count),
                    "XCOFF64 symbol section number is invalid");
            if (storage_class == c_ext) {
                auto name = symbol_name(row, strings, limits.max_name_bytes);
                if (!name.empty()) {
                    if (section > 0 || section == -1) {
                        if (definitions.emplace(name).second) result.definitions.push_back(std::move(name));
                    } else if (section == 0 && value != 0) {
                        if (definitions.emplace(name).second) result.definitions.push_back(std::move(name));
                    } else if (section == 0 && undefined.emplace(name).second) {
                        result.undefined.push_back(std::move(name));
                    }
                }
            }
            i += 1 + aux_count;
        }
        result.undefined.erase(std::remove_if(result.undefined.begin(), result.undefined.end(),
            [&](const auto &name) { return definitions.contains(name); }), result.undefined.end());
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate XCOFF64 archive symbol summary"};
    }
}
} // namespace hexlab
