#include "hexlab/loaders/ar.hpp"
#include "hexlab/loaders/elf.hpp"
#include <algorithm>
#include <limits>
#include <unordered_set>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool ok, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ELF archive member scan canceled", ErrorCode::canceled);
}
std::uint64_t value(std::span<const std::byte> bytes, std::size_t at, std::size_t width, ByteOrder order) {
    require(at <= bytes.size() && width <= bytes.size() - at, "Truncated ELF archive record");
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < width; ++i) {
        const auto shift = order == ByteOrder::little ? i : width - i - 1;
        result |= std::to_integer<std::uint64_t>(bytes[at + i]) << (shift * 8);
    }
    return result;
}
std::vector<std::byte> read(const ByteStorage &storage, std::uint64_t offset, std::uint64_t size,
                            std::uint64_t &budget, const ArObjectLimits &limits, std::stop_token stop) {
    canceled(stop);
    require(size <= limits.max_metadata_bytes - budget, "ELF archive metadata limit exceeded", ErrorCode::resource_limit);
    require(offset <= storage.size() && size <= storage.size() - offset, "ELF archive record exceeds member extent");
    require(size <= std::numeric_limits<std::size_t>::max(), "ELF archive record exceeds host address space", ErrorCode::resource_limit);
    budget += size;
    auto view = storage.read_at({offset}, static_cast<std::size_t>(size));
    if (!view) throw Failure{view.error()};
    require(view.value().bytes.size() == size, "Incomplete ELF archive member view", ErrorCode::io);
    canceled(stop);
    return {view.value().bytes.begin(), view.value().bytes.end()};
}
}

Result<ArMemberSymbols> summarize_elf_ar_member(const ByteStorage &storage, std::size_t member_index,
                                                std::stop_token stop, ArObjectLimits limits) {
    try {
        require(limits.max_metadata_bytes > 0 && limits.max_sections > 0 && limits.max_symbols > 0 &&
                    limits.max_name_bytes > 0,
                "ELF archive object limits must be positive", ErrorCode::invalid_argument);
        canceled(stop);
        auto header_result = read_elf_header(storage, stop);
        if (!header_result) throw Failure{header_result.error()};
        const auto &header = header_result.value();
        require(header.object_type == 1, "Archive ELF member is not ET_REL", ErrorCode::unsupported);
        require(header.sections.count <= limits.max_sections, "ELF archive section count limit exceeded", ErrorCode::resource_limit);
        const bool wide = header.is_64;
        const auto minimum_section = wide ? 64u : 40u;
        const auto minimum_symbol = wide ? 24u : 16u;
        std::uint64_t budget = 0;
        std::vector<std::byte> bytes;
        struct Section { std::uint32_t type = 0, link = 0, info = 0; std::uint64_t offset = 0, size = 0, stride = 0; };
        std::vector<Section> sections;
        sections.reserve(static_cast<std::size_t>(header.sections.count));
        for (std::uint64_t i = 0; i < header.sections.count; ++i) {
            canceled(stop);
            const auto at = header.sections.offset + header.sections.stride * i;
            bytes = read(storage, at, minimum_section, budget, limits, stop);
            const auto get = [&](std::size_t pos, std::size_t n) { return value(bytes, pos, n, header.order); };
            Section section;
            section.type = static_cast<std::uint32_t>(get(4, 4));
            section.offset = get(wide ? 24 : 16, wide ? 8 : 4);
            section.size = get(wide ? 32 : 20, wide ? 8 : 4);
            section.link = static_cast<std::uint32_t>(get(wide ? 40 : 24, 4));
            section.info = static_cast<std::uint32_t>(get(wide ? 44 : 28, 4));
            section.stride = get(wide ? 56 : 36, wide ? 8 : 4);
            if (section.type != 8 && section.size)
                require(section.offset <= storage.size() && section.size <= storage.size() - section.offset,
                        "ELF archive section exceeds member extent");
            sections.push_back(section);
        }
        require(!sections.empty() && sections[0].type == 0, "ELF archive section zero is invalid");
        ArMemberSymbols result;
        result.member_index = member_index;
        std::unordered_set<std::string> defined, undefined;
        std::size_t total_symbols = 0;
        for (std::size_t section_index = 0; section_index < sections.size(); ++section_index) {
            canceled(stop);
            const auto &table = sections[section_index];
            if (table.type != 2 && table.type != 11) continue; // SYMTAB / DYNSYM
            require(table.stride >= minimum_symbol && table.size % table.stride == 0,
                    "Invalid ELF archive symbol table stride/size");
            require(table.link < sections.size() && sections[table.link].type == 3,
                    "ELF archive symbol table link must name STRTAB");
            const auto &strings_section = sections[table.link];
            require(strings_section.size <= limits.max_metadata_bytes - budget,
                    "ELF archive string table limit exceeded", ErrorCode::resource_limit);
            const auto strings = read(storage, strings_section.offset, strings_section.size, budget, limits, stop);
            if (!strings.empty())
                require(strings.front() == std::byte{0} && strings.back() == std::byte{0},
                        "ELF archive string table needs boundary terminators");
            const auto count = table.size / table.stride;
            require(count <= limits.max_symbols - total_symbols,
                    "ELF archive symbol count limit exceeded", ErrorCode::resource_limit);
            require(count > 0 && table.info >= 1 && table.info <= count,
                    "ELF archive symbol local partition is outside table");
            total_symbols += static_cast<std::size_t>(count);
            for (std::uint64_t symbol_index = 0; symbol_index < count; ++symbol_index) {
                canceled(stop);
                bytes = read(storage, table.offset + table.stride * symbol_index, minimum_symbol, budget, limits, stop);
                const auto name_index = static_cast<std::uint32_t>(value(bytes, 0, 4, header.order));
                const auto info = value(bytes, wide ? 4 : 12, 1, header.order);
                const auto other = value(bytes, wide ? 5 : 13, 1, header.order);
                const auto section = value(bytes, wide ? 6 : 14, 2, header.order);
                const auto binding = static_cast<std::uint8_t>(info >> 4);
                if (symbol_index == 0)
                    require(name_index == 0 && info == 0 && other == 0 && section == 0 &&
                                value(bytes, wide ? 8 : 4, wide ? 8 : 4, header.order) == 0 &&
                                value(bytes, wide ? 16 : 8, wide ? 8 : 4, header.order) == 0,
                            "ELF archive first symbol must be the zero undefined entry");
                require(symbol_index < table.info ? binding == 0 : binding != 0,
                        "ELF archive symbol binding disagrees with local partition");
                if (binding != 1 && binding != 2 && binding != 10) continue; // GLOBAL, WEAK, GNU_UNIQUE
                if (name_index == 0) continue;
                require(name_index < strings.size(), "ELF archive symbol name is outside STRTAB");
                auto end = static_cast<std::size_t>(name_index);
                while (end < strings.size() && strings[end] != std::byte{0}) ++end;
                require(end < strings.size(), "Unterminated ELF archive symbol name");
                const auto length = end - name_index;
                require(length <= limits.max_name_bytes, "ELF archive symbol name exceeds limit", ErrorCode::resource_limit);
                if (!length) continue;
                std::string name(reinterpret_cast<const char *>(strings.data() + name_index), length);
                if (section == 0) {
                    if (binding != 2 && undefined.emplace(name).second) result.undefined.push_back(std::move(name));
                } else if (defined.emplace(name).second) {
                    result.definitions.push_back(std::move(name));
                }
            }
        }
        // A definition in any table resolves a same-object reference.
        result.undefined.erase(std::remove_if(result.undefined.begin(), result.undefined.end(),
                                              [&](const auto &name) { return defined.contains(name); }),
                               result.undefined.end());
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate ELF archive symbol summary"}; }
}
} // namespace hexlab
