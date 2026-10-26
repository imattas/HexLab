#pragma once
#include "hexlab/loaders/elf.hpp"
#include <limits>
#include <map>
#include <tuple>
namespace hexlab::elf_detail {
inline constexpr std::uint64_t metadata_limit = 64 * 1024 * 1024;
struct Failure {
    Error error;
};
inline void require(bool condition, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!condition)
        throw Failure{{code, message}};
}
template <class T> T take(Result<T> value) {
    if (!value)
        throw Failure{value.error()};
    return std::move(value.value());
}
inline void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ELF loading canceled", ErrorCode::canceled);
}
inline std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    require(b <= UINT64_MAX - a, "ELF extent overflow", ErrorCode::overflow);
    return a + b;
}
inline bool aligned(std::uint64_t alignment) { return alignment == 0 || (alignment & (alignment - 1)) == 0; }
struct Budget {
    std::uint64_t used = 0;
    std::uint64_t limit = metadata_limit;
    void include(std::uint64_t size) {
        require(used <= limit && size <= limit - used, "ELF metadata allocation budget exceeded", ErrorCode::resource_limit);
        used += size;
    }
};
class Reader {
    const ByteStorage &source_;
    ByteOrder order_;
    std::stop_token stop_;

  public:
    Reader(const ByteStorage &source, ByteOrder order, std::stop_token stop)
        : source_(source), order_(order), stop_(stop) {}
    void extent(std::uint64_t offset, std::uint64_t size) const {
        require(offset <= source_.size() && size <= source_.size() - offset, "ELF initialized range exceeds input");
    }
    ByteView bytes(std::uint64_t offset, std::size_t size) const {
        canceled(stop_);
        extent(offset, size);
        auto result = take(source_.read_at({offset}, size));
        require(result.bytes.size() == size, "Incomplete ELF storage view");
        canceled(stop_);
        return result;
    }
    std::uint64_t value(std::span<const std::byte> data, std::size_t at, std::size_t n) const {
        require(at <= data.size() && n <= data.size() - at, "Truncated ELF record field");
        std::uint64_t result = 0;
        for (std::size_t i = 0; i < n; ++i)
            result |= std::to_integer<std::uint64_t>(data[at + i])
                      << (8 * (order_ == ByteOrder::little ? i : n - 1 - i));
        return result;
    }
};
void read_tables(const ByteStorage &, ElfMetadata &, Budget &, std::stop_token);
std::vector<std::uint8_t> read_debug_section_bytes(const ByteStorage &, const ElfMetadata &,
    const ElfSection &, Budget &, std::stop_token);
void read_core_notes(ElfMetadata &, Budget &, std::stop_token);
Result<bool> read_source_lines(const ByteStorage &, ElfMetadata &, Budget &, std::stop_token);
Result<bool> read_dwarf_info(const ByteStorage &, ElfMetadata &, Budget &, std::stop_token,
                             const symbols::DwarfSplitUnitResolver & = {},
                             const symbols::DwarfSupplementaryTypeResolver & = {},
                             std::uint64_t supplementary_max_bytes = 64u * 1024u * 1024u,
                             std::uint32_t supplementary_max_requests = 100000,
                             std::shared_ptr<const ByteStorage> supplementary_package = {},
                             std::shared_ptr<const ByteStorage> split_debug_package = {});
Result<bool> read_unwind_ranges(const ByteStorage &, const Image &, ElfMetadata &, Budget &, std::stop_token);
void parse_debug_frame_section(const ByteStorage &, const Image &, const ElfMetadata &, const ElfSection &,
                              Budget &, std::stop_token, std::vector<ElfUnwindRange> &,
                              std::vector<ElfEhFrameFunction> &);
Result<bool> read_rtti(const ByteStorage &, const Image &, ElfMetadata &, Budget &, std::stop_token);
void read_symbols(const ByteStorage &, const Image &, ElfMetadata &, Budget &, std::stop_token);
void read_symbol_versions(const ByteStorage &, const Image &, ElfMetadata &, Budget &, std::stop_token);
ElfSymbol decode_symbol(const Reader &, std::span<const std::byte>, bool, ElfTableSource, std::uint32_t, ByteView,
                        Budget &);
void resolve_symbol(ElfSymbol &, const Image &, const ElfMetadata &);
void read_dynamic_symbols(const Reader &, const Image &, ElfMetadata &, ElfDynamicTable &,
                          const std::map<std::int64_t, std::uint64_t> &, ByteView, Budget &, std::stop_token);
using ElfSourceKey = std::tuple<bool, std::optional<std::uint32_t>, std::uint64_t, bool, std::uint32_t, std::uint64_t>;
inline ElfSourceKey source_key(const std::optional<ElfTableSource> &source) {
    if (!source)
        return {false, {}, 0, false, 0, 0};
    return {true,
            source->section,
            source->file_offset,
            bool(source->address),
            source->address ? source->address->space.value : 0,
            source->address ? source->address->offset : 0};
}
struct RelocationRegistry {
    using RowKey = std::tuple<std::uint64_t, std::uint64_t, ElfSourceKey, std::optional<std::uint32_t>>;
    using TableKey =
        std::tuple<ElfSourceKey, std::uint64_t, std::uint64_t, bool, ElfSourceKey, std::optional<std::uint32_t>>;
    std::map<RowKey, std::uint64_t> rows;
    std::map<TableKey, std::uint64_t> tables;
    std::uint64_t processed = 0;
};
struct RelocationInput {
    ElfTableSource source;
    std::uint64_t size = 0, stride = 0;
    bool rela = false;
    std::optional<std::uint32_t> target;
    const ElfSymbolTable *symbols = nullptr;
};
void read_relocations(const ByteStorage &, const Image &, ElfMetadata &, Budget &, RelocationRegistry &,
                      std::stop_token);
std::uint64_t read_relocation_table(const Reader &, const Image &, ElfMetadata &, const RelocationInput &, Budget &,
                                    RelocationRegistry &, std::stop_token);
std::uint64_t read_relr_table(const Reader &, const Image &, ElfMetadata &, const ElfTableSource &,
                              std::uint64_t size, std::uint64_t stride,
                              std::optional<std::uint32_t> target, Budget &, RelocationRegistry &,
                              std::stop_token);
std::uint64_t read_android_packed_relocation_table(const Reader &, const Image &, ElfMetadata &,
                                                   const ElfTableSource &, std::uint64_t size, bool rela,
                                                   const ElfSymbolTable *, Budget &, RelocationRegistry &,
                                                   std::stop_token);
ByteView read_virtual(const Reader &, const Image &, Address, std::size_t, Budget &, std::stop_token);
void validate_virtual_initialized(const Image &, Address, std::uint64_t, std::stop_token);
void validate_virtual_file(const Image &, Address, std::uint64_t, FileOffset, std::stop_token);
void read_dynamic(const ByteStorage &, const Image &, ElfMetadata &, Budget &, RelocationRegistry &, std::stop_token);
void read_dynamic_relocations(const Reader &, const Image &, ElfMetadata &, ElfDynamicTable &,
                              const std::map<std::int64_t, std::uint64_t> &, Budget &, RelocationRegistry &,
                              std::stop_token);
void normalize_loads(const ElfMetadata &, ImageLayout &, Budget &, std::stop_token);
} // namespace hexlab::elf_detail
