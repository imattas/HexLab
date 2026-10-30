#include "elf_internal.hpp"
#include <algorithm>
namespace hexlab::elf_detail {
namespace {
constexpr std::uint64_t symbol_limit = 1000000;
class VirtualReader {
    const Reader &reader_;
    const Image &image_;
    Budget &budget_;
    std::stop_token stop_;

  public:
    VirtualReader(const Reader &reader, const Image &image, Budget &budget, std::stop_token stop)
        : reader_(reader), image_(image), budget_(budget), stop_(stop) {}
    ByteView bytes(std::uint64_t at, std::uint64_t n) const {
        require(n <= SIZE_MAX, "Dynamic metadata exceeds host extent", ErrorCode::resource_limit);
        return read_virtual(reader_, image_, {{0}, at}, static_cast<std::size_t>(n), budget_, stop_);
    }
    std::uint64_t word(std::uint64_t at) const {
        const auto b = bytes(at, 4);
        return reader_.value(b.bytes, 0, 4);
    }
};
std::uint64_t sysv_count(const Reader &reader, const VirtualReader &input, std::uint64_t address, Budget &budget,
                         std::stop_token stop) {
    const auto header = input.bytes(address, 8);
    const auto buckets = reader.value(header.bytes, 0, 4), count = reader.value(header.bytes, 4, 4);
    require(buckets && buckets <= symbol_limit && count && count <= symbol_limit, "SysV ELF hash count exceeds bound",
            ErrorCode::resource_limit);
    const auto body = input.bytes(add(address, 8), 4 * (buckets + count));
    for (std::uint64_t i = 0; i < buckets + count; ++i) {
        canceled(stop);
        require(reader.value(body.bytes, static_cast<std::size_t>(i * 4), 4) < count,
                "SysV ELF hash index is outside symbol table");
    }
    budget.include(count);
    std::vector<std::uint8_t> colors(static_cast<std::size_t>(count));
    const auto next = [&](std::uint64_t at) {
        return reader.value(body.bytes, static_cast<std::size_t>((buckets + at) * 4), 4);
    };
    for (std::uint64_t start = 1; start < count; ++start) {
        canceled(stop);
        if (colors[static_cast<std::size_t>(start)])
            continue;
        auto cursor = start;
        while (cursor && colors[static_cast<std::size_t>(cursor)] == 0) {
            canceled(stop);
            colors[static_cast<std::size_t>(cursor)] = 1;
            cursor = next(cursor);
        }
        require(!cursor || colors[static_cast<std::size_t>(cursor)] != 1, "Cyclic SysV ELF hash chain");
        cursor = start;
        while (cursor && colors[static_cast<std::size_t>(cursor)] == 1) {
            colors[static_cast<std::size_t>(cursor)] = 2;
            cursor = next(cursor);
        }
    }
    return count;
}
std::uint64_t gnu_count(const Reader &reader, const VirtualReader &input, std::uint64_t address, bool wide,
                        std::stop_token stop) {
    const auto header = input.bytes(address, 16);
    const auto buckets = reader.value(header.bytes, 0, 4), offset = reader.value(header.bytes, 4, 4);
    const auto bloom = reader.value(header.bytes, 8, 4), shift = reader.value(header.bytes, 12, 4);
    require(buckets && buckets <= symbol_limit && offset && offset <= symbol_limit && bloom && bloom <= symbol_limit,
            "GNU ELF hash counts exceed bounds", ErrorCode::resource_limit);
    require(aligned(bloom) && shift < 32, "Invalid GNU ELF hash bloom parameters");
    const auto bloom_bytes = bloom * (wide ? 8 : 4);
    (void)input.bytes(add(address, 16), bloom_bytes);
    const auto bucket_at = add(add(address, 16), bloom_bytes);
    const auto bucket_data = input.bytes(bucket_at, buckets * 4);
    std::uint64_t maximum = 0;
    for (std::uint64_t i = 0; i < buckets; ++i) {
        canceled(stop);
        const auto start = reader.value(bucket_data.bytes, static_cast<std::size_t>(i * 4), 4);
        require(start == 0 || (start >= offset && start < symbol_limit), "GNU ELF hash bucket is outside symbol bound");
        maximum = std::max(maximum, start);
    }
    if (!maximum)
        return offset;
    const auto chain_at = add(bucket_at, buckets * 4);
    auto last = maximum;
    for (;; ++last) {
        canceled(stop);
        require(last < symbol_limit, "GNU ELF hash chain exceeds symbol bound", ErrorCode::resource_limit);
        if (input.word(add(chain_at, (last - offset) * 4)) & 1)
            break;
    }
    // Validate the whole counted chain region, not a guessed next-table pointer.
    const auto chains = input.bytes(chain_at, (last + 1 - offset) * 4);
    std::uint64_t terminator = last + 1;
    for (auto i = last + 1; i > offset;) {
        --i;
        canceled(stop);
        if (reader.value(chains.bytes, static_cast<std::size_t>((i - offset) * 4), 4) & 1)
            terminator = i;
        require(terminator <= last, "Unterminated GNU ELF hash chain");
    }
    return last + 1;
}

std::uint32_t gnu_hash(std::string_view name) {
    std::uint32_t hash = 5381;
    for (const auto character : name)
        hash = hash * 33u + static_cast<unsigned char>(character);
    return hash;
}

void validate_gnu_hash(const Reader &reader, const VirtualReader &input, std::uint64_t address, bool wide,
                       std::span<const ElfSymbol> symbols, Budget &budget, std::stop_token stop) {
    const auto header = input.bytes(address, 16);
    const auto buckets = reader.value(header.bytes, 0, 4);
    const auto first_symbol = reader.value(header.bytes, 4, 4);
    const auto bloom_words = reader.value(header.bytes, 8, 4);
    const auto shift = reader.value(header.bytes, 12, 4);
    require(symbols.size() <= symbol_limit && symbols.size() >= first_symbol,
            "GNU ELF hash symbol range exceeds the dynamic symbol table");
    const auto word_bits = wide ? 64u : 32u;
    const auto word_size = wide ? 8u : 4u;
    const auto bloom_bytes = bloom_words * word_size;
    const auto bloom = input.bytes(add(address, 16), bloom_bytes);
    const auto bucket_at = add(add(address, 16), bloom_bytes);
    const auto bucket_data = input.bytes(bucket_at, buckets * 4);
    const auto chain_at = add(bucket_at, buckets * 4);
    const auto chain_data = input.bytes(chain_at, (symbols.size() - first_symbol) * 4);
    budget.include(symbols.size());
    std::vector<bool> seen(symbols.size(), false);
    for (std::uint64_t bucket = 0; bucket < buckets; ++bucket) {
        canceled(stop);
        auto index = reader.value(bucket_data.bytes, static_cast<std::size_t>(bucket * 4), 4);
        if (index == 0)
            continue;
        require(index >= first_symbol && index < symbols.size(), "GNU ELF hash bucket is outside symbol table");
        for (;;) {
            canceled(stop);
            require(index < symbols.size(), "GNU ELF hash chain exceeds dynamic symbol table");
            const auto symbol_index = static_cast<std::size_t>(index);
            require(!seen[symbol_index], "GNU ELF hash bucket chains overlap");
            seen[symbol_index] = true;
            const auto hash = gnu_hash(symbols[static_cast<std::size_t>(index)].name);
            require(hash % buckets == bucket, "GNU ELF hash symbol is in the wrong bucket");
            const auto chain = reader.value(chain_data.bytes, static_cast<std::size_t>((index - first_symbol) * 4), 4);
            require((chain & ~std::uint64_t{1}) == (hash & ~std::uint32_t{1}),
                    "GNU ELF hash chain value disagrees with symbol name");
            const auto bloom_index = ((hash / word_bits) % bloom_words) * word_size;
            const auto bloom_word = reader.value(bloom.bytes, static_cast<std::size_t>(bloom_index), word_size);
            const auto first_bit = hash % word_bits;
            const auto second_bit = (hash >> shift) % word_bits;
            require((bloom_word & (UINT64_C(1) << first_bit)) &&
                        (bloom_word & (UINT64_C(1) << second_bit)),
                    "GNU ELF hash bloom filter omits a dynamic symbol");
            if (chain & 1)
                break;
            ++index;
        }
    }
    for (std::size_t index = static_cast<std::size_t>(first_symbol); index < symbols.size(); ++index) {
        canceled(stop);
        require(seen[index], "GNU ELF hash omits a symbol in its indexed range");
    }
}
} // namespace
void read_dynamic_symbols(const Reader &reader, const Image &image, ElfMetadata &metadata, ElfDynamicTable &dynamic,
                          const std::map<std::int64_t, std::uint64_t> &values, ByteView names, Budget &budget,
                          std::stop_token stop) {
    if (!values.contains(6)) {
        require(!values.contains(4) && !values.contains(0x6ffffef5) && !values.contains(39),
                "ELF symbol bounds require SYMTAB");
        return;
    }
    const auto wide = metadata.header.is_64;
    const auto minimum = wide ? 24u : 16u;
    require(metadata.header.object_type != 1, "Dynamic symbol pointers in relocatable ELF are unsupported",
            ErrorCode::unsupported);
    require(values.contains(11) && values.at(11) >= minimum, "ELF dynamic symbols require valid SYMENT");
    const auto stride = values.at(11), address = values.at(6);
    const auto first = image.to_file_offset({{0}, address});
    require(bool(first), "ELF dynamic symbol pointer is not initialized");
    ElfSymbolTable *candidate = nullptr;
    for (auto &table : metadata.symbol_tables)
        if (table.source.file_offset == first.value().value && table.source.section &&
            metadata.sections[*table.source.section].type == 11) {
            require(!candidate, "Ambiguous ELF dynamic symbol source");
            candidate = &table;
        }
    std::optional<std::uint64_t> count;
    auto origin = ElfSymbolCountSource::unavailable;
    const auto bind = [&](std::uint64_t n, ElfSymbolCountSource source) {
        require(n && n <= symbol_limit, "ELF dynamic symbol count exceeds bound", ErrorCode::resource_limit);
        if (count)
            require(*count == n, "ELF dynamic symbol bounds disagree");
        else {
            count = n;
            origin = source;
        }
    };
    VirtualReader input(reader, image, budget, stop);
    if (values.contains(39)) {
        require(values.at(39) % stride == 0, "ELF SYMTABSZ has fractional records");
        bind(values.at(39) / stride, ElfSymbolCountSource::explicit_size);
    }
    if (values.contains(4))
        bind(sysv_count(reader, input, values.at(4), budget, stop), ElfSymbolCountSource::sysv_hash);
    if (values.contains(0x6ffffef5))
        bind(gnu_count(reader, input, values.at(0x6ffffef5), wide, stop), ElfSymbolCountSource::gnu_hash);
    if (candidate && candidate->count)
        bind(*candidate->count, ElfSymbolCountSource::section);
    if (count) {
        require(stride <= metadata_limit / (*count), "ELF dynamic symbol table extent exceeds budget",
                ErrorCode::resource_limit);
        validate_virtual_initialized(image, {{0}, address}, *count * stride, stop);
    }
    const auto validate_alias = [&](const ElfSymbolTable &table) {
        if (!table.count)
            return;
        require(bool(table.symbol_begin), "Bounded ELF symbol alias lacks canonical rows");
        for (std::uint64_t i = 0; i < *table.count; ++i) {
            canceled(stop);
            const auto &symbol = metadata.symbols[static_cast<std::size_t>(*table.symbol_begin + i)];
            if (symbol.name_index) {
                require(symbol.name_index < names.bytes.size(), "ELF dynamic symbol name exceeds DT_STRSZ");
                const auto tail = names.bytes.subspan(symbol.name_index);
                const auto end = std::find(tail.begin(), tail.end(), std::byte{0});
                require(end != tail.end() &&
                            std::string_view(reinterpret_cast<const char *>(tail.data()),
                                             static_cast<std::size_t>(end - tail.begin())) == symbol.name,
                        "ELF dynamic symbol alias names conflict");
            }
            if (values.contains(34)) {
                const auto extended = input.word(add(values.at(34), i * 4));
                require(extended == (symbol.raw_section == 0xffff ? symbol.section_index : 0),
                        "ELF dynamic symbol alias extended indexes conflict");
            }
        }
    };
    if (candidate) {
        require(candidate->stride == stride && candidate->count && candidate->symbol_begin,
                "ELF dynamic section symbol layout conflicts");
        validate_virtual_file(image, {{0}, address}, *candidate->count * stride, {candidate->source.file_offset}, stop);
        const auto &section = metadata.sections[*candidate->source.section];
        const auto &strings = metadata.sections[section.link];
        const auto string_bounds_error = "ELF dynamic symbol string bounds conflict with section (dynamic " +
                                         std::to_string(values.at(10)) + ", section " + std::to_string(strings.size) + ")";
        require(values.at(10) <= strings.size, string_bounds_error.c_str());
        validate_virtual_file(image, {{0}, values.at(5)}, values.at(10), {strings.offset}, stop);
        validate_alias(*candidate);
        if (values.contains(0x6ffffef5))
            validate_gnu_hash(reader, input, values.at(0x6ffffef5), wide,
                              std::span<const ElfSymbol>(metadata.symbols).subspan(
                                  static_cast<std::size_t>(*candidate->symbol_begin),
                                  static_cast<std::size_t>(*candidate->count)), budget, stop);
        candidate->count_source = origin;
        dynamic.symbol_table = candidate->source;
        return;
    }
    const ElfTableSource source{{}, first.value().value, Address{{0}, address}};
    for (const auto &table : metadata.symbol_tables)
        if (table.source == source) {
            require(table.stride == stride && table.count == count, "ELF dynamic symbol aliases conflict");
            validate_alias(table);
            if (values.contains(0x6ffffef5))
                validate_gnu_hash(reader, input, values.at(0x6ffffef5), wide,
                                  std::span<const ElfSymbol>(metadata.symbols).subspan(
                                      static_cast<std::size_t>(*table.symbol_begin),
                                      static_cast<std::size_t>(*table.count)), budget, stop);
            dynamic.symbol_table = source;
            return;
        }
    budget.include(sizeof(ElfSymbolTable));
    if (!count) {
        metadata.symbol_tables.push_back({source, stride, {}, {}, ElfSymbolCountSource::unavailable});
        dynamic.symbol_table = source;
        metadata.dynamic_complete = false;
        return;
    }
    require(*count <= symbol_limit - metadata.symbols.size(), "ELF aggregate dynamic symbol count exceeds bound",
            ErrorCode::resource_limit);
    budget.include(*count * sizeof(ElfSymbol));
    const auto begin = metadata.symbols.size();
    bool global = false;
    for (std::uint32_t index = 0; index < *count; ++index) {
        const auto bytes = input.bytes(add(address, stride * index), minimum);
        auto symbol = decode_symbol(reader, bytes.bytes, wide, source, index, names, budget);
        require(symbol.binding != 0 || !global, "Dynamic ELF locals follow nonlocal symbols");
        global = global || symbol.binding != 0;
        std::uint64_t extended = 0;
        if (values.contains(34))
            extended = input.word(add(values.at(34), std::uint64_t{index} * 4));
        if (symbol.raw_section == 0xffff) {
            require(values.contains(34), "Dynamic ELF XINDEX requires SYMTAB_SHNDX");
            symbol.section_index = static_cast<std::uint32_t>(extended);
        } else
            require(extended == 0, "Unused dynamic ELF extended index must be zero");
        resolve_symbol(symbol, image, metadata);
        metadata.symbols.push_back(std::move(symbol));
    }
    if (values.contains(0x6ffffef5))
        validate_gnu_hash(reader, input, values.at(0x6ffffef5), wide,
                          std::span<const ElfSymbol>(metadata.symbols).subspan(begin, static_cast<std::size_t>(*count)),
                          budget, stop);
    metadata.symbol_tables.push_back({source, stride, count, begin, origin});
    dynamic.symbol_table = source;
}
} // namespace hexlab::elf_detail
