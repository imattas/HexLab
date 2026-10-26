#include "elf_internal.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <string_view>

namespace hexlab::elf_detail {
namespace {
struct MappingPoint {
    Address at;
    ArmCodeKind kind = ArmCodeKind::unknown;
    ArmContextSource source;
};
std::optional<std::pair<ArmCodeKind, ArmContextSource>>
arm_mapping_symbol(const ElfSymbol &symbol, const ElfMetadata &metadata, Budget &budget) {
    if (metadata.header.machine != 40 || metadata.header.is_64 || symbol.type != 0 ||
        symbol.state != ElfSymbolState::defined || !symbol.address ||
        symbol.section_index >= metadata.sections.size() || !(metadata.sections[symbol.section_index].flags & 4))
        return {};
    ArmCodeKind kind;
    if (symbol.name == "$a" || symbol.name.starts_with("$a."))
        kind = ArmCodeKind::a32;
    else if (symbol.name == "$t" || symbol.name.starts_with("$t."))
        kind = ArmCodeKind::thumb;
    else if (symbol.name == "$d" || symbol.name.starts_with("$d."))
        kind = ArmCodeKind::data;
    else
        return {};

    const auto table = std::find_if(metadata.symbol_tables.begin(), metadata.symbol_tables.end(), [&](const auto &row) {
        return row.source.section == symbol.table && row.source.file_offset == symbol.table_offset;
    });
    require(table != metadata.symbol_tables.end() && table->stride && symbol.index < table->count.value_or(0),
            "ELF ARM mapping symbol lacks an identified source record");
    require(symbol.index <= (UINT64_MAX - symbol.table_offset) / table->stride,
            "ELF ARM mapping-symbol source offset overflows", ErrorCode::overflow);
    const auto record_offset = add(symbol.table_offset, symbol.index * table->stride);
    budget.include(sizeof(MappingPoint));
    return std::pair{kind, ArmContextSource{ArmContextSourceKind::elf_mapping_symbol,
                                            symbol.table ? *symbol.table : symbol.table_offset, symbol.index,
                                            ArmSourceEvidence{{record_offset}, table->stride}}};
}
std::optional<ArmContextSource> arm_function_source(const ElfSymbol &symbol, const ElfMetadata &metadata) {
    if (metadata.header.machine != 40 || metadata.header.is_64 || symbol.type != 2 ||
        symbol.state != ElfSymbolState::defined || !symbol.address)
        return {};
    const auto table = std::find_if(metadata.symbol_tables.begin(), metadata.symbol_tables.end(), [&](const auto &row) {
        return row.source.section == symbol.table && row.source.file_offset == symbol.table_offset;
    });
    require(table != metadata.symbol_tables.end() && table->stride && symbol.index < table->count.value_or(0),
            "ELF ARM function symbol lacks an identified source record");
    require(symbol.index <= (UINT64_MAX - symbol.table_offset) / table->stride,
            "ELF ARM function-symbol source offset overflows", ErrorCode::overflow);
    const auto record_offset = add(symbol.table_offset, symbol.index * table->stride);
    return ArmContextSource{ArmContextSourceKind::elf_function_symbol,
                            symbol.table ? *symbol.table : symbol.table_offset, symbol.index,
                            ArmSourceEvidence{{record_offset}, table->stride}};
}
void populate_arm_context(const ElfMetadata &metadata, ImageLayout &layout, Budget &budget, std::stop_token stop) {
    if (metadata.header.machine != 40 || metadata.header.is_64 || metadata.header.order != ByteOrder::little ||
        layout.space.width_bits != 32)
        return;
    std::map<std::uint32_t, std::vector<MappingPoint>> by_section;
    for (const auto &symbol : metadata.symbols) {
        canceled(stop);
        auto mapping = arm_mapping_symbol(symbol, metadata, budget);
        if (mapping)
            by_section[symbol.section_index].push_back({*symbol.address, mapping->first, std::move(mapping->second)});
    }

    ArmImageProfile profile;
    for (auto &[section_index, points] : by_section) {
        canceled(stop);
        const auto &section = metadata.sections[section_index];
        std::sort(points.begin(), points.end(), [](const auto &a, const auto &b) {
            return std::tie(a.at.space.value, a.at.offset, a.kind) < std::tie(b.at.space.value, b.at.offset, b.kind);
        });
        const auto section_begin =
            metadata.header.object_type == 1 ? Address{{section_index}, 0} : Address{{0}, section.address};
        const auto section_end = add(section_begin.offset, section.size);
        for (std::size_t first = 0; first < points.size();) {
            canceled(stop);
            auto last = first + 1;
            while (last < points.size() && points[last].at == points[first].at)
                ++last;
            const auto begin = points[first].at;
            const std::uint64_t end = last < points.size() ? points[last].at.offset : section_end;
            require(begin.space == section_begin.space && begin.offset >= section_begin.offset &&
                        begin.offset < section_end && end > begin.offset && end <= section_end,
                    "ELF ARM mapping-symbol interval exceeds its executable section");
            std::vector<ArmContextSource> sources;
            sources.reserve(last - first);
            auto kind = points[first].kind;
            bool conflict = false;
            for (auto index = first; index < last; ++index) {
                conflict |= points[index].kind != kind;
                sources.push_back(points[index].source);
            }
            if (conflict)
                kind = ArmCodeKind::conflict;
            budget.include(sizeof(ArmCodeRange) + sources.size() * sizeof(ArmContextSource));
            profile.ranges.push_back({begin, end - begin.offset, kind, std::move(sources)});
            first = last;
        }
    }
    std::sort(profile.ranges.begin(), profile.ranges.end(), [](const auto &a, const auto &b) {
        return std::tie(a.begin.space.value, a.begin.offset) < std::tie(b.begin.space.value, b.begin.offset);
    });

    const auto range_at = [&](Address at) -> const ArmCodeRange * {
        const auto found =
            std::upper_bound(profile.ranges.begin(), profile.ranges.end(), at, [](Address value, const auto &range) {
                return std::tie(value.space.value, value.offset) <
                       std::tie(range.begin.space.value, range.begin.offset);
            });
        if (found == profile.ranges.begin())
            return nullptr;
        const auto &range = *std::prev(found);
        return range.begin.space == at.space && at.offset - range.begin.offset < range.size ? &range : nullptr;
    };
    for (const auto &symbol : metadata.symbols) {
        canceled(stop);
        auto source = arm_function_source(symbol, metadata);
        if (!source)
            continue;
        const auto *range = range_at(*symbol.address);
        if (!range || (range->kind != ArmCodeKind::a32 && range->kind != ArmCodeKind::thumb))
            continue;
        const auto mode = (symbol.value & 1u) ? ExecutionMode::thumb : ExecutionMode::a32;
        if ((range->kind == ArmCodeKind::a32 && mode == ExecutionMode::thumb) ||
            (range->kind == ArmCodeKind::thumb && mode == ExecutionMode::a32)) {
            auto mutable_range = std::find_if(profile.ranges.begin(), profile.ranges.end(),
                                              [&](const auto &row) { return &row == range; });
            mutable_range->kind = ArmCodeKind::conflict;
            mutable_range->sources.push_back(*source);
            continue;
        }
        auto existing = std::find_if(profile.roots.begin(), profile.roots.end(),
                                     [&](const auto &root) { return root.at == *symbol.address; });
        if (existing != profile.roots.end()) {
            require(existing->mode == mode, "Conflicting ARM function states share one ELF address",
                    ErrorCode::conflict);
            existing->sources.push_back(*source);
            continue;
        }
        budget.include(sizeof(ArmCodeRoot) + sizeof(ArmContextSource));
        profile.roots.push_back({*symbol.address, mode, mode == ExecutionMode::thumb, {*source}});
    }
    if (metadata.header.object_type != 1 && metadata.header.entry) {
        const Address entry{{0}, metadata.header.entry & ~UINT64_C(1)};
        const auto *range = range_at(entry);
        if (range && (range->kind == ArmCodeKind::a32 || range->kind == ArmCodeKind::thumb)) {
            const auto mode = (metadata.header.entry & 1u) ? ExecutionMode::thumb : ExecutionMode::a32;
            const ArmContextSource source{ArmContextSourceKind::platform_entry, 0, 0, ArmSourceEvidence{{24}, 4}};
            if ((range->kind == ArmCodeKind::a32 && mode == ExecutionMode::thumb) ||
                (range->kind == ArmCodeKind::thumb && mode == ExecutionMode::a32)) {
                auto mutable_range = std::find_if(profile.ranges.begin(), profile.ranges.end(),
                                                  [&](const auto &row) { return &row == range; });
                mutable_range->kind = ArmCodeKind::conflict;
                mutable_range->sources.push_back(source);
            } else {
                auto existing = std::find_if(profile.roots.begin(), profile.roots.end(),
                                             [&](const auto &root) { return root.at == entry; });
                if (existing != profile.roots.end()) {
                    require(existing->mode == mode, "ELF ARM entry conflicts with a function root",
                            ErrorCode::conflict);
                    existing->sources.push_back(source);
                } else {
                    budget.include(sizeof(ArmCodeRoot) + sizeof(ArmContextSource));
                    profile.roots.push_back({entry, mode, mode == ExecutionMode::thumb, {source}});
                }
            }
        }
    }
    if (!profile.ranges.empty() || !profile.roots.empty())
        layout.arm_profile = std::move(profile);
}
} // namespace
namespace {
constexpr std::uint32_t pf_execute = 0x1;
constexpr std::uint32_t pf_write = 0x2;
constexpr std::uint32_t pf_read = 0x4;
constexpr std::size_t execute_slot = 0;
constexpr std::size_t write_slot = 1;
constexpr std::size_t read_slot = 2;
constexpr std::array<std::uint32_t, 3> permission_bits{pf_execute, pf_write, pf_read};
} // namespace
void normalize_loads(const ElfMetadata &metadata, ImageLayout &layout, Budget &budget, std::stop_token stop) {
    struct Piece {
        std::uint64_t begin, end, file;
        bool initialized;
        std::uint32_t flags;
    };
    struct Event {
        std::uint64_t at;
        std::size_t piece;
        bool start;
    };
    std::vector<Piece> pieces;
    std::vector<Event> events;
    const auto insert = [&](Piece piece) {
        if (piece.begin == piece.end)
            return;
        budget.include(sizeof(Piece) + 2 * sizeof(Event));
        const auto index = pieces.size();
        pieces.push_back(piece);
        events.push_back({piece.begin, index, true});
        events.push_back({piece.end, index, false});
    };
    for (const auto &p : metadata.programs) {
        canceled(stop);
        if (p.type != 1 || !p.memory_size)
            continue;
        insert({p.address, p.address + p.file_size, p.offset, true, p.flags});
        insert({p.address + p.file_size, p.address + p.memory_size, 0, false, p.flags});
    }
    std::sort(events.begin(), events.end(), [](const auto &a, const auto &b) { return a.at < b.at; });
    std::set<std::size_t> active;
    std::map<std::uint64_t, std::size_t> provenance;
    std::array<std::size_t, 3> permissions{};
    std::size_t zeros = 0, index = 0;
    std::uint64_t previous = events.empty() ? 0 : events.front().at;
    while (index < events.size()) {
        canceled(stop);
        const auto at = events[index].at;
        if (at > previous && !active.empty()) {
            require(zeros == active.size() || (zeros == 0 && provenance.size() == 1),
                    "Conflicting ELF load overlap provenance", ErrorCode::unsupported);
            const auto &sample = pieces[*active.begin()];
            const auto size = at - previous;
            budget.include(sizeof(Segment) + 32);
            layout.segments.push_back({"LOAD" + std::to_string(layout.segments.size()),
                                       {{0}, previous},
                                       size,
                                       {sample.initialized ? sample.file + (previous - sample.begin) : 0},
                                       sample.initialized ? size : 0,
                                       permissions[read_slot] != 0,
                                       permissions[write_slot] != 0,
                                       permissions[execute_slot] != 0});
        }
        while (index < events.size() && events[index].at == at) {
            const auto &event = events[index++];
            const auto &piece = pieces[event.piece];
            if (event.start)
                active.insert(event.piece);
            else
                active.erase(event.piece);
            if (piece.initialized) {
                // Difference modulo2^64 is a stable provenance key. Actual file
                // offsets are computed from a checked active interval above.
                const auto key = piece.file - piece.begin;
                if (event.start)
                    ++provenance[key];
                else {
                    auto found = provenance.find(key);
                    if (--found->second == 0)
                        provenance.erase(found);
                }
            } else if (event.start)
                ++zeros;
            else
                --zeros;
            for (std::size_t bit = 0; bit < permission_bits.size(); ++bit)
                if (piece.flags & permission_bits[bit]) {
                    if (event.start)
                        ++permissions[bit];
                    else
                        --permissions[bit];
                }
        }
        previous = at;
    }
}
} // namespace hexlab::elf_detail
namespace hexlab {
Result<LoadedImage> load_elf(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    return load_elf(std::move(storage), ElfLoadOptions{}, stop);
}
Result<LoadedImage> load_elf(std::shared_ptr<const ByteStorage> storage, const ElfLoadOptions &options,
                             std::stop_token stop) {
    using namespace elf_detail;
    try {
        canceled(stop);
        require(bool(storage), "ELF loading requires storage", ErrorCode::invalid_argument);
        auto tracking = take(TrackingStorage::create(storage));
        ElfMetadata elf;
        elf.header = take(read_elf_header(*tracking, stop));
        Budget budget;
        read_tables(*tracking, elf, budget, stop);
        read_core_notes(elf, budget, stop);
        const auto &header = elf.header;
        Architecture architecture = Architecture::unknown;
        ExecutionMode mode = ExecutionMode::unknown;
        if (header.machine == 3) {
            architecture = Architecture::x86;
            if (!header.is_64 && header.order == ByteOrder::little)
                mode = ExecutionMode::x86_32;
        } else if (header.machine == 62) {
            architecture = Architecture::x86_64;
            if (header.is_64 && header.order == ByteOrder::little)
                mode = ExecutionMode::x86_64;
        } else if (header.machine == 40)
            architecture = Architecture::arm;
        else if (header.machine == 183) {
            architecture = Architecture::arm64;
            if (header.is_64 && header.order == ByteOrder::little)
                mode = ExecutionMode::a64;
        } else if (header.machine == 243) {
            architecture = header.is_64 ? Architecture::riscv64 : Architecture::riscv32;
            if (header.order == ByteOrder::little) {
                if (header.is_64)
                    mode = (header.flags & 1u) ? ExecutionMode::rv64c : ExecutionMode::rv64;
                else if (!(header.flags & 1u))
                    mode = ExecutionMode::rv32;
            }
        } else if (header.machine == 8) {
            // EF_MIPS_ABI2 identifies the N32 ABI: ELFCLASS32 data model on
            // the MIPS III+ 64-bit instruction set. Require ELF32 metadata;
            // never infer N32 from machine or byte order alone.
            constexpr std::uint32_t ef_mips_abi2 = 0x20;
            const bool n32 = !header.is_64 && (header.flags & ef_mips_abi2) != 0;
            architecture = (header.is_64 || n32) ? Architecture::mips64 : Architecture::mips32;
            mode = (header.is_64 || n32) ? ExecutionMode::mips64 : ExecutionMode::mips32;
        } else if (header.machine == 20) {
            architecture = Architecture::powerpc;
            if (!header.is_64) mode = ExecutionMode::ppc32;
        } else if (header.machine == 21) {
            architecture = Architecture::powerpc;
            if (header.is_64) mode = ExecutionMode::ppc64;
        }
        ImageLayout layout{
            {{0}, static_cast<std::uint8_t>(header.is_64 ? 64 : 32), 1, header.order}, architecture, mode, {}, {}};
        LoadedImage loaded;
        loaded.metadata_complete = true;
        const auto partial = [&](std::string message) {
            budget.include(sizeof(Diagnostic) + message.size());
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back({DiagnosticSeverity::warning, std::move(message), {}});
        };
        if (elf.core) {
            for (const auto &message : elf.core->diagnostics)
                partial(message);
            for (const auto &thread : elf.core->threads)
                if (thread.status != ElfCoreThreadStatus::decoded && !thread.diagnostic.empty())
                    partial("ELF core thread " + std::to_string(thread.process_id) + ": " + thread.diagnostic);
            if (!elf.core->load_segment_count)
                partial("ELF core has no nonempty PT_LOAD memory segments");
            if (elf.core->threads.empty())
                partial("ELF core contains no Linux NT_PRSTATUS thread records");
        }
        if (mode == ExecutionMode::unknown)
            partial("ELF machine/class/byte-order combination has no supported instruction decoder");
        for (const auto &s : elf.sections) {
            canceled(stop);
            if (s.flags & 0x800) {
                partial("Compressed ELF section is not interpreted: " + s.name);
                require(header.object_type == 1 || !(s.flags & 2),
                        "Compressed allocated section in executable ELF is unsupported", ErrorCode::unsupported);
                continue;
            }
            if (header.object_type == 1 && s.index && s.type != 0 && (s.flags & 2)) {
                budget.include(sizeof(Segment) + sizeof(ImageDomain) + s.name.size());
                layout.domains.push_back(
                    {{{s.index}, layout.space.width_bits, 1, header.order}, {architecture, mode, header.order}});
                layout.segments.push_back({s.name.empty() ? "section" + std::to_string(s.index) : s.name,
                                           {{s.index}, 0},
                                           s.size,
                                           {s.type == 8 ? 0 : s.offset},
                                           s.type == 8 ? 0 : s.size,
                                           true,
                                           bool(s.flags & 1),
                                           bool(s.flags & 4)});
            }
        }
        if (header.object_type != 1)
            normalize_loads(elf, layout, budget, stop);
        auto image = take(Image::create(storage, layout));
        if (header.object_type != 1 && header.object_type != 4 && header.entry) {
            const Address entry{
                {0}, architecture == Architecture::arm && !header.is_64 ? header.entry & ~UINT64_C(1) : header.entry};
            const auto *segment = image->segment_at(entry);
            if (segment && segment->executable && image->to_file_offset(entry)) {
                layout.entries.push_back(entry);
                image = take(Image::create(storage, std::move(layout)));
            } else
                partial("ELF entry is not initialized executable memory");
        }
        loaded.image = std::move(image);
        loaded.metadata.format = header.object_type == 4 ? (header.is_64 ? "ELF64 core" : "ELF32 core")
                                                         : (header.is_64 ? "ELF64" : "ELF32");
        loaded.metadata.machine = header.machine;
        loaded.metadata.header_size = header.is_64 ? 64 : 52;
        if (header.object_type != 1 && !loaded.image->layout().segments.empty()) {
            const auto &segments = loaded.image->layout().segments;
            loaded.metadata.preferred_base = segments.front().begin.offset;
            loaded.metadata.image_size =
                segments.back().begin.offset + segments.back().size - segments.front().begin.offset;
        }
        if (header.object_type != 4) {
            read_symbols(*tracking, *loaded.image, elf, budget, stop);
            auto line_result = read_source_lines(*tracking, elf, budget, stop);
            if (!line_result)
                partial("DWARF line information unavailable: " + line_result.error().message);
            auto dwarf_result = read_dwarf_info(*tracking, elf, budget, stop, options.dwarf_split_resolver,
                                                 options.dwarf_supplementary_resolver,
                                                 options.dwarf_supplementary_max_bytes,
                                                 options.dwarf_supplementary_max_requests,
                                                 options.dwarf_supplementary_package,
                                                 options.dwarf_split_debug_package);
            if (!dwarf_result)
                partial("DWARF type/symbol information unavailable: " + dwarf_result.error().message);
            else if (elf.dwarf_info)
                for (const auto &diagnostic : elf.dwarf_info->diagnostics)
                    partial("DWARF: " + diagnostic);
            auto unwind_result = read_unwind_ranges(*tracking, *loaded.image, elf, budget, stop);
            if (!unwind_result)
                partial("DWARF unwind information unavailable: " + unwind_result.error().message);
            if (architecture == Architecture::arm && !header.is_64 && header.order == ByteOrder::little) {
                auto context_layout = loaded.image->layout();
                populate_arm_context(elf, context_layout, budget, stop);
                if (context_layout.arm_profile)
                    loaded.image = take(Image::create(storage, std::move(context_layout)));
            }
            RelocationRegistry relocation_registry;
            read_relocations(*tracking, *loaded.image, elf, budget, relocation_registry, stop);
            read_dynamic(*tracking, *loaded.image, elf, budget, relocation_registry, stop);
            read_symbol_versions(*tracking, *loaded.image, elf, budget, stop);
            auto rtti_result = read_rtti(*tracking, *loaded.image, elf, budget, stop);
            if (!rtti_result)
                partial("ELF Itanium RTTI metadata unavailable: " + rtti_result.error().message);
            else if (!rtti_result.value())
                partial("ELF Itanium RTTI metadata is incomplete or contains unresolved relationships");
            if (!elf.relocations_complete)
                partial("Some ELF relocation field types remain unsupported");
            if (!elf.dynamic_complete)
                partial("Some ELF dynamic tags remain uninterpreted");
        } else if (options.runtime_load_bias) {
            return Error{ErrorCode::unsupported, "Runtime relocation is unavailable for ELF core images"};
        }
        loaded.metadata.elf = std::move(elf);
        loaded.metadata_reads = tracking->reads();
        if (options.runtime_load_bias) {
            auto runtime = take(apply_elf_runtime_relocations(loaded, *options.runtime_load_bias, stop));
            loaded.runtime_image = std::move(runtime.image);
            loaded.runtime_load_bias = runtime.load_bias;
            loaded.runtime_relocations_complete = runtime.complete;
            loaded.runtime_relocations_applied = std::move(runtime.applied_indices);
            for (const auto &skip : runtime.skipped)
                loaded.runtime_relocation_diagnostics.push_back(
                    {DiagnosticSeverity::warning,
                     "ELF runtime relocation " +
                         (skip.relocation_index == UINT64_MAX ? std::string("metadata")
                                                              : std::to_string(skip.relocation_index)) +
                         " skipped: " + skip.reason,
                     {}});
        }
        canceled(stop);
        return loaded;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF image metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF image metadata exceeds container limit"};
    }
}
} // namespace hexlab
