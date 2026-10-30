#include "macho_internal.hpp"
#include <algorithm>
namespace hexlab {
namespace {
bool sections_match_image(const MachOMetadata &metadata, const Image &image, std::stop_token stop) {
    using namespace macho_detail;
    if (metadata.container.slices[metadata.selected_slice].header.file_type == 1)
        return true;
    std::uint64_t work = 64 * 1024 * 1024;
    for (const auto &section : metadata.sections) {
        // S_ATTR_DEBUG sections carry file metadata and are not required to
        // participate in the mapped VM image.
        if (section.flags & 0x02000000)
            continue;
        for (std::uint64_t done = 0; done < section.size;) {
            canceled(stop);
            require(work != 0, "Mach-O section/mapping comparison exceeds work budget", ErrorCode::resource_limit);
            --work;
            const auto *mapped = image.segment_at({{0}, add(section.address, done)});
            if (!mapped)
                return false;
            const auto relative = section.address + done - mapped->begin.offset;
            if (section.file_offset) {
                if (relative >= mapped->file_size ||
                    add(mapped->file_begin.value, relative) != add(section.file_offset->value, done))
                    return false;
            } else if (relative < mapped->file_size)
                return false;
            done = add(done, std::min(section.size - done, mapped->size - relative));
        }
    }
    return true;
}
} // namespace
namespace macho_detail {
Result<std::uint32_t> select_slice(const MachOContainer &container, const MachOOptions &options) {
    const auto &slices = container.slices;
    if (slices.empty())
        return Error{ErrorCode::malformed, "Mach-O container has no slices"};
    if (options.slice_index) {
        if (*options.slice_index >= slices.size())
            return Error{ErrorCode::invalid_argument, "Mach-O requested slice is outside container"};
        return *options.slice_index;
    }
    struct PreferredSlice { std::uint32_t cpu; bool is_64; ByteOrder order; };
    // Preserve the historic little-endian x86/ARM64 preference, then select
    // bounded 32-bit and big-endian modes when they are the best available
    // decoded slices in a universal container.
    constexpr PreferredSlice preference[] = {
        {0x01000007u, true, ByteOrder::little}, {7u, false, ByteOrder::little},
        {0x0100000cu, true, ByteOrder::little}, {12u, false, ByteOrder::little},
        {0x01000012u, true, ByteOrder::little}, {0x01000008u, true, ByteOrder::little},
        {18u, false, ByteOrder::big}, {18u, false, ByteOrder::little},
        {8u, false, ByteOrder::big}, {8u, false, ByteOrder::little},
        {12u, false, ByteOrder::big}, {7u, false, ByteOrder::big},
        {0x01000012u, true, ByteOrder::big}, {0x01000008u, true, ByteOrder::big}
    };
    for (const auto &preferred : preference)
        for (std::uint32_t index = 0; index < slices.size(); ++index)
            if (slices[index].header.cpu_type == preferred.cpu &&
                slices[index].header.order == preferred.order &&
                slices[index].header.is_64 == preferred.is_64)
                return index;
    return std::uint32_t{0};
}
} // namespace macho_detail
Result<LoadedImage> macho_detail::load_macho_bound(std::shared_ptr<const ByteStorage> storage,
                                                   const MachOOptions &options, std::optional<bool> universal,
                                                   std::stop_token stop) {
    using namespace macho_detail;
    try {
        canceled(stop);
        require(bool(storage), "Mach-O loading requires storage", ErrorCode::invalid_argument);
        auto tracking = take(TrackingStorage::create(storage));
        MachOMetadata metadata;
        metadata.container = take(read_macho_container(*tracking, stop));
        require(!universal || metadata.container.universal == *universal,
                "Saved Mach-O container kind differs from the current input", ErrorCode::conflict);
        const auto &slices = metadata.container.slices;
        metadata.selected_slice = take(select_slice(metadata.container, options));
        const auto &slice = slices[metadata.selected_slice];
        const auto &header = slice.header;
        require(header.file_type == 1 || header.file_type == 2 || header.file_type == 6 || header.file_type == 7 ||
                    header.file_type == 8,
                "Mach-O file type has no implemented image semantics", ErrorCode::unsupported);
        Budget budget;
        budget.include(slices.size() * sizeof(MachOSlice));
        if (metadata.container.universal)
            budget.include(8 + slices.size() * (metadata.container.fat_64 ? 32 : 20));
        for (const auto &item : slices)
            budget.include(item.header.command_bytes + item.header.commands.size() * sizeof(MachOLoadCommand));
        read_segments(*tracking, metadata, budget, stop);
        Architecture architecture = Architecture::unknown;
        ExecutionMode mode = ExecutionMode::unknown;
        if (header.cpu_type == 7)
            architecture = Architecture::x86;
        else if (header.cpu_type == 0x01000007)
            architecture = Architecture::x86_64;
        else if (header.cpu_type == 12)
            architecture = Architecture::arm;
        else if (header.cpu_type == 0x0100000c)
            architecture = Architecture::arm64;
        else if (header.cpu_type == 18 || header.cpu_type == 0x01000012u)
            architecture = Architecture::powerpc;
        else if (header.cpu_type == 8 || header.cpu_type == 0x01000008u)
            architecture = header.is_64 ? Architecture::mips64 : Architecture::mips32;
        if (header.cpu_type == 7 && !header.is_64)
            mode = ExecutionMode::x86_32;
        else if (header.cpu_type == 0x01000007 && header.is_64)
            mode = ExecutionMode::x86_64;
        else if (header.cpu_type == 12 && !header.is_64)
            mode = ExecutionMode::a32;
        else if (header.cpu_type == 0x0100000c && header.is_64)
            mode = ExecutionMode::a64;
        else if ((header.cpu_type == 18 && !header.is_64) ||
                 (header.cpu_type == 0x01000012u && header.is_64))
            mode = header.is_64 ? ExecutionMode::ppc64 : ExecutionMode::ppc32;
        else if ((header.cpu_type == 8 && !header.is_64) ||
                 (header.cpu_type == 0x01000008u && header.is_64))
            mode = header.is_64 ? ExecutionMode::mips64 : ExecutionMode::mips32;
        if (header.order == ByteOrder::big &&
            (header.cpu_type == 7 || header.cpu_type == 0x01000007 ||
             header.cpu_type == 0x0100000c))
            mode = ExecutionMode::unknown;
        ImageLayout layout{
            {{0}, static_cast<std::uint8_t>(header.is_64 ? 64 : 32), 1, header.order}, architecture, mode, {}, {}};
        map_segments(metadata, layout, budget, stop);
        LoadedImage loaded;
        loaded.image = take(Image::create(storage, std::move(layout)));
        auto protected_layout = loaded.image->layout();
        read_protections(*tracking, *loaded.image, metadata, protected_layout, budget, stop);
        if (!protected_layout.code_exclusions.empty() || !protected_layout.encrypted_ranges.empty())
            loaded.image = take(Image::create(storage, std::move(protected_layout)));
        read_symbols(*tracking, *loaded.image, metadata, budget, stop);
        read_commands(*tracking, *loaded.image, metadata, budget, stop);
        read_indirect_symbol_bindings(metadata, budget, stop);
        read_relocations(*tracking, *loaded.image, metadata, budget, stop);
        read_dyld(*tracking, *loaded.image, metadata, budget, stop);
        if (!metadata.entries_conflict) {
            auto with_entries = loaded.image->layout();
            for (const auto &entry : metadata.entries)
                if (entry.address && std::find(with_entries.entries.begin(), with_entries.entries.end(),
                                               *entry.address) == with_entries.entries.end())
                    with_entries.entries.push_back(*entry.address);
            if (!with_entries.entries.empty())
                loaded.image = take(Image::create(storage, std::move(with_entries)));
        }
        loaded.metadata.format = header.is_64 ? "Mach-O64" : "Mach-O32";
        if (header.order == ByteOrder::big) loaded.metadata.format += "-BE";
        loaded.metadata.header_size = header.is_64 ? 32 : 28;
        loaded.metadata_complete = mode != ExecutionMode::unknown;
        auto source_lines=read_source_lines(*tracking,*loaded.image,metadata,budget,stop);
        if(!source_lines){loaded.metadata_complete=false;loaded.diagnostics.push_back({DiagnosticSeverity::warning,"Mach-O DWARF line information unavailable: "+source_lines.error().message,{}});}
        if (!metadata.protections_complete) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                                          "Mach-O data/encryption/signature declarations include unknown kinds, "
                                          "encrypted bytes or unauthenticated signatures",
                                          {}});
        }
        if (!metadata.commands_complete) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back(
                {DiagnosticSeverity::warning, "Some Mach-O entry/command relationships remain unresolved", {}});
        }
        if (!metadata.symbols_complete) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back(
                {DiagnosticSeverity::warning, "Some Mach-O symbol semantics remain unavailable", {}});
        }
        if (!sections_match_image(metadata, *loaded.image, stop)) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                                          "Mach-O section declarations disagree with authoritative segment mappings",
                                          {}});
        }
        if (mode == ExecutionMode::unknown)
            loaded.diagnostics.push_back(
                {DiagnosticSeverity::warning, "Mach-O CPU/class/order has no implemented decoder", {}});
        const bool unknown = std::any_of(header.commands.begin(), header.commands.end(),
                                         [](const auto &command) { return !supported_command(command.command); });
        if (unknown) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back(
                {DiagnosticSeverity::warning, "Some Mach-O command payloads remain uninterpreted", {}});
        }
        if (!metadata.relocations_complete) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back(
                {DiagnosticSeverity::warning, "Some Mach-O relocation semantics remain unsupported", {}});
        }
        if (!metadata.dyld_complete) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back(
                {DiagnosticSeverity::warning, "Some Mach-O dyld payloads remain uninterpreted", {}});
        }
        if (header.file_type != 1 && !loaded.image->layout().segments.empty()) {
            const auto &segments = loaded.image->layout().segments;
            loaded.metadata.preferred_base = segments.front().begin.offset;
            loaded.metadata.image_size =
                add(segments.back().begin.offset, segments.back().size) - segments.front().begin.offset;
        }
        loaded.metadata.macho = std::move(metadata);
        loaded.metadata_reads = tracking->reads();
        loaded.metadata_reads_complete = true;
        canceled(stop);
        return loaded;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O image metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mach-O image allocation exceeds limits"};
    }
}
Result<LoadedImage> load_macho(std::shared_ptr<const ByteStorage> storage, const MachOOptions &options,
                               std::stop_token stop) {
    return macho_detail::load_macho_bound(std::move(storage), options, std::nullopt, stop);
}
} // namespace hexlab
