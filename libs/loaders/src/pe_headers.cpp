#include "pe_internal.hpp"
#include <map>
#include <tuple>

namespace hexlab {
namespace {
constexpr std::uint64_t arm64x_apply_limit = 1'000'000;

struct Arm64xRange {
    std::uint64_t begin = 0, end = 0;
};

bool overlaps(std::vector<Arm64xRange> ranges) {
    std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) {
        return std::tie(a.begin, a.end) < std::tie(b.begin, b.end);
    });
    for (std::size_t i = 1; i < ranges.size(); ++i)
        if (ranges[i].begin < ranges[i - 1].end)
            return true;
    return false;
}

Result<std::pair<std::shared_ptr<const Image>, std::vector<PeDynamicRelocationAppliedFixup>>>
build_arm64x_view(const Image &source, const ImageMetadata &metadata,
                  const PeDynamicRelocationTable &table, std::uint64_t load_base,
                  std::stop_token stop) {
    using namespace pe_detail;
    try {
        require(table.status == PeDynamicRelocationStatus::decoded_layout,
                "ARM64X dynamic relocation table is not fully decoded", ErrorCode::unsupported);
        std::vector<PatchSpan> patches;
        std::vector<Arm64xRange> rva_ranges, file_ranges;
        std::vector<PeDynamicRelocationAppliedFixup> applied;
        std::uint64_t total = 0;
        bool saw_arm64x = false;
        for (std::size_t ri = 0; ri < table.records.size(); ++ri) {
            canceled(stop);
            const auto &record = table.records[ri];
            if (record.symbol != 6) {
                if (record.fixup_size)
                    throw Failure{{ErrorCode::unsupported,
                                   "An opaque dynamic relocation record prevents atomic ARM64X view application"}};
                continue;
            }
            saw_arm64x = true;
            require(record.fixups_decoded,
                    "An ARM64X record contains opaque fixups", ErrorCode::unsupported);
            require(ri <= UINT32_MAX, "ARM64X record index exceeds provenance width", ErrorCode::resource_limit);
            for (std::size_t fi = 0; fi < record.fixups.size(); ++fi) {
                canceled(stop);
                if (++total > arm64x_apply_limit)
                    throw Failure{{ErrorCode::resource_limit, "ARM64X application fixup budget exceeded"}};
                const auto &fixup = record.fixups[fi];
                require(fi <= UINT32_MAX, "ARM64X fixup index exceeds provenance width", ErrorCode::resource_limit);
                require(fixup.size >= 1 && fixup.size <= 8,
                        "ARM64X fixup has an invalid target width");
                require(fixup.rva <= metadata.image_size &&
                            fixup.size <= metadata.image_size - fixup.rva,
                        "ARM64X fixup target exceeds the image");
                const auto target_value = checked_add(load_base, fixup.rva);
                require(target_value.has_value(), "ARM64X target address overflows", ErrorCode::overflow);
                const Address target{source.layout().space.id, target_value.value()};
                const auto *segment = source.segment_at(target);
                require(segment != nullptr, "ARM64X target is not mapped");
                const auto relative = target.offset - segment->begin.offset;
                require(relative <= segment->file_size && fixup.size <= segment->file_size - relative,
                        "ARM64X target is not fully backed by initialized file bytes");
                const auto file_value = checked_add(segment->file_begin.value, relative);
                require(file_value.has_value(), "ARM64X target file offset overflows", ErrorCode::overflow);
                auto original = source.read(target, fixup.size);
                require(original.has_value(), "ARM64X target bytes cannot be read");

                std::vector<std::byte> replacement(fixup.size, std::byte{0});
                if (fixup.kind == PeDynamicRelocationFixupKind::value) {
                    require(fixup.value.size() == fixup.size,
                            "ARM64X VALUE payload width disagrees with its target width");
                    replacement = fixup.value;
                } else if (fixup.kind == PeDynamicRelocationFixupKind::delta) {
                    require(fixup.size == 4 && fixup.delta.has_value(),
                            "ARM64X DELTA requires a signed 32-bit adjustment");
                    std::uint32_t prior = 0;
                    for (unsigned i = 0; i < 4; ++i)
                        prior |= std::to_integer<std::uint32_t>(original.value()[i]) << (i * 8);
                    const auto adjusted = static_cast<std::int64_t>(prior) + *fixup.delta;
                    require(adjusted >= 0 && adjusted <= UINT32_MAX,
                            "ARM64X DELTA result is outside the 32-bit value range", ErrorCode::overflow);
                    for (unsigned i = 0; i < 4; ++i)
                        replacement[i] = static_cast<std::byte>(
                            (static_cast<std::uint32_t>(adjusted) >> (i * 8)) & 0xffu);
                } else {
                    require(fixup.kind == PeDynamicRelocationFixupKind::zero_fill,
                            "ARM64X fixup kind is unknown", ErrorCode::unsupported);
                    require(fixup.value.empty() && !fixup.delta,
                            "ARM64X ZERO_FILL carries an unexpected payload");
                }

                const auto rva_end = std::uint64_t{fixup.rva} + fixup.size;
                const auto file_end = file_value.value() + fixup.size;
                rva_ranges.push_back({fixup.rva, rva_end});
                file_ranges.push_back({file_value.value(), file_end});
                patches.push_back({{file_value.value()}, std::move(original.value()), std::move(replacement)});
                applied.push_back({static_cast<std::uint32_t>(ri), static_cast<std::uint32_t>(fi)});
            }
        }
        require(saw_arm64x && !patches.empty(), "No applicable ARM64X fixups were decoded",
                ErrorCode::unsupported);
        require(!overlaps(std::move(rva_ranges)) && !overlaps(std::move(file_ranges)),
                "ARM64X fixup ranges overlap; no fixups were applied", ErrorCode::invalid_argument);
        auto overlay = make_overlay(source.storage(), patches);
        if (!overlay) throw Failure{overlay.error()};
        auto view = Image::create(std::move(overlay.value()), source.layout());
        if (!view) throw Failure{view.error()};
        return std::pair{std::move(view.value()), std::move(applied)};
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ARM64X effective view"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ARM64X effective view exceeds memory limits"};
    }
}

Result<LoadedImage> load_pe_impl(std::shared_ptr<const ByteStorage> storage,
                                 std::optional<std::uint64_t> requested_load_base, std::stop_token stop) {
    using namespace pe_detail;
    try {
        canceled(stop);
        require(static_cast<bool>(storage),"PE loader requires input storage");
        const auto original=storage;
        auto tracking=TrackingStorage::create(storage);
        if(!tracking)return tracking.error();
        storage=tracking.value();
        FileReader r(*storage);
        require(r.integer<std::uint16_t>(0,"DOS signature")==0x5a4d,"Missing PE DOS signature");
        const std::uint64_t nt=r.integer<std::uint32_t>(0x3c,"e_lfanew");
        require(nt>=0x40,"PE signature overlaps DOS header");
        require(r.integer<std::uint32_t>(nt,"signature")==0x4550,"Missing PE signature");
        const auto coff=add(nt,4,"COFF position");
        const auto machine=r.integer<std::uint16_t>(coff,"machine");
        const auto count=r.integer<std::uint16_t>(coff+2,"section count");
        const auto optional_size=r.integer<std::uint16_t>(coff+16,"optional header size");
        (void)r.bytes(coff,20,"COFF header");
        const auto optional=coff+20;
        (void)r.bytes(optional,optional_size,"optional header");
        const auto magic=r.integer<std::uint16_t>(optional,"optional magic");
        require(magic==0x10b || magic==0x20b,"Unsupported PE optional magic");
        const bool pe64=magic==0x20b;
        const std::uint64_t directory_offset=pe64?112:96;
        require(optional_size>=directory_offset,"PE optional header lacks standard fields");
        require((machine!=0x8664 || pe64) && (machine!=0x14c || !pe64),"PE machine and optional-header mode mismatch");
        ImageMetadata metadata;
        metadata.format=pe64?"PE32+":"PE32";
        metadata.pe.emplace();
        metadata.machine=machine;
        metadata.preferred_base=pe64?r.integer<std::uint64_t>(optional+24,"image base"):r.integer<std::uint32_t>(optional+28,"image base");
        metadata.image_size=r.integer<std::uint32_t>(optional+56,"image size");
        metadata.header_size=r.integer<std::uint32_t>(optional+60,"header size");
        metadata.subsystem=r.integer<std::uint16_t>(optional+68,"subsystem");
        const auto section_alignment=r.integer<std::uint32_t>(optional+32,"section alignment");
        const auto file_alignment=r.integer<std::uint32_t>(optional+36,"file alignment");
        auto power_two=[](std::uint32_t value) {return value!=0 && (value&(value-1))==0;};
        require(power_two(section_alignment) && power_two(file_alignment) && section_alignment>=file_alignment,"Invalid PE section/file alignment");
        require(section_alignment>=0x1000 || section_alignment==file_alignment,"Low-alignment PE requires matching file alignment");
        require(metadata.image_size!=0 && metadata.header_size!=0 && metadata.header_size<=metadata.image_size,"Invalid PE image/header size");
        (void)add(metadata.preferred_base,metadata.image_size,"image extent");
        const auto entry=r.integer<std::uint32_t>(optional+16,"entry RVA");
        require(entry==0 || entry<metadata.image_size,"PE entry exceeds image");
        const auto directories=r.integer<std::uint32_t>(optional+(pe64?108:92),"directory count");
        require(directories<=(optional_size-directory_offset)/8,"PE directories exceed optional header");
        for (std::uint32_t i=0;i<directories;++i) {
            canceled(stop);
            const auto at=optional+directory_offset+std::uint64_t{i}*8;
            metadata.directories.push_back({i,r.integer<std::uint32_t>(at,"directory location"),r.integer<std::uint32_t>(at+4,"directory size"),i==4});
        }
        const auto section_table=optional+optional_size;
        const auto section_table_end=add(section_table,std::uint64_t{count}*40,"section table extent");
        require(section_table_end<=metadata.header_size,"PE section table exceeds header mapping");
        (void)r.bytes(0,metadata.header_size,"header mapping");
        ImageLayout layout{{{0},static_cast<std::uint8_t>(pe64?64:32),1,ByteOrder::little},Architecture::unknown,ExecutionMode::unknown,{}, {}};
        if (machine==0x8664) {layout.architecture=Architecture::x86_64;layout.mode=ExecutionMode::x86_64;}
        else if (machine==0x14c) {layout.architecture=Architecture::x86;layout.mode=ExecutionMode::x86_32;}
        else if (machine==0xaa64) {layout.architecture=Architecture::arm64;if(pe64)layout.mode=ExecutionMode::a64;}
        else if (machine==0x1c0 || machine==0x1c4) {
            layout.architecture=Architecture::arm;
            layout.mode=machine==0x1c4?ExecutionMode::thumb:ExecutionMode::a32;
        }
        layout.segments.push_back({"headers",{{0},metadata.preferred_base},metadata.header_size,{0},metadata.header_size,true,false,false});
        for (std::uint32_t i=0;i<count;++i) {
            canceled(stop);
            const auto at=section_table+std::uint64_t{i}*40;
            const auto name_bytes=r.bytes(at,8,"section name");
            std::string name;
            for (auto ch:name_bytes.bytes) {if (ch==std::byte{0}) break; name.push_back(static_cast<char>(std::to_integer<unsigned char>(ch)));}
            SectionDeclaration section{name,{r.integer<std::uint32_t>(at+12,"section RVA")},r.integer<std::uint32_t>(at+8,"section virtual size"),
                {r.integer<std::uint32_t>(at+20,"section raw position")},r.integer<std::uint32_t>(at+16,"section raw size"),r.integer<std::uint32_t>(at+36,"section characteristics")};
            const auto extent=std::max(section.virtual_size,section.raw_size);
            require(add(section.rva.value,extent,"section virtual extent")<=metadata.image_size,"PE section exceeds image size");
            require(section.rva.value%section_alignment==0,"Unaligned PE section RVA");
            if (section.raw_size) require(section.raw_position.value%file_alignment==0 && section.raw_size%file_alignment==0,"Unaligned PE raw section");
            layout.segments.push_back({name,{{0},add(metadata.preferred_base,section.rva.value,"section VA")},extent,
                {section.raw_size?section.raw_position.value:0},section.raw_size,(section.characteristics&0x40000000)!=0,
                (section.characteristics&0x80000000)!=0,(section.characteristics&0x20000000)!=0});
            metadata.sections.push_back(std::move(section));
        }
        if (entry) layout.entries.push_back({{0},add(metadata.preferred_base,entry,"entry VA")});
        auto image=Image::create(std::move(storage),std::move(layout));
        if (!image) return image.error();
        LoadedImage loaded{image.value(),std::move(metadata),{},true};
        bool relocation_directory_valid = true;
        for (const auto& directory:loaded.metadata.directories) {
            canceled(stop);
            if (directory.location==0 && directory.size==0) continue;
            Result<std::size_t> parsed=Error{ErrorCode::unsupported,"Directory contents are not yet interpreted"};
            const auto directory_end=std::uint64_t{directory.location}+directory.size;
            if (directory.location==0 || directory.size==0)
                parsed=Error{ErrorCode::malformed,"Directory has an empty location or size"};
            else if (directory.file_offset) {
                const auto view=loaded.image->storage()->read_at({directory.location},directory.size);
                if (!view) parsed=Error{ErrorCode::malformed,"Certificate file range exceeds input"};
                else if (directory.index==4)
                    parsed=read_certificates(*loaded.image,directory,loaded.metadata,stop);
            } else if (directory_end>loaded.metadata.image_size)
                parsed=Error{ErrorCode::malformed,"Directory RVA range exceeds image"};
            else if (directory.index==1) parsed=read_imports(*loaded.image,directory,pe64,loaded.metadata,stop);
            else if (directory.index==11) parsed=read_bound_imports(*loaded.image,directory,loaded.metadata,stop);
            else if (directory.index==13) parsed=read_delay_imports(*loaded.image,directory,pe64,loaded.metadata,stop);
            else if (directory.index==6) parsed=read_debug_directory(*loaded.image,directory,loaded.metadata,stop);
            else if (directory.index==0) parsed=read_exports(*loaded.image,directory,loaded.metadata,stop);
            else if (directory.index==5) parsed=read_relocations(*loaded.image,directory,loaded.metadata,stop);
            else if (directory.index==9) parsed=read_tls(*loaded.image,directory,pe64,loaded.metadata,stop);
            else if (directory.index==10) {
                parsed=read_load_configuration(*loaded.image,directory,pe64,loaded.metadata,stop);
                if (parsed)
                    parsed=read_chpe_metadata(*loaded.image,directory,pe64,loaded.metadata,stop);
            }
            else if (directory.index==2) parsed=read_resources(*loaded.image,directory,loaded.metadata,stop);
            else if (directory.index==3) parsed=read_exception_directory(*loaded.image,directory,loaded.metadata,stop);
            if (!parsed) {
                if (parsed.error().code==ErrorCode::canceled) return parsed.error();
                if (directory.index == 5) relocation_directory_valid = false;
                loaded.metadata_complete=false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,"PE directory "+std::to_string(directory.index)+": "+parsed.error().message,{}});
            }
        }
        if (loaded.metadata.pe && loaded.metadata.pe->load_configuration &&
            loaded.metadata.pe->load_configuration->chpe_metadata &&
            !loaded.metadata.pe->load_configuration->chpe_metadata->code_ranges.empty()) {
            auto layout = loaded.image->layout();
            ImageExecutionProfile profile;
            const auto &rows = loaded.metadata.pe->load_configuration->chpe_metadata->code_ranges;
            profile.ranges.reserve(rows.size());
            for (const auto &row : rows) {
                const auto begin = checked_add(loaded.metadata.preferred_base, row.start_rva);
                if (!begin)
                    return begin.error();
                const DecodeContext context = row.kind == PeChpeCodeRangeKind::amd64
                    ? DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little}
                    : DecodeContext{Architecture::arm64, ExecutionMode::a64, ByteOrder::little};
                profile.ranges.push_back({{layout.space.id, begin.value()}, row.length, context});
            }
            layout.execution_profile = std::move(profile);
            auto profiled = Image::create(loaded.image->storage(), std::move(layout));
            if (!profiled)
                return profiled.error();
            loaded.image = std::move(profiled.value());
        }
        // Discover structural MSVC RTTI against the original preferred-base
        // bytes, before applying relocation overlays. Published links are RVAs.
        auto rtti = read_msvc_rtti(*loaded.image, loaded.metadata, stop);
        if (!rtti) {
            if (rtti.error().code == ErrorCode::canceled) return rtti.error();
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back({DiagnosticSeverity::warning, "PE MSVC RTTI discovery: " + rtti.error().message, {}});
        } else if (loaded.metadata.pe->msvc_rtti && !loaded.metadata.pe->msvc_rtti->discovery_complete) {
            loaded.metadata_complete = false;
            loaded.diagnostics.push_back({DiagnosticSeverity::warning, "PE MSVC RTTI discovery: " + loaded.metadata.pe->msvc_rtti->diagnostic, {}});
        }
        const auto requested_base = requested_load_base.value_or(loaded.metadata.preferred_base);
        loaded.load_base = requested_base;
        if (requested_base != loaded.metadata.preferred_base) {
            require(relocation_directory_valid, "Cannot rebase PE image because its relocation directory is incomplete",
                    ErrorCode::unsupported);
            auto rebased = apply_pe_relocations(*loaded.image, loaded.metadata, requested_base, stop);
            if (!rebased) return rebased.error();
            auto overlay = make_overlay(original, rebased.value().patches);
            if (!overlay) return overlay.error();
            auto moved = Image::create(std::move(overlay.value()), std::move(rebased.value().layout));
            if (!moved) return moved.error();
            loaded.image = std::move(moved.value());
        }
        loaded.metadata_reads=tracking.value()->reads();
        loaded.metadata_reads_complete=true;
        auto published_storage = requested_base == loaded.metadata.preferred_base
            ? original : loaded.image->storage();
        auto published=Image::create(std::move(published_storage),loaded.image->layout());
        if(!published)return published.error();
        loaded.image=std::move(published.value());
        loaded.pe_native_image = loaded.image;
        if (loaded.metadata.pe && loaded.metadata.pe->load_configuration &&
            loaded.metadata.pe->load_configuration->dynamic_value_relocations) {
            // ARM64X effective-view construction reads additional target bytes
            // after the parsed image has been rebound to its source storage.
            // Until those reads are routed through TrackingStorage, do not
            // certify the earlier read snapshot as exhaustive.
            loaded.metadata_reads_complete = false;
            auto &dynamic = *loaded.metadata.pe->load_configuration->dynamic_value_relocations;
            auto arm64x = build_arm64x_view(*loaded.image, loaded.metadata, dynamic, requested_base, stop);
            if (arm64x) {
                loaded.pe_arm64x_image = std::move(arm64x.value().first);
                dynamic.application_status = PeDynamicRelocationApplicationStatus::applied;
                dynamic.applied_fixups = std::move(arm64x.value().second);
                dynamic.application_diagnostic = "Complete ARM64X fixup set applied to a separate effective image view";
            } else {
                if (arm64x.error().code == ErrorCode::canceled)
                    return arm64x.error();
                dynamic.application_status = arm64x.error().code == ErrorCode::unsupported
                    ? PeDynamicRelocationApplicationStatus::unsupported
                    : (arm64x.error().code == ErrorCode::invalid_argument ||
                       arm64x.error().code == ErrorCode::conflict)
                        ? PeDynamicRelocationApplicationStatus::conflict
                        : PeDynamicRelocationApplicationStatus::malformed;
                dynamic.applied_fixups.clear();
                dynamic.application_diagnostic = arm64x.error().message;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "PE ARM64X effective view was not created: " + arm64x.error().message, {}});
            }
        }
        return loaded;
    } catch (const Failure& failure) {return failure.error;}
      catch (const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate PE image metadata"};}
      catch (const std::length_error&) {return Error{ErrorCode::resource_limit,"PE image metadata is too large"};}
}
} // namespace
Result<LoadedImage> load_pe(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    return load_pe_impl(std::move(storage), {}, stop);
}
Result<LoadedImage> load_pe_at_base(std::shared_ptr<const ByteStorage> storage, std::uint64_t load_base,
                                    std::stop_token stop) {
    return load_pe_impl(std::move(storage), load_base, stop);
}

Result<std::shared_ptr<const Image>> select_pe_runtime_view(
    const LoadedImage &loaded, PeRuntimeArchitecture target) {
    if (!loaded.image || !loaded.metadata.pe)
        return Error{ErrorCode::invalid_argument, "Runtime view selection requires a loaded PE image"};

    const auto machine = loaded.metadata.machine;
    const bool native_arm64 = machine == 0xaa64;
    const bool native_x64 = machine == 0x8664;
    if (target != PeRuntimeArchitecture::arm64 && target != PeRuntimeArchitecture::x64_compatible)
        return Error{ErrorCode::invalid_argument, "Unknown PE runtime architecture"};
    if (!native_arm64 && !native_x64)
        return Error{ErrorCode::unsupported, "PE machine has no supported Windows-on-Arm runtime view"};

    const bool target_is_arm64 = target == PeRuntimeArchitecture::arm64;
    const bool target_is_native = target_is_arm64 ? native_arm64 : native_x64;
    const auto base = loaded.pe_native_image ? loaded.pe_native_image : loaded.image;
    std::shared_ptr<const Image> selected = base;
    if (!target_is_native) {
        if (!loaded.pe_arm64x_image)
            return Error{ErrorCode::unsupported,
                         "The requested PE architecture requires an ARM64X transformed view, which is unavailable"};
        const auto *configuration = loaded.metadata.pe->load_configuration
            ? &*loaded.metadata.pe->load_configuration : nullptr;
        const bool has_chpe_map = configuration && configuration->chpe_metadata &&
                                  !configuration->chpe_metadata->code_ranges.empty();
        if (!has_chpe_map)
            return Error{ErrorCode::unsupported,
                         "The requested ARM64X view has no validated CHPE code map for range-aware decoding"};
        selected = loaded.pe_arm64x_image;
    }

    auto layout = selected->layout();
    if (target_is_arm64) {
        layout.architecture = Architecture::arm64;
        layout.mode = ExecutionMode::a64;
        // In a classic ARM64 process all executable bytes in the selected view
        // use the ARM64 ISA; the hybrid map describes the other process view.
        layout.execution_profile.reset();
    } else {
        layout.architecture = Architecture::x86_64;
        layout.mode = ExecutionMode::x86_64;
        // Preserve the validated CHPE map so AMD64 and ARM64EC ranges keep
        // their per-range decoding contexts in the compatible process view.
        if (!target_is_native && (!layout.execution_profile || layout.execution_profile->ranges.empty()))
            return Error{ErrorCode::unsupported,
                         "The x64-compatible view has no validated per-range decode profile"};
    }
    auto profiled = Image::create(selected->storage(), std::move(layout));
    if (!profiled)
        return profiled.error();
    return std::shared_ptr<const Image>(std::move(profiled.value()));
}
}
