#include "macho_internal.hpp"
#include "hexlab/symbols/dwarf.hpp"

#include <algorithm>

namespace hexlab::macho_detail {
Result<bool> read_source_lines(const ByteStorage &storage,const Image &image,MachOMetadata &metadata,Budget &budget,std::stop_token stop) {
    const auto &slice=metadata.container.slices[metadata.selected_slice];
    Reader reader(storage,slice,stop);
    bool any=false;
    for(const auto &section:metadata.sections) {
        canceled(stop);
        if(section.name=="__zdebug_line")return Error{ErrorCode::unsupported,"compressed Mach-O __zdebug_line is unsupported"};
        if(section.name!="__debug_line")continue;
        any=true;
        if(!section.file_offset)return Error{ErrorCode::unsupported,"Mach-O __debug_line has no file-backed bytes"};
        if(section.size>metadata_limit)return Error{ErrorCode::resource_limit,"Mach-O __debug_line exceeds metadata budget"};
        budget.include(section.size);
        const auto view=reader.bytes(section.raw_file_offset,static_cast<std::size_t>(section.size));
        std::vector<std::uint8_t> data;data.reserve(view.bytes.size());
        for(auto byte:view.bytes){canceled(stop);data.push_back(std::to_integer<std::uint8_t>(byte));}
        const auto address_size=static_cast<std::uint8_t>(slice.header.is_64?8:4);
        auto imported=symbols::import_dwarf_line_v2_v4({"Mach-O selected slice .__debug_line",data,address_size,slice.header.order==ByteOrder::little,4'000'000,stop});
        if(!imported)return imported.error();
        for(std::size_t unit_index=0;unit_index<imported.value().size();++unit_index) {
            const auto &unit=imported.value()[unit_index];
            for(std::size_t row_index=0;row_index<unit.rows.size();++row_index) {
                canceled(stop);const auto &row=unit.rows[row_index];std::string file;
                if(row.file&&row.file<=unit.files.size()) {
                    const auto &entry=unit.files[static_cast<std::size_t>(row.file-1)];
                    if(entry.directory&&entry.directory<=unit.directories.size())file=unit.directories[static_cast<std::size_t>(entry.directory-1)]+"/";
                    file+=entry.name;
                }
                MachOSourceLine out;out.selected_slice=metadata.selected_slice;out.source_section=section.ordinal;
                out.line_unit=static_cast<std::uint32_t>(unit_index);out.row=static_cast<std::uint32_t>(row_index);
                out.source_file_offset=*section.file_offset;out.raw_address=row.address;out.file=std::move(file);
                out.line=row.line;out.column=row.column;out.end_sequence=row.end_sequence;
                // MH_OBJECT set_address operands depend on relocation records
                // to identify the section domain. Preserve raw coordinates
                // until that provenance is decoded. Linked images carry VMAs;
                // map only if exactly one section range and the loaded image
                // both agree that the coordinate is mapped.
                if(slice.header.file_type!=1) {
                    const MachOSection *match=nullptr;bool ambiguous=false;
                    for(const auto &candidate:metadata.sections)if(candidate.size&&row.address>=candidate.address&&row.address-candidate.address<candidate.size) {
                        if(match){ambiguous=true;break;}match=&candidate;
                    }
                    if(match&&!ambiguous) {
                        const Address address{{0},row.address};
                        if(image.segment_at(address)){out.address=address;out.address_section=match->ordinal;}
                    }
                }
                budget.include(sizeof(MachOSourceLine)+out.file.size());metadata.source_lines.push_back(std::move(out));
            }
        }
    }
    return any;
}
} // namespace hexlab::macho_detail
