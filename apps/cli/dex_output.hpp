#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <bit>
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string_view>

namespace hexlab::cli {
inline std::string dex_safe(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c == 0x7f) out += '?';
        else out += static_cast<char>(c);
    }
    return out;
}
inline std::string dex_identifier_preview(std::string_view value) {
    constexpr std::size_t max_bytes = 160;
    auto end = std::min(value.size(), max_bytes);
    while (end && end < value.size() && (static_cast<unsigned char>(value[end]) & 0xc0) == 0x80) --end;
    std::string out;
    for (const unsigned char ch : value.substr(0, end)) {
        if (ch == '\\') out += "\\\\";
        else if (ch == '"') out += "\\\"";
        else if (ch == '\n') out += "\\n";
        else if (ch == '\r') out += "\\r";
        else if (ch == '\t') out += "\\t";
        else if (ch < 0x20 || ch == 0x7f) {
            constexpr char digits[] = "0123456789abcdef";
            out += "\\u00"; out += digits[ch >> 4]; out += digits[ch & 15];
        } else out += static_cast<char>(ch);
    }
    if (end < value.size()) out += "...<truncated>";
    return out;
}
inline void dex_static_value_tree(std::ostream &out, const DexMetadata &dex,
                                  const DexEncodedValue &value, unsigned depth,
                                  std::size_t &shown, std::size_t &omitted) {
    constexpr std::size_t max_values = 512;
    if (shown >= max_values) {
        omitted = 1;
        return;
    }
    ++shown;
    out << "    " << std::string(std::min(depth, 8u) * 2, ' ') << "tag=0x"
        << std::hex << unsigned(value.type) << std::dec << " file=0x" << std::hex
        << value.file_offset << std::dec << " bytes=" << value.byte_size;
    const auto string_name = [&](std::uint64_t index) {
        return index < dex.strings.size()
            ? dex_identifier_preview(dex.strings[static_cast<std::size_t>(index)]) : std::string("<invalid-index>");
    };
    const auto type_name = [&](std::uint64_t index) {
        return index < dex.type_descriptors.size()
            ? dex_identifier_preview(dex.type_descriptors[static_cast<std::size_t>(index)]) : std::string("<invalid-index>");
    };
    const auto field_name = [&](std::uint64_t index) {
        if (index >= dex.field_identifiers.size()) return std::string("<invalid-field-index>");
        const auto &field = dex.field_identifiers[static_cast<std::size_t>(index)];
        return type_name(field.declaring_type_index) + "." + string_name(field.name_index);
    };
    const auto method_name = [&](std::uint64_t index) {
        if (index >= dex.method_identifiers.size()) return std::string("<invalid-method-index>");
        const auto &method = dex.method_identifiers[static_cast<std::size_t>(index)];
        return type_name(method.declaring_type_index) + "." + string_name(method.name_index) + " proto#" +
            std::to_string(method.prototype_index);
    };
    switch (value.type) {
    case 0x00: out << " byte=" << std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value.payload)); break;
    case 0x02: out << " short=" << std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(value.payload)); break;
    case 0x03: out << " char=U+" << std::hex << static_cast<std::uint16_t>(value.payload) << std::dec; break;
    case 0x04: out << " int=" << std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value.payload)); break;
    case 0x06: out << " long=" << std::bit_cast<std::int64_t>(value.payload); break;
    case 0x10: out << " float=" << std::bit_cast<float>(static_cast<std::uint32_t>(value.payload >> 32)); break;
    case 0x11: out << " double=" << std::bit_cast<double>(value.payload); break;
    case 0x15: out << " method-type proto#" << value.payload; break;
    case 0x16:
        out << " method-handle#" << value.payload;
        if (value.payload < dex.method_handles.size()) {
            const auto &handle = dex.method_handles[static_cast<std::size_t>(value.payload)];
            constexpr const char *kinds[] = {"static-put", "static-get", "instance-put", "instance-get",
                "invoke-static", "invoke-instance", "invoke-constructor", "invoke-direct", "invoke-interface"};
            out << " kind=" << (handle.kind < std::size(kinds) ? kinds[handle.kind] : "unknown")
                << " target=" << (handle.kind <= 3 ? field_name(handle.member_index) : method_name(handle.member_index));
        }
        break;
    case 0x17: out << " string#" << value.payload << " \"" << string_name(value.payload) << '"'; break;
    case 0x18: out << " type#" << value.payload << ' ' << type_name(value.payload); break;
    case 0x19: out << " field#" << value.payload << ' ' << field_name(value.payload); break;
    case 0x1a: out << " method#" << value.payload << ' ' << method_name(value.payload); break;
    case 0x1b: out << " enum-field#" << value.payload << ' ' << field_name(value.payload); break;
    case 0x1c: out << " array items=" << value.children.size(); break;
    case 0x1d: out << " annotation type#" << value.payload << ' ' << type_name(value.payload)
                   << " elements=" << value.children.size(); break;
    case 0x1e: out << " null"; break;
    case 0x1f: out << " boolean=" << (value.value_arg ? "true" : "false"); break;
    default: out << " payload=0x" << std::hex << value.payload << std::dec; break;
    }
    if (value.name_index != UINT32_MAX)
        out << " name=\"" << string_name(value.name_index) << '"';
    out << '\n';
    if (depth >= 8) {
        if (!value.children.empty()) omitted = 1;
        return;
    }
    for (const auto &child : value.children)
        dex_static_value_tree(out, dex, child, depth + 1, shown, omitted);
}
inline void dex_annotation_description(std::ostream &out,const DexMetadata &dex) {
    constexpr std::size_t max_rows=128,max_entries=256,max_values=256;
    std::size_t entries_shown=0,entries_omitted=0,values_shown=0,values_omitted=0;
    const auto type_name=[&](std::uint32_t index){return index<dex.type_descriptors.size()?dex_identifier_preview(dex.type_descriptors[index]):std::string("<unavailable>");};
    const auto string_name=[&](std::uint32_t index){return index<dex.strings.size()?dex_identifier_preview(dex.strings[index]):std::string("<unavailable>");};
    out<<"DEX annotation graph: directories="<<dex.annotation_directories.size()<<" sets="<<dex.annotation_sets.size()
       <<" parameter-lists="<<dex.annotation_set_ref_lists.size()<<" items="<<dex.annotations.size()<<" links="<<dex.annotation_links.size()<<'\n';
    for(std::size_t n=0;n<std::min(dex.annotation_directories.size(),max_rows);++n){const auto &directory=dex.annotation_directories[n];
        out<<"  directory#"<<n<<" class-def#"<<directory.class_def_index<<" offset=0x"<<std::hex<<directory.file_offset
           <<" class-set=0x"<<directory.class_annotations_offset<<std::dec<<" bytes="<<directory.byte_size
           <<" fields="<<directory.fields.size()<<" methods="<<directory.methods.size()<<" parameter-methods="<<directory.parameters.size()<<'\n';
        const auto entries=[&](const auto &items,const char *kind){const auto shown=std::min({items.size(),std::size_t{16},max_entries-entries_shown});
            for(std::size_t i=0;i<shown;++i){const auto &entry=items[i];out<<"    "<<kind<<'#'<<entry.member_index<<" target=0x"<<std::hex
                <<entry.annotations_offset<<" entry-file=0x"<<entry.file_offset<<std::dec<<'\n';}
            entries_shown+=shown;entries_omitted+=items.size()-shown;};
        entries(directory.fields,"field");entries(directory.methods,"method");entries(directory.parameters,"parameter-method");
    }
    for(std::size_t n=0;n<std::min(dex.annotation_sets.size(),max_rows);++n){const auto &set=dex.annotation_sets[n];
        out<<"  set#"<<n<<" offset=0x"<<std::hex<<set.file_offset<<std::dec<<" bytes="<<set.byte_size<<" items="<<set.annotation_indices.size();
        if(set.annotation_indices.empty())out<<" (present-empty)";out<<'\n';
        const auto shown=std::min({set.annotation_indices.size(),std::size_t{16},max_entries-entries_shown});
        for(std::size_t i=0;i<shown;++i)out<<"    annotation#"<<set.annotation_indices[i]<<" reference-file=0x"<<std::hex<<set.file_offset+4+i*4<<std::dec<<'\n';
        entries_shown+=shown;entries_omitted+=set.annotation_indices.size()-shown;
    }
    for(std::size_t n=0;n<std::min(dex.annotation_set_ref_lists.size(),max_rows);++n){const auto &list=dex.annotation_set_ref_lists[n];
        out<<"  parameter-list#"<<n<<" offset=0x"<<std::hex<<list.file_offset<<std::dec<<" bytes="<<list.byte_size<<" slots="<<list.set_offsets.size()<<'\n';
        const auto shown=std::min({list.set_offsets.size(),std::size_t{16},max_entries-entries_shown});
        for(std::size_t i=0;i<shown;++i){out<<"    parameter#"<<i<<" set=0x"<<std::hex<<list.set_offsets[i]<<" reference-file=0x"<<list.file_offset+4+i*4<<std::dec;if(!list.set_offsets[i])out<<" (absent)";out<<'\n';}
        entries_shown+=shown;entries_omitted+=list.set_offsets.size()-shown;
    }
    const auto values=[&](auto &&self,const std::vector<DexEncodedValue>& items,unsigned depth)->void{
        std::size_t shown=0;
        while(depth<8&&shown<items.size()&&shown<16&&values_shown<max_values){
            const auto &value=items[shown++];++values_shown;out<<"    value depth="<<depth;
            if(value.name_index!=UINT32_MAX)out<<" name=string#"<<value.name_index<<" \""<<string_name(value.name_index)<<'"';
            out<<" tag=0x"<<std::hex<<unsigned(value.type)<<" arg=0x"<<unsigned(value.value_arg)<<" bits-or-index=0x"<<value.payload
               <<" file=0x"<<value.file_offset<<" bytes="<<std::dec<<value.byte_size<<" children="<<value.children.size();
            if(value.type==0x17&&value.payload<dex.strings.size())out<<" string=\""<<string_name(static_cast<std::uint32_t>(value.payload))<<'"';
            if((value.type==0x18||value.type==0x1d)&&value.payload<dex.type_descriptors.size())out<<" type="<<type_name(static_cast<std::uint32_t>(value.payload));
            out<<'\n';self(self,value.children,depth+1);
        }
        values_omitted+=items.size()-shown;
    };
    for(std::size_t n=0;n<std::min(dex.annotations.size(),max_rows);++n){const auto &annotation=dex.annotations[n];
        const char *visibility=annotation.visibility==0?"build":annotation.visibility==1?"runtime":annotation.visibility==2?"system":"unknown";
        out<<"  annotation#"<<n<<" type#"<<annotation.type_index<<' '<<type_name(annotation.type_index)<<" visibility="<<unsigned(annotation.visibility)
           <<'('<<visibility<<") offset=0x"<<std::hex<<annotation.file_offset<<std::dec<<" bytes="<<annotation.byte_size<<" elements="<<annotation.elements.size()<<'\n';
        values(values,annotation.elements,0);
    }
    for(std::size_t n=0;n<std::min(dex.annotation_links.size(),max_rows);++n){const auto &link=dex.annotation_links[n];
        constexpr const char *kinds[]={"class","field","method","parameter"};const auto kind=static_cast<std::size_t>(link.kind);
        out<<"  annotation-link class-def#"<<link.class_def_index<<" kind="<<(kind<std::size(kinds)?kinds[kind]:"unknown");
        if(link.member_index!=UINT32_MAX)out<<" member#"<<link.member_index;if(link.parameter_index!=UINT32_MAX)out<<" parameter#"<<link.parameter_index;
        out<<" annotation#"<<link.annotation_index<<" reference-file=0x"<<std::hex<<link.file_offset<<std::dec<<'\n';
    }
    const auto omitted=[&](std::size_t count){return count-std::min(count,max_rows);};
    if(omitted(dex.annotation_directories.size())||omitted(dex.annotation_sets.size())||omitted(dex.annotation_set_ref_lists.size())||omitted(dex.annotations.size())||omitted(dex.annotation_links.size()))
        out<<"  annotation rows omitted: directories="<<omitted(dex.annotation_directories.size())<<" sets="<<omitted(dex.annotation_sets.size())<<" parameter-lists="<<omitted(dex.annotation_set_ref_lists.size())<<" items="<<omitted(dex.annotations.size())<<" links="<<omitted(dex.annotation_links.size())<<'\n';
    if(entries_omitted)out<<"  entries omitted from shown containers="<<entries_omitted<<'\n';
    if(values_omitted)out<<"  immediate values omitted from visited lists="<<values_omitted<<'\n';
}
inline void dex_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.dex) return;
    const auto &dex = *metadata.dex;
    constexpr std::size_t max_classes = 256;
    constexpr std::size_t max_members_per_class = 128;
    constexpr std::size_t max_map_items = 256;
    if (dex.link_data_size)
        out << "DEX link data: offset=0x" << std::hex << dex.link_data_offset << std::dec
            << " bytes=" << dex.link_data_size << " (opaque payload)\n";
    else
        out << "DEX link data: none\n";
    out << "DEX map entries: " << dex.map_items.size() << '\n';
    const auto map_count = std::min(dex.map_items.size(), max_map_items);
    for (std::size_t i = 0; i < map_count; ++i) {
        const auto &item = dex.map_items[i];
        out << "  map type=0x" << std::hex << item.type << " offset=0x" << item.offset
            << std::dec << " count=" << item.size << '\n';
    }
    if (map_count < dex.map_items.size())
        out << "  map entries omitted=" << (dex.map_items.size() - map_count) << '\n';
    constexpr std::size_t max_identifier_rows = 128;
    out << "DEX identifiers: strings=" << dex.strings.size() << " fields=" << dex.field_identifiers.size()
        << " methods=" << dex.method_identifiers.size() << '\n';
    const auto name = [&](std::uint32_t index) {
        return index < dex.strings.size() ? dex_identifier_preview(dex.strings[index]) : std::string("<unavailable>");
    };
    for (std::size_t i = 0; i < std::min(dex.strings.size(), max_identifier_rows); ++i) {
        out << "  string#" << i << " value=\"" << dex_identifier_preview(dex.strings[i]) << '"';
        if (i < dex.string_sources.size()) {
            const auto &source = dex.string_sources[i];
            out << " id-offset=0x" << std::hex << source.id_file_offset << " data-offset=0x"
                << source.data_file_offset << std::dec << " data-bytes=" << source.data_size << " utf16-units=" << source.utf16_size;
        }
        out << '\n';
    }
    for (std::size_t i = 0; i < std::min(dex.field_identifiers.size(), max_identifier_rows); ++i) {
        const auto &field = dex.field_identifiers[i];
        out << "  field#" << i << " owner=type#" << field.declaring_type_index << " type=type#" << field.type_index
            << " name=string#" << field.name_index << " \"" << name(field.name_index) << "\" id-offset=0x"
            << std::hex << field.file_offset << std::dec << '\n';
    }
    for (std::size_t i = 0; i < std::min(dex.method_identifiers.size(), max_identifier_rows); ++i) {
        const auto &method = dex.method_identifiers[i];
        out << "  method#" << i << " owner=type#" << method.declaring_type_index << " proto#" << method.prototype_index
            << " name=string#" << method.name_index << " \"" << name(method.name_index) << "\" id-offset=0x"
            << std::hex << method.file_offset << std::dec << '\n';
    }
    out << "DEX dynamic linkage: method-handles=" << dex.method_handles.size()
        << " call-sites=" << dex.call_sites.size() << '\n';
    constexpr std::size_t max_linkage_rows = 128;
    constexpr const char *handle_kinds[] = {"static-put", "static-get", "instance-put", "instance-get",
        "invoke-static", "invoke-instance", "invoke-constructor", "invoke-direct", "invoke-interface"};
    for (std::size_t i = 0; i < std::min(dex.method_handles.size(), max_linkage_rows); ++i) {
        const auto &handle = dex.method_handles[i];
        out << "  method-handle#" << i << " kind="
            << (handle.kind < std::size(handle_kinds) ? handle_kinds[handle.kind] : "unknown")
            << " target=";
        if (handle.kind <= 3) {
            out << "field#" << handle.member_index;
            if (handle.member_index < dex.field_identifiers.size()) {
                const auto &field = dex.field_identifiers[handle.member_index];
                out << ' ' << name(field.name_index);
            }
        } else {
            out << "method#" << handle.member_index;
            if (handle.member_index < dex.method_identifiers.size()) {
                const auto &method = dex.method_identifiers[handle.member_index];
                out << ' ' << name(method.name_index);
            }
        }
        out << " file=0x" << std::hex << handle.file_offset << std::dec << '\n';
    }
    if (dex.method_handles.size() > max_linkage_rows)
        out << "  method-handle rows omitted=" << dex.method_handles.size() - max_linkage_rows << '\n';
    std::size_t shown_call_site_values = 0, omitted_call_site_values = 0;
    for (std::size_t i = 0; i < std::min(dex.call_sites.size(), max_linkage_rows); ++i) {
        const auto &site = dex.call_sites[i];
        out << "  call-site#" << i << " file=0x" << std::hex << site.file_offset << std::dec
            << " values=" << site.values.size();
        if (site.values.size() >= 3) {
            const auto &bootstrap = site.values[0];
            const auto &method_name = site.values[1];
            const auto &method_type = site.values[2];
            out << " bootstrap-handle#" << bootstrap.payload
                << " name=string#" << method_name.payload << " \"" << name(static_cast<std::uint32_t>(method_name.payload)) << '\"'
                << " proto#" << method_type.payload;
        }
        out << '\n';
        const auto argument_count = site.values.size() > 3 ? site.values.size() - 3 : 0;
        const auto shown = shown_call_site_values < 512
            ? std::min({argument_count, std::size_t{8}, std::size_t{512} - shown_call_site_values})
            : std::size_t{0};
        for (std::size_t j = 0; j < shown; ++j)
            dex_static_value_tree(out, dex, site.values[j + 3], 1, shown_call_site_values, omitted_call_site_values);
        omitted_call_site_values += argument_count - shown;
    }
    if (dex.call_sites.size() > max_linkage_rows)
        out << "  call-site rows omitted=" << dex.call_sites.size() - max_linkage_rows << '\n';
    if (omitted_call_site_values)
        out << "  call-site argument values omitted=" << omitted_call_site_values << '\n';
    if (dex.strings.size() > max_identifier_rows || dex.field_identifiers.size() > max_identifier_rows ||
        dex.method_identifiers.size() > max_identifier_rows)
        out << "  identifier rows omitted: strings=" << (dex.strings.size() - std::min(dex.strings.size(), max_identifier_rows))
            << " fields=" << (dex.field_identifiers.size() - std::min(dex.field_identifiers.size(), max_identifier_rows))
            << " methods=" << (dex.method_identifiers.size() - std::min(dex.method_identifiers.size(), max_identifier_rows)) << '\n';
    out << "DEX class definitions: " << dex.classes.size() << '\n';
    const auto class_count = std::min(dex.classes.size(), max_classes);
    for (std::size_t i = 0; i < class_count; ++i) {
        const auto &definition = dex.classes[i];
        out << "  class type#" << definition.class_index << " flags=0x" << std::hex
            << definition.access_flags << std::dec;
        if (definition.superclass_index) out << " superclass=type#" << *definition.superclass_index;
        else out << " superclass=<none>";
        if (definition.source_file_index) {
            out << " source-file=string#" << *definition.source_file_index;
            if (*definition.source_file_index < dex.strings.size())
                out << " \"" << dex_identifier_preview(dex.strings[*definition.source_file_index]) << '"';
        } else {
            out << " source-file=<none>";
        }
        if(definition.annotations_offset)out<<" annotation-directory=0x"<<std::hex<<definition.annotations_offset<<std::dec;
        else out<<" annotation-directory=<absent>";
        out << " interfaces=" << definition.interface_indices.size()
            << " static-fields=" << definition.static_fields.size()
            << " instance-fields=" << definition.instance_fields.size()
            << " direct-methods=" << definition.direct_methods.size()
            << " virtual-methods=" << definition.virtual_methods.size() << '\n';
        const auto fields = [&](std::string_view label, const auto &items) {
            const auto shown = std::min(items.size(), max_members_per_class);
            for (std::size_t member = 0; member < shown; ++member) {
                const auto &field = items[member];
                out << "    " << label << " field#" << field.field_index;
                if (!field.name.empty()) out << " name=" << dex_safe(field.name);
                out << " flags=0x" << std::hex << field.access_flags << std::dec << '\n';
            }
            if (shown < items.size()) out << "    " << label << " fields omitted=" << (items.size() - shown) << '\n';
        };
        const auto methods = [&](std::string_view label, const auto &items) {
            const auto shown = std::min(items.size(), max_members_per_class);
            for (std::size_t member = 0; member < shown; ++member) {
                const auto &method = items[member];
                out << "    " << label << " method#" << method.method_index;
                if (!method.name.empty()) out << " name=" << dex_safe(method.name);
                out << " flags=0x" << std::hex << method.access_flags << std::dec
                    << " code-offset=0x" << std::hex << method.code_offset << std::dec << '\n';
            }
            if (shown < items.size()) out << "    " << label << " methods omitted=" << (items.size() - shown) << '\n';
        };
        fields("static", definition.static_fields);
        fields("instance", definition.instance_fields);
        methods("direct", definition.direct_methods);
        methods("virtual", definition.virtual_methods);
    }
    if (class_count < dex.classes.size()) out << "  classes omitted=" << (dex.classes.size() - class_count) << '\n';
    out << "DEX explicit static values: " << dex.static_values.size() << '\n';
    constexpr std::size_t max_static_value_rows = 256;
    std::size_t value_nodes_shown = 0, value_nodes_omitted = 0;
    const auto static_value_count = std::min(dex.static_values.size(), max_static_value_rows);
    for (std::size_t i = 0; i < static_value_count; ++i) {
        const auto &entry = dex.static_values[i];
        const auto class_name = entry.class_index < dex.type_descriptors.size()
            ? dex_identifier_preview(dex.type_descriptors[entry.class_index]) : std::string("<invalid-class-index>");
        out << "  class type#" << entry.class_index << ' ' << class_name << " field#" << entry.field_index;
        if (entry.field_index < dex.field_identifiers.size()) {
            const auto &field = dex.field_identifiers[entry.field_index];
            if (field.name_index < dex.strings.size())
                out << " name=" << dex_identifier_preview(dex.strings[field.name_index]);
        }
        out << " value:\n";
        dex_static_value_tree(out, dex, entry.value, 0, value_nodes_shown, value_nodes_omitted);
    }
    if (static_value_count < dex.static_values.size())
        out << "  static-value rows omitted=" << dex.static_values.size() - static_value_count << '\n';
    if (value_nodes_omitted)
        out << "  nested static-value output truncated by display caps (256 rows, 512 nodes, depth 8)\n";
    dex_annotation_description(out,dex);
    out << "DEX MethodParameters rows: " << dex.method_parameters.size() << '\n';
    const auto parameter_count = std::min<std::size_t>(dex.method_parameters.size(), 256);
    for (std::size_t i = 0; i < parameter_count; ++i) {
        const auto &parameter = dex.method_parameters[i];
        out << "  method #" << parameter.method_index << " parameter " << parameter.parameter_index << " name=";
        if (parameter.name_index && *parameter.name_index < dex.strings.size())
            out << dex_identifier_preview(dex.strings[*parameter.name_index]);
        else out << "<unnamed>";
        out << " flags=0x" << std::hex << parameter.access_flags
            << " name-file=0x" << parameter.name_file_offset
            << " flags-file=0x" << parameter.access_flags_file_offset << std::dec << '\n';
    }
    if (parameter_count < dex.method_parameters.size())
        out << "  MethodParameters rows omitted=" << dex.method_parameters.size() - parameter_count << '\n';
    out << "DEX declared exceptions: rows=" << dex.method_throws.size() << '\n';
    const auto throws_count = std::min<std::size_t>(dex.method_throws.size(), 256);
    for (std::size_t i = 0; i < throws_count; ++i) {
        const auto &throws = dex.method_throws[i];
        out << "  method #" << throws.method_index << " value-file=0x" << std::hex
            << throws.value_file_offset << " annotation-link-file=0x" << throws.annotation_link_file_offset
            << std::dec << " types=" << throws.type_indices.size() << '\n';
        const auto shown = std::min<std::size_t>(throws.type_indices.size(), 16);
        for (std::size_t j = 0; j < shown; ++j) {
            const auto type_index = throws.type_indices[j];
            out << "    type#" << type_index << ' ';
            if (type_index < dex.type_descriptors.size())
                out << dex_identifier_preview(dex.type_descriptors[type_index]);
            else out << "<invalid type index>";
            out << '\n';
        }
        if (shown < throws.type_indices.size())
            out << "    exception types omitted=" << throws.type_indices.size() - shown << " (limit 16)\n";
    }
    if (throws_count < dex.method_throws.size())
        out << "  declared-exception methods omitted=" << dex.method_throws.size() - throws_count << '\n';
    out << "DEX debug methods: " << dex.methods.size() << '\n';
    for (const auto &method : dex.methods) {
        out << "  method #" << method.method_index << " line-start=" << method.line_start
            << " parameters=" << method.parameter_names.size() << " lines=" << method.lines.size()
            << " locals=" << method.locals.size() << '\n';
        for (std::size_t i = 0; i < method.parameter_names.size(); ++i) {
            out << "    parameter " << i << " name=";
            if (method.parameter_names[i]) out << dex_safe(*method.parameter_names[i]);
            else out << "<unnamed>";
            out << '\n';
        }
        for (std::size_t i = 0; i < method.lines.size() && i < 256; ++i) {
            const auto &line = method.lines[i];
            out << "    line +0x" << std::hex << line.address << std::dec << '=' << line.line;
            if (!line.source_file.empty()) out << " file=" << dex_safe(line.source_file);
            if (line.prologue_end) out << " prologue-end";
            if (line.epilogue_begin) out << " epilogue-begin";
            out << '\n';
        }
        for (std::size_t i = 0; i < method.locals.size() && i < 256; ++i) {
            const auto &local = method.locals[i];
            out << "    local v" << local.register_index << " [+0x" << std::hex << local.begin
                << ",+0x" << local.end << ")" << std::dec;
            if (local.name) out << " name=" << dex_safe(*local.name);
            if (local.type) out << " type=" << dex_safe(*local.type);
            if (local.signature) out << " signature=" << dex_safe(*local.signature);
            out << '\n';
        }
        if (method.lines.size() > 256 || method.locals.size() > 256)
            out << "    display truncated at 256 rows per category\n";
    }
}
} // namespace hexlab::cli
