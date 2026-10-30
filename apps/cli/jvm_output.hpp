#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <ostream>
#include <string>
#include <string_view>

namespace hexlab::cli {
inline std::string jvm_safe(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char c : value) {
        if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else if (c < 0x20 || c == 0x7f) result += '?';
        else result += static_cast<char>(c);
    }
    return result;
}
inline std::string jvm_utf8_prefix(std::string_view value, std::size_t limit) {
    auto length = std::min(value.size(), limit);
    while (length && length < value.size() &&
           (static_cast<unsigned char>(value[length]) & 0xc0) == 0x80) --length;
    return jvm_safe(value.substr(0, length));
}
inline void jvm_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.jvm) return;
    const auto &j = *metadata.jvm;
    std::size_t generic_owners=0,generic_owners_omitted=0,generic_nodes=0,generic_nodes_omitted=0;
    const auto generic=[&](const std::optional<JvmGenericSignatureAnalysis>& item,const char *owner,std::string_view name){
        if(!item)return;
        if(generic_owners++>=128){++generic_owners_omitted;return;}
        const auto &analysis=*item;
        out<<"  Generic signature "<<owner<<' '<<jvm_utf8_prefix(name,192)<<" cp#"<<analysis.signature_index
           <<" reference-file=0x"<<std::hex<<analysis.reference_file_offset.value<<" text-file=0x"<<analysis.text_file_offset.value<<std::dec;
        if(!analysis.parsed){out<<" status=unparsed note="<<jvm_utf8_prefix(analysis.diagnostic,256)<<'\n';return;}
        const auto &nodes=analysis.parsed->nodes;out<<" nodes="<<nodes.size()<<'\n';
        constexpr const char *labels[]={"class-signature","method-signature","field-signature","type-parameter",
            "class-bound","interface-bound","superclass","superinterface","parameters","result","throws",
            "primitive","void","class-type","class-segment","type-variable","array","exact-argument",
            "extends-argument","super-argument","unbounded-argument"};
        const auto shown=std::min({nodes.size(),std::size_t{16},std::size_t{128}-generic_nodes});
        for(std::size_t n=0;n<shown;++n){const auto &node=nodes[n];const auto kind=static_cast<std::size_t>(node.kind);
            out<<"    node#"<<n<<' '<<(kind<std::size(labels)?labels[kind]:"unknown");
            if(!node.name.empty()){out<<" name="<<jvm_utf8_prefix(node.name,96);if(node.name.size()>96)out<<"...";}
            out<<" text=["<<node.text_offset<<','<<node.text_offset+node.text_size<<") file=0x"<<std::hex
               <<analysis.text_file_offset.value+node.text_offset<<std::dec<<" children="<<node.children.size();
            for(std::size_t c=0;c<std::min<std::size_t>(node.children.size(),8);++c)out<<" #"<<node.children[c];
            if(node.children.size()>8)out<<" ...";out<<'\n';
        }
        generic_nodes+=shown;generic_nodes_omitted+=nodes.size()-shown;
    };
    std::size_t opaque_rows=0,opaque_rows_omitted=0;
    const auto opaque_attributes=[&](const std::vector<JvmOpaqueAttribute> &items,std::string_view owner){
        for(const auto &item:items){
            if(opaque_rows++>=128){++opaque_rows_omitted;continue;}
            out<<"Opaque JVM attribute "<<owner<<" "<<jvm_utf8_prefix(item.name,128)
               <<" payload-file=0x"<<std::hex<<item.payload_file_offset.value<<std::dec
               <<" bytes="<<item.payload_size<<'\n';
        }
    };
    out << "Java class: " << j.class_name << " version=" << j.major_version << '.' << j.minor_version
        << " access=" << j.access_flags << '\n';
    opaque_attributes(j.opaque_attributes,"class");
    if(j.source_file)out<<"Source file: "<<*j.source_file<<'\n';
    const auto provenance_id=[&](std::string_view name,const std::optional<JvmProvenanceId> &id){
        if(!id)return;
        out<<name<<" (CONSTANT_Utf8 #"<<id->constant_pool_index<<", reference-file=0x"
           <<std::hex<<id->reference_file_offset.value<<std::dec<<", "<<id->value.size()<<" bytes): \""
           <<jvm_utf8_prefix(id->value,192);
        if(id->value.size()>192)out<<"...";
        out<<"\"\n";
    };
    provenance_id("Compilation ID",j.compilation_id);
    provenance_id("Source ID",j.source_id);
    if(j.source_debug_extension){
        out<<"Source debug extension ("<<j.source_debug_extension->size()<<" bytes): \""
           <<jvm_utf8_prefix(*j.source_debug_extension,192);
        if(j.source_debug_extension->size()>192)out<<"...";
        out<<"\"\n";
    }
    if (j.source_debug_map) {
        const auto &map = *j.source_debug_map;
        out << "Source debug map: generated=" << jvm_utf8_prefix(map.generated_file, 192)
            << " default-stratum=" << jvm_utf8_prefix(map.default_stratum, 96)
            << " strata=" << map.strata.size() << '\n';
        std::size_t detail_rows = 0, details_omitted = 0;
        for (const auto &stratum : map.strata) {
            out << "  SMAP stratum " << jvm_utf8_prefix(stratum.name, 96)
                << " files=" << stratum.files.size() << " line-rules=" << stratum.lines.size() << '\n';
            for (const auto &file : stratum.files) {
                if (detail_rows++ >= 256) { ++details_omitted; continue; }
                out << "    file#" << file.id << " name=" << jvm_utf8_prefix(file.name, 192);
                if (file.path) out << " path=" << jvm_utf8_prefix(*file.path, 256);
                out << '\n';
            }
            for (const auto &line : stratum.lines) {
                if (detail_rows++ >= 256) { ++details_omitted; continue; }
                out << "    map file#" << line.file_id << " input=" << line.input_start
                    << " repeat=" << line.repeat_count << " output=" << line.output_start
                    << " increment=" << line.output_increment << '\n';
            }
        }
        if (details_omitted) out << "  SMAP detail rows omitted=" << details_omitted << " (limit 256)\n";
    } else if (j.source_debug_map_diagnostic) {
        out << "Source debug map not interpreted: " << jvm_utf8_prefix(*j.source_debug_map_diagnostic, 256) << '\n';
    }
    if(j.module_target)
        out<<"Module target: "<<(j.module_target->platform?jvm_safe(*j.module_target->platform):"<unspecified>")<<'\n';
    if(j.module){
        const auto &module=*j.module;
        const auto saved_flags=out.flags();
        out<<"Module: "<<jvm_utf8_prefix(module.name,192)<<" flags=0x"<<std::hex<<module.flags<<std::dec;
        if(module.version)out<<" version=\""<<jvm_utf8_prefix(*module.version,192)<<'"';
        out<<" requires="<<module.required_modules.size()<<" exports="<<module.exports.size()
           <<" opens="<<module.opens.size()<<" uses="<<module.uses.size()<<" provides="<<module.provides.size()<<'\n';
        out.flags(saved_flags);
        constexpr std::size_t module_detail_limit=128, module_target_preview=8;
        std::size_t module_details=0,module_details_omitted=0;
        const auto emit_detail=[&](auto &&write){
            if(module_details==module_detail_limit){++module_details_omitted;return;}
            ++module_details;write();
        };
        const auto targets=[&](const auto &items){
            for(std::size_t i=0;i<std::min(items.size(),module_target_preview);++i)
                out<<' '<<jvm_utf8_prefix(items[i],96);
            if(items.size()>module_target_preview)out<<" ... ("<<(items.size()-module_target_preview)<<" more)";
        };
        for(const auto &require:module.required_modules)emit_detail([&]{
            const auto flags=out.flags();
            out<<"  requires "<<jvm_utf8_prefix(require.module,192)<<" flags=0x"<<std::hex<<require.flags<<std::dec;
            if(require.version)out<<" version=\""<<jvm_utf8_prefix(*require.version,192)<<'"';
            out<<'\n';out.flags(flags);
        });
        const auto print_packages=[&](const auto &entries,std::string_view kind){
            for(const auto &entry:entries)emit_detail([&]{
                const auto flags=out.flags();
                out<<"  "<<kind<<' '<<jvm_utf8_prefix(entry.package_name,192)<<" flags=0x"<<std::hex<<entry.flags<<std::dec;
                if(!entry.to_modules.empty()){out<<" to=";targets(entry.to_modules);}
                out<<'\n';out.flags(flags);
            });
        };
        print_packages(module.exports,"exports");
        print_packages(module.opens,"opens");
        for(const auto &used:module.uses)emit_detail([&]{out<<"  uses "<<jvm_utf8_prefix(used,192)<<'\n';});
        for(const auto &provided:module.provides)emit_detail([&]{
            out<<"  provides "<<jvm_utf8_prefix(provided.service,192)<<" with";targets(provided.implementations);out<<'\n';
        });
        if(module_details_omitted)out<<"  Module detail rows omitted: "<<module_details_omitted
            <<" (limit "<<module_detail_limit<<")\n";
    }
    if(!j.module_packages.empty()){
        out<<"Module packages: "<<j.module_packages.size()<<'\n';
        constexpr std::size_t preview=128;
        for(std::size_t i=0;i<std::min(j.module_packages.size(),preview);++i)
            out<<"  "<<jvm_utf8_prefix(j.module_packages[i],192)<<'\n';
        if(j.module_packages.size()>preview)
            out<<"  Module package rows omitted: "<<(j.module_packages.size()-preview)<<" (limit "<<preview<<")\n";
    }
    if(j.module_main_class)out<<"Module main class: "<<jvm_utf8_prefix(*j.module_main_class,192)<<'\n';
    if(j.module_hash_algorithm){
        out<<"Module hashes: algorithm=\""<<jvm_safe(*j.module_hash_algorithm)<<"\" entries="<<j.module_hashes.size()<<'\n';
        constexpr char digits[]="0123456789abcdef";
        for(const auto &entry:j.module_hashes){
            out<<"  "<<jvm_safe(entry.module)<<" bytes="<<entry.hash.size()<<" hash=0x";
            const auto preview=std::min<std::size_t>(entry.hash.size(),16);
            for(std::size_t i=0;i<preview;++i){out<<digits[entry.hash[i]>>4]<<digits[entry.hash[i]&0x0f];}
            if(entry.hash.size()>preview)out<<"...";
            out<<'\n';
        }
    }
    if(j.module_resolution){
        const auto flags=out.flags();
        out<<"Module resolution flags=0x"<<std::hex<<*j.module_resolution<<std::dec<<'\n';
        out.flags(flags);
    }
    if(j.signature)out<<"Class signature: "<<jvm_safe(*j.signature)<<'\n';
    generic(j.generic_signature,"class",j.class_name);
    if(j.enclosing_method){
        out<<"Enclosing method: "<<jvm_safe(j.enclosing_method->class_name);
        if(j.enclosing_method->method_name&&j.enclosing_method->method_descriptor)
            out<<'.'<<jvm_safe(*j.enclosing_method->method_name)<<jvm_safe(*j.enclosing_method->method_descriptor);
        out<<'\n';
    }
    if (!j.super_name.empty()) out << "Superclass: " << j.super_name << '\n';
    out << "Interfaces: " << j.interfaces.size() << " Fields: " << j.fields.size()
        << " Methods: " << j.methods.size() << " Constant pool: " << (j.constant_pool.size() - 1) << '\n';
    const auto annotations=[&](const auto &items,const char *visibility,const char *owner){for(const auto &annotation:items)out<<visibility<<" annotation "<<owner<<": "<<annotation.descriptor<<" elements="<<annotation.elements.size()<<'\n';};
    const auto type_annotations=[&](const auto &items,const char *visibility,const std::string &owner){for(const auto &annotation:items)out<<visibility<<" type annotation "<<owner<<" target=0x"<<std::hex<<static_cast<unsigned>(annotation.target_type)<<std::dec<<" path="<<annotation.type_path.size()<<": "<<annotation.annotation.descriptor<<" elements="<<annotation.annotation.elements.size()<<'\n';};
    annotations(j.visible_annotations,"visible","class");annotations(j.invisible_annotations,"invisible","class");
    type_annotations(j.visible_type_annotations,"visible","class");type_annotations(j.invisible_type_annotations,"invisible","class");
    if (j.nest_host_reference) {
        const auto flags=out.flags();
        out << "Nest host: " << j.nest_host_reference->class_name << " cp#"
            << j.nest_host_reference->constant_pool_index << " index-file=0x" << std::hex
            << j.nest_host_reference->reference_file_offset.value << '\n';
        out.flags(flags);
    }
    for (const auto &reference : j.nest_member_references) {
        const auto flags=out.flags();
        out << "Nest member: " << reference.class_name << " cp#" << reference.constant_pool_index
            << " index-file=0x" << std::hex << reference.reference_file_offset.value << '\n';
        out.flags(flags);
    }
    for (const auto &reference : j.permitted_subclass_references) {
        const auto flags=out.flags();
        out << "Permitted subclass: " << reference.class_name << " cp#" << reference.constant_pool_index
            << " index-file=0x" << std::hex << reference.reference_file_offset.value << '\n';
        out.flags(flags);
    }
    if(j.preload_classes){
        out<<"Preload classes: "<<j.preload_classes->size()<<'\n';
        constexpr std::size_t preview=128;
        for(std::size_t i=0;i<std::min(j.preload_classes->size(),preview);++i){
            const auto &reference=(*j.preload_classes)[i];
            const auto flags=out.flags();
            out<<"  "<<jvm_utf8_prefix(reference.class_name,192)<<" cp#"<<reference.constant_pool_index
               <<" index-file=0x"<<std::hex<<reference.reference_file_offset.value<<'\n';
            out.flags(flags);
        }
        if(j.preload_classes->size()>preview)
            out<<"  Preload class rows omitted: "<<(j.preload_classes->size()-preview)<<" (limit "<<preview<<")\n";
    }
    if(j.record){
        const auto flags=out.flags();
        out<<"Record: components="<<j.record_components.size()<<" attribute-offset=0x"<<std::hex
           <<j.record->attribute_file_offset.value<<std::dec<<" payload-bytes="<<j.record->attribute_length<<'\n';
        out.flags(flags);
    }
    constexpr std::size_t max_record_annotation_rows=128;
    std::size_t record_annotation_rows=0,record_annotations_omitted=0;
    for (std::size_t component_index=0;component_index<j.record_components.size();++component_index) {
        const auto &component=j.record_components[component_index];
        opaque_attributes(component.opaque_attributes,"record component "+jvm_safe(component.name));
        out << "Record component: " << component.name << ' ' << component.descriptor;
        if (component.signature) out << " signature=" << *component.signature;
        out << " source-offset=0x"<<std::hex<<component.file_begin.value<<std::dec
            <<" source-bytes="<<component.byte_size<<'\n';
        generic(component.generic_signature,"record-component",component.name);
        const auto record_annotations=[&](const auto &items,const char *visibility){
            const auto shown=std::min(items.size(),max_record_annotation_rows-record_annotation_rows);
            for(std::size_t n=0;n<shown;++n){
                out<<"  "<<visibility<<" record annotation component#"<<component_index<<": "
                   <<jvm_utf8_prefix(items[n].descriptor,192);
                if(items[n].descriptor.size()>192)out<<"...";
                out<<" elements="<<items[n].elements.size()<<'\n';
            }
            record_annotation_rows+=shown;record_annotations_omitted+=items.size()-shown;
        };
        record_annotations(component.visible_annotations,"visible");
        record_annotations(component.invisible_annotations,"invisible");
        const auto owner = "record component " + jvm_safe(component.name) + " " + jvm_safe(component.descriptor);
        type_annotations(component.visible_type_annotations,"visible",owner);
        type_annotations(component.invisible_type_annotations,"invisible",owner);
    }
    if(record_annotations_omitted)out<<"Record annotation rows omitted: "<<record_annotations_omitted<<'\n';
    for (const auto &inner : j.inner_classes) {
        out << "Inner class: " << jvm_safe(inner.inner_class);
        if (inner.outer_class) out << " outer=" << jvm_safe(*inner.outer_class);
        if (inner.inner_name) out << " name=" << jvm_safe(*inner.inner_name);
        out << " access=" << inner.access_flags << '\n';
    }
    for (const auto &method : j.methods) {
        opaque_attributes(method.opaque_attributes,"method "+jvm_safe(method.name));
        out << "  " << method.name << method.descriptor << " access=" << method.access_flags;
        if (method.signature) out << " signature=" << jvm_safe(*method.signature);
        if (method.declared_exceptions) {
            out << " throws=";
            for (std::size_t i = 0; i < method.declared_exceptions->size(); ++i) {
                if (i) out << ',';
                out << (*method.declared_exceptions)[i];
            }
        }
        if (method.code) out << " code=" << method.code->code_size << " max_stack=" << method.code->max_stack
                             << " max_locals=" << method.code->max_locals
                             << " exceptions=" << method.code->exception_table.size();
        else out << " native/abstract";
        out << '\n';
        generic(method.generic_signature,"method",method.name);
        annotations(method.visible_annotations,"visible","method");annotations(method.invisible_annotations,"invisible","method");
        type_annotations(method.visible_type_annotations,"visible","method");type_annotations(method.invisible_type_annotations,"invisible","method");
        if(method.code){
            opaque_attributes(method.code->opaque_attributes,"Code "+jvm_safe(method.name));
            type_annotations(method.code->visible_type_annotations,"visible","Code");type_annotations(method.code->invisible_type_annotations,"invisible","Code");
            if(method.code->line_numbers)for(const auto &line:*method.code->line_numbers)out<<"    line "<<line.line_number<<" at +0x"<<std::hex<<line.start_pc<<std::dec<<'\n';
            if(method.code->local_variables)for(const auto &local:*method.code->local_variables)out<<"    local "<<local.name<<' '<<local.descriptor<<" slot="<<local.slot<<" range=["<<local.start_pc<<','<<std::uint32_t(local.start_pc)+local.length<<")\n";
            if(method.code->local_variable_types)for(const auto &local:*method.code->local_variable_types){out<<"    local-type "<<local.name<<' '<<local.signature<<" slot="<<local.slot<<" range=["<<local.start_pc<<','<<std::uint32_t(local.start_pc)+local.length<<")\n";generic(local.generic_signature,"local",local.name);}
        }
        const auto parameter_annotations=[&](const auto &parameters,const char *visibility){
            if(!parameters)return;
            for(std::size_t i=0;i<parameters->size();++i)
                annotations((*parameters)[i],visibility,(std::string("method parameter ")+std::to_string(i)).c_str());
        };
        parameter_annotations(method.visible_parameter_annotations,"visible");
        parameter_annotations(method.invisible_parameter_annotations,"invisible");
        if(method.method_parameters){
            for(std::size_t i=0;i<method.method_parameters->size();++i){
                const auto &parameter=(*method.method_parameters)[i];
                const auto flags=out.flags();
                out<<"    parameter["<<i<<"] "<<(parameter.name?jvm_safe(*parameter.name):"<unnamed>")
                   <<" flags=0x"<<std::hex<<parameter.access_flags<<std::dec<<'\n';
                out.flags(flags);
            }
        }
        if(method.annotation_default)out<<"    annotation default: "<<*method.annotation_default<<'\n';
    }
    for(const auto &field:j.fields){
        opaque_attributes(field.opaque_attributes,"field "+jvm_safe(field.name));
        out << "  Field: " << field.name << ' ' << field.descriptor;
        if (field.signature) out << " signature=" << jvm_safe(*field.signature);
        if(field.constant_value){
            const auto &value=*field.constant_value;
            out << " ConstantValue=";
            if(value.tag==8) out << '"' << jvm_safe(value.text) << '"';
            else {
                const auto flags=out.flags();
                out << "0x" << std::hex << value.first;
                out.flags(flags);
            }
        }
        out << '\n';
        generic(field.generic_signature,"field",field.name);
        annotations(field.visible_annotations,"visible","field");annotations(field.invisible_annotations,"invisible","field");
        type_annotations(field.visible_type_annotations,"visible","field");type_annotations(field.invisible_type_annotations,"invisible","field");
    }
    if(generic_owners_omitted)out<<"Generic signature owners omitted: "<<generic_owners_omitted<<'\n';
    if(generic_nodes_omitted)out<<"Generic signature nodes omitted from shown owners: "<<generic_nodes_omitted<<'\n';
    if(opaque_rows_omitted)out<<"Opaque JVM attribute rows omitted: "<<opaque_rows_omitted<<'\n';
}
} // namespace hexlab::cli
