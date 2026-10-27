#pragma once
#include "hexlab/image/metadata.hpp"
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
inline void jvm_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.jvm) return;
    const auto &j = *metadata.jvm;
    out << "Java class: " << j.class_name << " version=" << j.major_version << '.' << j.minor_version
        << " access=" << j.access_flags << '\n';
    if(j.source_file)out<<"Source file: "<<*j.source_file<<'\n';
    if(j.signature)out<<"Class signature: "<<jvm_safe(*j.signature)<<'\n';
    if (!j.super_name.empty()) out << "Superclass: " << j.super_name << '\n';
    out << "Interfaces: " << j.interfaces.size() << " Fields: " << j.fields.size()
        << " Methods: " << j.methods.size() << " Constant pool: " << (j.constant_pool.size() - 1) << '\n';
    const auto annotations=[&](const auto &items,const char *visibility,const char *owner){for(const auto &annotation:items)out<<visibility<<" annotation "<<owner<<": "<<annotation.descriptor<<" elements="<<annotation.elements.size()<<'\n';};
    const auto type_annotations=[&](const auto &items,const char *visibility,const char *owner){for(const auto &annotation:items)out<<visibility<<" type annotation "<<owner<<" target=0x"<<std::hex<<static_cast<unsigned>(annotation.target_type)<<std::dec<<" path="<<annotation.type_path.size()<<": "<<annotation.annotation.descriptor<<" elements="<<annotation.annotation.elements.size()<<'\n';};
    annotations(j.visible_annotations,"visible","class");annotations(j.invisible_annotations,"invisible","class");
    type_annotations(j.visible_type_annotations,"visible","class");type_annotations(j.invisible_type_annotations,"invisible","class");
    if (j.nest_host) out << "Nest host: " << *j.nest_host << '\n';
    for (const auto &name : j.nest_members) out << "Nest member: " << name << '\n';
    for (const auto &name : j.permitted_subclasses) out << "Permitted subclass: " << name << '\n';
    for (const auto &component : j.record_components) {
        out << "Record component: " << component.name << ' ' << component.descriptor;
        if (component.signature) out << " signature=" << *component.signature;
        out << '\n';
    }
    for (const auto &inner : j.inner_classes) {
        out << "Inner class: " << jvm_safe(inner.inner_class);
        if (inner.outer_class) out << " outer=" << jvm_safe(*inner.outer_class);
        if (inner.inner_name) out << " name=" << jvm_safe(*inner.inner_name);
        out << " access=" << inner.access_flags << '\n';
    }
    for (const auto &method : j.methods) {
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
        annotations(method.visible_annotations,"visible","method");annotations(method.invisible_annotations,"invisible","method");
        type_annotations(method.visible_type_annotations,"visible","method");type_annotations(method.invisible_type_annotations,"invisible","method");
        if(method.code){
            type_annotations(method.code->visible_type_annotations,"visible","Code");type_annotations(method.code->invisible_type_annotations,"invisible","Code");
            if(method.code->line_numbers)for(const auto &line:*method.code->line_numbers)out<<"    line "<<line.line_number<<" at +0x"<<std::hex<<line.start_pc<<std::dec<<'\n';
            if(method.code->local_variables)for(const auto &local:*method.code->local_variables)out<<"    local "<<local.name<<' '<<local.descriptor<<" slot="<<local.slot<<" range=["<<local.start_pc<<','<<std::uint32_t(local.start_pc)+local.length<<")\n";
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
        annotations(field.visible_annotations,"visible","field");annotations(field.invisible_annotations,"invisible","field");
        type_annotations(field.visible_type_annotations,"visible","field");type_annotations(field.invisible_type_annotations,"invisible","field");
    }
}
} // namespace hexlab::cli
