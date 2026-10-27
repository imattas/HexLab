#pragma once
#include "hexlab/image/metadata.hpp"
#include <ostream>
#include <string>

namespace hexlab::cli {
inline void jvm_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.jvm) return;
    const auto &j = *metadata.jvm;
    out << "Java class: " << j.class_name << " version=" << j.major_version << '.' << j.minor_version
        << " access=" << j.access_flags << '\n';
    if (!j.super_name.empty()) out << "Superclass: " << j.super_name << '\n';
    out << "Interfaces: " << j.interfaces.size() << " Fields: " << j.fields.size()
        << " Methods: " << j.methods.size() << " Constant pool: " << (j.constant_pool.size() - 1) << '\n';
    const auto annotations=[&](const auto &items,const char *visibility,const char *owner){for(const auto &annotation:items)out<<visibility<<" annotation "<<owner<<": "<<annotation.descriptor<<" elements="<<annotation.elements.size()<<'\n';};
    annotations(j.visible_annotations,"visible","class");annotations(j.invisible_annotations,"invisible","class");
    if (j.nest_host) out << "Nest host: " << *j.nest_host << '\n';
    for (const auto &name : j.nest_members) out << "Nest member: " << name << '\n';
    for (const auto &name : j.permitted_subclasses) out << "Permitted subclass: " << name << '\n';
    for (const auto &component : j.record_components) {
        out << "Record component: " << component.name << ' ' << component.descriptor;
        if (component.signature) out << " signature=" << *component.signature;
        out << '\n';
    }
    for (const auto &method : j.methods) {
        out << "  " << method.name << method.descriptor << " access=" << method.access_flags;
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
        const auto parameter_annotations=[&](const auto &parameters,const char *visibility){
            if(!parameters)return;
            for(std::size_t i=0;i<parameters->size();++i)
                annotations((*parameters)[i],visibility,(std::string("method parameter ")+std::to_string(i)).c_str());
        };
        parameter_annotations(method.visible_parameter_annotations,"visible");
        parameter_annotations(method.invisible_parameter_annotations,"invisible");
        if(method.annotation_default)out<<"    annotation default: "<<*method.annotation_default<<'\n';
    }
    for(const auto &field:j.fields){annotations(field.visible_annotations,"visible","field");annotations(field.invisible_annotations,"invisible","field");}
}
} // namespace hexlab::cli
