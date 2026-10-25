#pragma once
#include "hexlab/image/metadata.hpp"
#include <ostream>

namespace hexlab::cli {
inline void jvm_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.jvm) return;
    const auto &j = *metadata.jvm;
    out << "Java class: " << j.class_name << " version=" << j.major_version << '.' << j.minor_version
        << " access=" << j.access_flags << '\n';
    if (!j.super_name.empty()) out << "Superclass: " << j.super_name << '\n';
    out << "Interfaces: " << j.interfaces.size() << " Fields: " << j.fields.size()
        << " Methods: " << j.methods.size() << " Constant pool: " << (j.constant_pool.size() - 1) << '\n';
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
        if (method.code) out << " code=" << method.code->code_size << " max_stack=" << method.code->max_stack
                             << " max_locals=" << method.code->max_locals
                             << " exceptions=" << method.code->exception_table.size();
        else out << " native/abstract";
        out << '\n';
    }
}
} // namespace hexlab::cli
