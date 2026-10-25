#include "macho_objc_view.hpp"

#include "project_view.hpp"
#include <algorithm>

namespace hexlab::desktop {
namespace {
std::string number(std::uint64_t value) { return "0x" + [](std::uint64_t v) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    do { out.insert(out.begin(), digits[v & 15]); v >>= 4; } while (v);
    return out;
}(value); }

std::string opt_number(const std::optional<std::uint32_t> &value) {
    return value ? std::to_string(*value) : "unavailable";
}

void mark_limit(std::vector<MachOObjCViewRow> &rows) {
    if (rows.empty()) return;
    rows.back() = {"Display limit", "", "Additional records omitted", "bounded", "desktop row cap",
                   "The scanner result is unchanged; the desktop displays at most " +
                       std::to_string(macho_objc_view_row_limit) + " rows.", {}};
}

bool add(std::vector<MachOObjCViewRow> &rows, std::string kind, std::string owner, std::string name,
         std::string status, std::string provenance, std::string details, std::optional<Address> address = {}) {
    if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); return false; }
    rows.push_back({std::move(kind), std::move(owner), std::move(name), std::move(status),
                    std::move(provenance), std::move(details), address});
    return true;
}

std::string value(const std::optional<std::string> &v) { return v.value_or("<unavailable>"); }

void add_method(std::vector<MachOObjCViewRow> &rows, const MachOObjCMethod &method,
                const std::string &owner, std::string kind) {
    std::string status = "selector=" + method.selector_status + "; types=" + method.type_status +
                         "; signature=" + method.signature_status + "; implementation=" + method.implementation_status;
    std::string details = "entry=" + number(method.entry.offset) + "; selector=" + value(method.selector) +
                          "; encoding=" + value(method.type_encoding) + "; implementation=" +
                          (method.implementation ? number(method.implementation->offset) : "unavailable") +
                          "; pointer=" + method.implementation_pointer_status;
    add(rows, std::move(kind), owner, value(method.selector), std::move(status),
        "method entry " + number(method.entry.offset), std::move(details),
        method.implementation ? method.implementation : std::optional<Address>{method.entry});
}

void add_property(std::vector<MachOObjCViewRow> &rows, const MachOObjCProperty &property,
                  const std::string &owner, std::string kind) {
    add(rows, std::move(kind), owner, value(property.name),
        "name=" + property.name_status + "; attributes=" + property.attributes_status + "; type=" + property.type_status,
        "property entry " + number(property.entry.offset),
        "attributes=" + value(property.attributes) + "; encoding=" + value(property.type_encoding), property.entry);
}

void add_ivar(std::vector<MachOObjCViewRow> &rows, const MachOObjCIvar &ivar, const std::string &owner) {
    add(rows, "Ivar", owner, value(ivar.name),
        "name=" + ivar.name_status + "; type=" + ivar.type_status + "; offset=" + ivar.offset_status,
        "ivar entry " + number(ivar.entry.offset),
        "encoding=" + value(ivar.type_encoding) + "; offset=" + opt_number(ivar.offset) +
            "; offset-address=" + (ivar.offset_address ? number(ivar.offset_address->offset) : "unavailable") +
            "; size=" + opt_number(ivar.size) + "; alignment=" + opt_number(ivar.alignment), ivar.entry);
}

void add_protocol_reference(std::vector<MachOObjCViewRow> &rows, const MachOObjCProtocolReference &reference,
                            const std::string &owner, const std::string &kind) {
    add(rows, kind, owner, value(reference.name),
        "pointer=" + reference.pointer_status + "; name=" + reference.name_status,
        "protocol slot " + number(reference.slot.offset),
        "address=" + (reference.address ? number(reference.address->offset) : "unavailable") +
            "; definition-index=" + (reference.definition_index ? std::to_string(*reference.definition_index) : "unlinked"),
        reference.address ? reference.address : std::optional<Address>{reference.slot});
}

void add_list(std::vector<MachOObjCViewRow> &rows, const MachOObjCList &list, const std::string &owner,
              const std::string &prefix) {
    for (const auto &method : list.methods) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); return; }
        add_method(rows, method, owner, prefix + " method");
    }
    for (const auto &property : list.properties) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); return; }
        add_property(rows, property, owner, prefix + " property");
    }
    for (const auto &ivar : list.ivars) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); return; }
        add_ivar(rows, ivar, owner);
    }
    for (const auto &reference : list.protocol_references) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); return; }
        add_protocol_reference(rows, reference, owner, prefix + " protocol reference");
    }
}
} // namespace

std::vector<MachOObjCViewRow> macho_objc_view_rows(const MachOObjCScan &scan) {
    std::vector<MachOObjCViewRow> rows;
    rows.reserve(std::min<std::size_t>(macho_objc_view_row_limit,
        scan.classes.size() * 2 + scan.categories.size() + scan.protocols.size() + 1));
    add(rows, "Scan", "", "Objective-C runtime metadata",
        scan.complete ? "complete" : "partial", "bounded scanner result",
        "classes=" + std::to_string(scan.classes.size()) + "; categories=" +
        std::to_string(scan.categories.size()) + "; protocols=" + std::to_string(scan.protocols.size()) +
        "; metadata-bytes=" + std::to_string(scan.metadata_bytes) + "; pointer-bytes=" +
        std::to_string(scan.pointer_bytes) + (scan.reason.empty() ? "" : "; reason=" + scan.reason));

    for (std::size_t i = 0; i < scan.classes.size(); ++i) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); break; }
        const auto &c = scan.classes[i];
        const auto owner = value(c.name) + " (#" + std::to_string(i) + ")";
        const auto origin = "classlist section #" + std::to_string(c.classlist_section) + " index " +
                            std::to_string(c.classlist_index) + " slot " + number(c.classlist_slot.offset);
        add(rows, "Class", owner, value(c.name), c.name_status + "; class pointer=" + c.class_pointer_status +
            (c.complete ? "; record=complete" : "; record=partial"), origin,
            "class=" + (c.class_address ? number(c.class_address->offset) : "unavailable") +
            "; superclass=" + value(c.superclass_name) + " (" + c.superclass_pointer_status + ")" +
            "; instance-size=" + opt_number(c.instance_size) + "; flags=" + opt_number(c.flags),
            c.class_address ? c.class_address : std::optional<Address>{c.classlist_slot});
        add(rows, "Metaclass", owner, value(c.metaclass_name), c.metaclass_name_status +
            "; pointer=" + c.metaclass_pointer_status + "; ro-pointer=" + c.metaclass_ro_pointer_status,
            origin, "metaclass=" + (c.metaclass_address ? number(c.metaclass_address->offset) : "unavailable") +
            "; metaclass-ro=" + (c.metaclass_ro_address ? number(c.metaclass_ro_address->offset) : "unavailable"),
            c.metaclass_address ? c.metaclass_address : std::optional<Address>{c.classlist_slot});
        add_list(rows, c.methods, owner, "Instance");
        add_list(rows, c.class_methods, owner, "Class");
        add_list(rows, c.ivars, owner, "Instance");
        add_list(rows, c.protocols, owner, "Class");
        add_list(rows, c.properties, owner, "Instance");
    }
    for (std::size_t i = 0; i < scan.categories.size(); ++i) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); break; }
        const auto &c = scan.categories[i];
        const auto owner = value(c.name) + " category";
        const auto origin = "categorylist section #" + std::to_string(c.categorylist_section) + " index " +
                            std::to_string(c.categorylist_index) + " slot " + number(c.categorylist_slot.offset);
        add(rows, "Category", owner, value(c.name), c.name_status + "; pointer=" + c.pointer_status +
            "; target=" + c.target_class_status + "; link=" + c.target_class_link_status +
            (c.complete ? "; record=complete" : "; record=partial"), origin,
            "class=" + value(c.target_class_name) + "; address=" +
            (c.address ? number(c.address->offset) : "unavailable"),
            c.address ? c.address : std::optional<Address>{c.categorylist_slot});
        add_list(rows, c.instance_methods, owner, "Instance");
        add_list(rows, c.class_methods, owner, "Class");
        add_list(rows, c.protocols, owner, "Category");
        add_list(rows, c.instance_properties, owner, "Instance");
    }
    for (std::size_t i = 0; i < scan.protocols.size(); ++i) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); break; }
        const auto &p = scan.protocols[i];
        const auto owner = value(p.name) + " protocol (#" + std::to_string(i) + ")";
        const auto origin = "protolist section #" + std::to_string(p.protolist_section) + " index " +
                            std::to_string(p.protolist_index) + " slot " + number(p.protolist_slot.offset);
        add(rows, "Protocol", owner, value(p.name), p.name_status + "; pointer=" + p.pointer_status +
            (p.complete ? "; record=complete" : "; record=partial"), origin,
            "address=" + (p.address ? number(p.address->offset) : "unavailable"),
            p.address ? p.address : std::optional<Address>{p.protolist_slot});
        add_list(rows, p.required_instance_methods, owner, "Required instance");
        add_list(rows, p.required_class_methods, owner, "Required class");
        add_list(rows, p.optional_instance_methods, owner, "Optional instance");
        add_list(rows, p.optional_class_methods, owner, "Optional class");
        add_list(rows, p.instance_properties, owner, "Instance");
        add_list(rows, p.adopted_protocols, owner, "Adopted");
    }
    return rows;
}

wxString macho_objc_view_cell(const MachOObjCViewRow &row, int column, const Image *image) {
    switch (column) {
    case 0: return wxString::FromUTF8(row.kind.c_str());
    case 1: return wxString::FromUTF8(row.owner.c_str());
    case 2: return wxString::FromUTF8(row.name.c_str());
    case 3: return row.address ? location_text(*row.address, image) : wxString("unmapped");
    case 4: return wxString::FromUTF8(row.status.c_str());
    case 5: return wxString::FromUTF8(row.provenance.c_str());
    default: return wxString::FromUTF8(row.details.c_str());
    }
}

} // namespace hexlab::desktop
