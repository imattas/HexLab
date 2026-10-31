#include "macho_objc_view.hpp"

#include "project_view.hpp"
#include "hexlab/analysis/macho_objc_types.hpp"
#include "hexlab/database/codec.hpp"
#include <algorithm>
#include <array>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

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

std::string layout_hex(const MachOObjCIvarLayout &layout) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(layout.encoded_bytes.size() * 2);
    for (const auto byte : layout.encoded_bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::string class_ro_flag_names(std::uint32_t flags) {
    const auto names = macho_objc_class_ro_flag_names(flags);
    if (names.empty()) return "none recognized";
    std::string result;
    for (const auto &name : names) {
        if (!result.empty()) result += ',';
        result += name;
    }
    return result;
}

void mark_limit(std::vector<MachOObjCViewRow> &rows) {
    if (rows.empty()) return;
    rows.back() = {"Display limit", "", "Additional records omitted", "bounded", "desktop row cap",
                   "The scanner result is unchanged; the desktop displays at most " +
                       std::to_string(macho_objc_view_row_limit) + " rows.", {}};
}

bool add(std::vector<MachOObjCViewRow> &rows, std::string kind, std::string owner, std::string name,
         std::string status, std::string provenance, std::string details, std::optional<Address> address = {},
         std::optional<Address> code_address = {}) {
    if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); return false; }
    rows.push_back({std::move(kind), std::move(owner), std::move(name), std::move(status),
                    std::move(provenance), std::move(details), address, code_address});
    return true;
}

std::string value(const std::optional<std::string> &v) { return v.value_or("<unavailable>"); }

std::string objc_type_component(std::string_view name) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (const auto ch : name) {
        const auto byte = static_cast<unsigned char>(ch);
        if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '_') {
            result.push_back(static_cast<char>(byte));
        } else {
            result.push_back('%');
            result.push_back(hex[byte >> 4]);
            result.push_back(hex[byte & 15]);
        }
    }
    return result;
}

void add_method(std::vector<MachOObjCViewRow> &rows, const MachOObjCMethod &method,
                const std::string &owner, std::string kind) {
    std::string status = "selector=" + method.selector_status + "; types=" + method.type_status +
                         "; signature=" + method.signature_status + "; implementation=" + method.implementation_status +
                         "; encoding=" + (method.relative_encoding ? "small-relative" : "absolute-pointer");
    std::string details = "entry=" + number(method.entry.offset) + "; selector=" + value(method.selector) +
                          "; encoding=" + value(method.type_encoding) + "; implementation=" +
                          (method.implementation ? number(method.implementation->offset) : "unavailable") +
                          "; pointer=" + method.implementation_pointer_status;
    add(rows, std::move(kind), owner, value(method.selector), std::move(status),
        "method entry " + number(method.entry.offset), std::move(details),
        method.implementation ? method.implementation : std::optional<Address>{method.entry}, method.implementation);
}

void add_property(std::vector<MachOObjCViewRow> &rows, const MachOObjCProperty &property,
                  const std::string &owner, std::string kind) {
    add(rows, std::move(kind), owner, value(property.name),
        "name=" + property.name_status + "; attributes=" + property.attributes_status + "; type=" + property.type_status +
            "; backing-ivar-link=" + property.backing_ivar_link_status +
            "; getter-link=" + property.getter_link_status + "; setter-link=" + property.setter_link_status,
        "property entry " + number(property.entry.offset),
        "attributes=" + value(property.attributes) + "; encoding=" + value(property.type_encoding) +
            "; semantics=" + property.attribute_semantics_status +
            "; readonly=" + (property.readonly ? "yes" : "no") +
            "; memory=" + (property.copy ? "copy" : property.strong ? "strong" : property.weak ? "weak" : "default") +
            "; atomicity=" + (property.nonatomic ? "nonatomic" : "atomic/default") +
            "; dynamic=" + (property.dynamic ? "yes" : "no") +
            "; getter=" + property.custom_getter.value_or("default") +
            "; setter=" + property.custom_setter.value_or("default") +
            "; backing-ivar=" + property.backing_ivar.value_or("unspecified") +
            "; backing-ivar-index=" + (property.backing_ivar_index
                ? std::to_string(*property.backing_ivar_index) : "unavailable") +
            "; getter-method=" + (property.getter_method ? number(property.getter_method->offset) : "unavailable") +
            "; setter-method=" + (property.setter_method ? number(property.setter_method->offset) : "unavailable"),
        property.entry);
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
    std::string requirements = "; required-methods=" + reference.conformance_status;
    constexpr std::size_t shown_limit = 64;
    for (std::size_t i = 0; i < std::min(shown_limit, reference.requirements.size()); ++i) {
        const auto &requirement = reference.requirements[i];
        requirements += "; ";
        requirements += requirement.class_method ? "+" : "-";
        requirements += requirement.selector + "=" + requirement.status;
    }
    if (reference.requirements.size() > shown_limit)
        requirements += "; omitted-requirements=" +
            std::to_string(reference.requirements.size() - shown_limit);
    add(rows, kind, owner, value(reference.name),
        "pointer=" + reference.pointer_status + "; name=" + reference.name_status + requirements,
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
            "; superclass=" + value(c.superclass_name) + " (pointer=" + c.superclass_pointer_status +
            "; link=" + c.superclass_link_status + ")" +
            "; instance-size=" + opt_number(c.instance_size) + "; flags=" + opt_number(c.flags) +
            "; flag-semantics=" + (c.flags ? class_ro_flag_names(*c.flags) : "unavailable"),
            c.class_address ? c.class_address : std::optional<Address>{c.classlist_slot});
        add(rows, "Metaclass", owner, value(c.metaclass_name), c.metaclass_name_status +
            "; pointer=" + c.metaclass_pointer_status + "; ro-pointer=" + c.metaclass_ro_pointer_status,
            origin, "metaclass=" + (c.metaclass_address ? number(c.metaclass_address->offset) : "unavailable") +
            "; metaclass-ro=" + (c.metaclass_ro_address ? number(c.metaclass_ro_address->offset) : "unavailable"),
            c.metaclass_address ? c.metaclass_address : std::optional<Address>{c.classlist_slot});
        for (const auto &[kind, layout] : std::array<std::pair<const char *, const MachOObjCIvarLayout *>, 4>{{
                 {"Strong ivar layout", &c.ivar_layout}, {"Weak ivar layout", &c.weak_ivar_layout},
                 {"Metaclass strong ivar layout", &c.metaclass_ivar_layout},
                 {"Metaclass weak ivar layout", &c.metaclass_weak_ivar_layout}}}) {
            add(rows, kind, owner, layout_hex(*layout), layout->status + "; pointer=" + layout->pointer_status,
                layout->address ? "layout " + number(layout->address->offset) : "class_ro_t layout field",
                "pointer=" + layout->pointer_status + "; raw compressed layout bytes=" + layout_hex(*layout), layout->address);
        }
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
            "; class-properties=" + c.class_properties_status +
            (c.complete ? "; record=complete" : "; record=partial"), origin,
            "class=" + value(c.target_class_name) + "; address=" +
            (c.address ? number(c.address->offset) : "unavailable"),
            c.address ? c.address : std::optional<Address>{c.categorylist_slot});
        add_list(rows, c.instance_methods, owner, "Instance");
        add_list(rows, c.class_methods, owner, "Class");
        add_list(rows, c.protocols, owner, "Category");
        add_list(rows, c.instance_properties, owner, "Instance");
        add_list(rows, c.class_properties, owner, "Class");
    }
    for (std::size_t i = 0; i < scan.protocols.size(); ++i) {
        if (rows.size() >= macho_objc_view_row_limit) { mark_limit(rows); break; }
        const auto &p = scan.protocols[i];
        const auto owner = value(p.name) + " protocol (#" + std::to_string(i) + ")";
        const auto origin = "protolist section #" + std::to_string(p.protolist_section) + " index " +
                            std::to_string(p.protolist_index) + " slot " + number(p.protolist_slot.offset);
        add(rows, "Protocol", owner, value(p.name), p.name_status + "; pointer=" + p.pointer_status +
            "; class-properties=" + p.class_properties_status +
            (p.complete ? "; record=complete" : "; record=partial"), origin,
            "address=" + (p.address ? number(p.address->offset) : "unavailable") +
            "; runtime-size=" + opt_number(p.runtime_size),
            p.address ? p.address : std::optional<Address>{p.protolist_slot});
        add_list(rows, p.required_instance_methods, owner, "Required instance");
        add_list(rows, p.required_class_methods, owner, "Required class");
        add_list(rows, p.optional_instance_methods, owner, "Optional instance");
        add_list(rows, p.optional_class_methods, owner, "Optional class");
        add_list(rows, p.instance_properties, owner, "Instance");
        add_list(rows, p.class_properties, owner, "Class");
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

MachOObjCTypeImportPlan macho_objc_type_import_plan(
    const MachOObjCScan &scan, const std::vector<database::TypeDefinition> &existing) {
    MachOObjCTypeImportPlan plan;
    std::unordered_map<std::string, std::size_t> class_name_counts;
    class_name_counts.reserve(scan.classes.size());
    for (const auto &row : scan.classes) {
        if (row.name && row.name_status == "resolved")
            ++class_name_counts[*row.name];
    }
    std::unordered_set<std::string> reported_duplicate_names;
    bool project_type_limit_reported = false;
    const auto add_definition = [&](std::string name, types::TypePtr type,
                                    std::string section, std::uint64_t slot_index,
                                    std::uint64_t record_offset, std::uint64_t record_size) {
        if (!type) return;
        // ImportPortableTypes validates every definition before applying any of them.
        // Reject a record that the project format cannot name or encode here so it
        // does not invalidate otherwise importable classes in the same scan.
        if (name.empty() || name.size() > 512) {
            plan.skipped.push_back("Objective-C type name exceeds the project import limit");
            return;
        }
        auto encoding = types::encode(*type);
        if (!encoding) {
            plan.skipped.push_back(name + " cannot be encoded for project import: " + encoding.error().message);
            return;
        }
        database::DwarfSourceOrigin origin{"Mach-O ObjC2", std::move(section), slot_index,
                                           record_offset, std::max<std::uint64_t>(record_size, 1)};
        auto prior = std::find_if(existing.begin(), existing.end(), [&](const auto &item) { return item.name == name; });
        if (prior != existing.end()) {
            auto old_encoding = types::encode(*prior->type);
            if (old_encoding && old_encoding.value() == encoding.value() && prior->origin == origin)
                return;
            plan.conflicts.push_back(name + " already exists with different content or provenance");
            return;
        }
        if (existing.size() + plan.definitions.size() >= database::project_record_limit) {
            if (!project_type_limit_reported) {
                plan.skipped.push_back("Objective-C type import reaches the project type-record limit");
                project_type_limit_reported = true;
            }
            return;
        }
        plan.definitions.push_back({std::move(name), std::move(type), {}, std::move(origin),
                                    database::DeclarationKind::type, {}});
    };
    const auto make_methods = [](const MachOObjCList &list, bool is_static)
        -> std::optional<std::vector<types::Method>> {
        std::vector<types::Method> methods;
        for (const auto &method : list.methods) {
            if (method.selector && method.signature && method.signature_status == "parsed") {
                // The persistent type codec accepts at most 100,000 methods.
                if (methods.size() == 100000) return std::nullopt;
                methods.push_back({*method.selector, method.signature, types::MemberAccess::unknown,
                                   types::MemberDispatch::unknown, 0, is_static});
            }
        }
        return methods;
    };
    const auto add_instance_property_accessors = [&](const MachOObjCList &properties,
                                                       const std::string &class_type_name,
                                                       std::vector<types::Method> &methods,
                                                       const std::string &owner_name) {
        const auto class_reference = types::Type::named_reference(class_type_name);
        const auto self_type = class_reference
            ? types::Type::pointer(class_reference.value(), scan.pointer_bytes, scan.pointer_bytes)
            : hexlab::Result<types::TypePtr>(class_reference.error());
        const auto selector_type = types::Type::pointer(types::Type::void_type(),
                                                        scan.pointer_bytes, scan.pointer_bytes);
        const auto accessor = [&](std::string selector, types::TypePtr return_type,
                                  const types::TypePtr &argument) -> bool {
            if (selector.empty()) return false;
            const auto already_declared = std::any_of(methods.begin(), methods.end(),
                [&](const auto &method) { return method.name == selector; });
            // Explicit method encodings are authoritative over synthesized
            // property declarations.
            if (already_declared) return true;
            if (methods.size() >= 100000 || !self_type || !selector_type || !return_type)
                return false;
            std::vector<types::Parameter> parameters;
            parameters.push_back({"self", self_type.value()});
            parameters.push_back({"_cmd", selector_type.value()});
            if (argument) parameters.push_back({"value", argument});
            auto signature = types::Type::function(std::move(return_type), std::move(parameters), false);
            if (!signature) return false;
            methods.push_back({std::move(selector), signature.value(), types::MemberAccess::unknown,
                               types::MemberDispatch::unknown, 0, false});
            return true;
        };
        for (const auto &property : properties.properties) {
            if (!property.name || property.name_status != "resolved" || !property.type ||
                property.type_status != "parsed" ||
                (property.attribute_semantics_status != "parsed" &&
                 property.attribute_semantics_status != "parsed-with-unknown-attributes"))
                continue;
            const auto getter = property.custom_getter.value_or(*property.name);
            if (!accessor(getter, property.type, {})) {
                plan.skipped.push_back(owner_name + " property " + *property.name +
                                       " getter could not be represented as a method signature");
                continue;
            }
            if (property.readonly) continue;
            std::string default_setter = "set" + *property.name;
            if (default_setter.size() > 3 && default_setter[3] >= 'a' && default_setter[3] <= 'z')
                default_setter[3] = static_cast<char>(default_setter[3] - 'a' + 'A');
            default_setter.push_back(':');
            const auto setter = property.custom_setter.value_or(std::move(default_setter));
            if (!accessor(setter, types::Type::void_type(), property.type))
                plan.skipped.push_back(owner_name + " property " + *property.name +
                                       " setter could not be represented as a method signature");
        }
    };
    // Build storage independently of class-list order. The base is embedded as
    // a concrete, method-free aggregate, so later same-name project conflicts
    // cannot silently change the child's inherited storage.
    struct ClassLayout {
        types::TypePtr type;
        std::string reason;
        std::size_t depth = 0;
        bool attempted = false;
    };
    std::vector<ClassLayout> layouts(scan.classes.size());
    const auto make_layout = [&](std::size_t index, const ClassLayout *base) -> ClassLayout {
        const auto &row = scan.classes[index];
        const auto fail = [](std::string reason) -> ClassLayout { return {{}, std::move(reason), 0, true}; };
        if (!row.name || row.name_status != "resolved" || !row.class_address || class_name_counts[*row.name] != 1)
            return fail("layout lacks a unique resolved class identity");
        if (!row.instance_start || !row.instance_size || !*row.instance_size ||
            *row.instance_start > *row.instance_size)
            return fail("layout has no proven consistent instance extent");
        if (row.ivars.status != "null" && !row.ivars.status.ends_with("/extent-validated"))
            return fail("layout has no validated ivar-list extent");
        std::vector<types::Member> members;
        std::uint64_t cursor = 0;
        if (base) {
            if (!base->type)
                return fail("superclass has no validated layout: " + base->reason);
            if (!base->type->size() || *base->type->size() > *row.instance_start)
                return fail("superclass storage overlaps the declared instance start");
            members.push_back({"__objc_super", base->type, 0, {}, {}, 1});
            cursor = *base->type->size();
        }
        const auto add_opaque = [&](std::uint64_t end) {
            if (end == cursor) return true;
            if (members.size() == 100000) return false;
            auto byte = types::Type::integer("objc_byte", 1, 1, false);
            auto padding = byte ? types::Type::array(byte.value(), end - cursor)
                                : hexlab::Result<types::TypePtr>(byte.error());
            if (!padding) return false;
            members.push_back({"__objc_opaque_" + std::to_string(cursor), padding.value(), cursor, {}, {}, 1});
            cursor = end;
            return true;
        };
        for (const auto &ivar : row.ivars.ivars) {
            if (!ivar.name || ivar.name_status != "resolved" || !ivar.type_encoding ||
                ivar.type_status != "resolved" || !ivar.offset || !ivar.size ||
                *ivar.offset < *row.instance_start || *ivar.offset < cursor ||
                *ivar.offset > *row.instance_size || *ivar.size > *row.instance_size - *ivar.offset)
                return fail("ivar lacks a proven type, size, or non-overlapping instance offset");
            if (members.size() + 1 + (*ivar.offset > cursor ? 1 : 0) > 100000)
                return fail("layout exceeds the persistent aggregate-member limit");
            auto parsed = parse_macho_objc_property_encoding(*ivar.type_encoding,
                MachOObjCEncodingLimits{4096, 32, 256, scan.pointer_bytes});
            if (!parsed || parsed.value().status != "parsed" || !parsed.value().type ||
                !parsed.value().type->size() || *parsed.value().type->size() != *ivar.size)
                return fail("ivar lacks a supported type with a matching encoded size");
            if (!add_opaque(*ivar.offset))
                return fail("layout has an unrepresentable opaque storage range");
            members.push_back({*ivar.name, parsed.value().type, *ivar.offset, {}, {}, 1});
            cursor = static_cast<std::uint64_t>(*ivar.offset) + *ivar.size;
        }
        if (!add_opaque(*row.instance_size))
            return fail("layout exceeds the member limit or has an unrepresentable instance extent");
        auto structure = types::Type::structure("ObjC2.Class." + objc_type_component(*row.name),
                                                std::move(members), *row.instance_size, 1);
        if (!structure) return fail("layout cannot form a project type: " + structure.error().message);
        return {structure.value(), {}, base ? base->depth + 1 : 1, true};
    };
    constexpr std::size_t superclass_depth_limit = 32;
    for (std::size_t root = 0; root < scan.classes.size(); ++root) {
        if (layouts[root].attempted) continue;
        std::vector<std::size_t> chain;
        std::size_t current = root;
        std::string failure;
        while (!layouts[current].attempted) {
            if (std::find(chain.begin(), chain.end(), current) != chain.end()) {
                failure = "superclass chain contains a cycle";
                break;
            }
            if (chain.size() == superclass_depth_limit) {
                failure = "superclass chain exceeds the 32-class layout depth limit";
                break;
            }
            chain.push_back(current);
            const auto &row = scan.classes[current];
            if (!row.superclass_address) {
                if (row.superclass_pointer_status != "null")
                    failure = "superclass pointer is unresolved";
                else if (row.superclass_index)
                    failure = "null superclass has an inconsistent scanned-class link";
                break;
            }
            if (!row.superclass_index || *row.superclass_index >= scan.classes.size() ||
                scan.classes[*row.superclass_index].class_address != row.superclass_address) {
                failure = "superclass is not linked to a scanned class record";
                break;
            }
            current = *row.superclass_index;
        }
        if (failure.empty() && layouts[current].attempted && layouts[current].type &&
            chain.size() + layouts[current].depth > superclass_depth_limit)
            failure = "superclass chain exceeds the 32-class layout depth limit";
        if (!failure.empty()) {
            // Only this root is rejected: an ancestor reached at the depth cap
            // can still have a valid shorter chain when processed separately.
            layouts[root] = {{}, std::move(failure), 0, true};
            continue;
        }
        for (auto item = chain.rbegin(); item != chain.rend(); ++item) {
            const auto &row = scan.classes[*item];
            const auto *base = row.superclass_index ? &layouts[*row.superclass_index] : nullptr;
            layouts[*item] = make_layout(*item, base);
        }
    }
    for (std::size_t index = 0; index < scan.classes.size(); ++index) {
        const auto &row = scan.classes[index];
        if (!row.name || row.name_status != "resolved" || !row.class_address) {
            plan.skipped.push_back("Class record #" + std::to_string(index) + " lacks a resolved class name or address");
            continue;
        }
        if (class_name_counts[*row.name] > 1) {
            if (reported_duplicate_names.insert(*row.name).second)
                plan.skipped.push_back("Class name " + *row.name +
                    " appears in multiple runtime records; all matching records were skipped");
            continue;
        }
        const auto class_type_name = "ObjC2.Class." + objc_type_component(*row.name);
        const auto meta_type_name = "ObjC2.Meta." + objc_type_component(*row.name);
        auto instance_methods = make_methods(row.methods, false);
        if (instance_methods)
            add_instance_property_accessors(row.properties, class_type_name, *instance_methods,
                                            "Class " + *row.name);
        const auto import_instance_methods_without_layout = [&] {
            auto methods = *instance_methods;
            if (methods.empty()) return;
            auto incomplete = types::Type::incomplete_aggregate(types::Kind::structure, class_type_name);
            if (!incomplete) return;
            auto with_methods = types::Type::with_methods(incomplete.value(), std::move(methods));
            if (with_methods)
                add_definition(class_type_name, with_methods.value(), "__objc_classlist",
                               row.classlist_index, row.class_address->offset, 1);
        };
        if (row.metaclass_address) {
            auto class_methods = make_methods(row.class_methods, true);
            if (!class_methods) {
                plan.skipped.push_back("Class " + *row.name + " has too many parsed class methods for project storage");
            } else {
                auto meta = types::Type::incomplete_aggregate(types::Kind::structure, meta_type_name);
                if (meta) {
                    auto meta_methods = types::Type::with_methods(meta.value(), std::move(*class_methods));
                    if (meta_methods)
                        add_definition(meta_type_name, meta_methods.value(), "__objc_metaclass",
                                       row.classlist_index, row.metaclass_address->offset, 1);
                }
            }
        } else if (!row.class_methods.methods.empty()) {
            plan.skipped.push_back("Class " + *row.name + " has class methods but no validated metaclass address");
        }
        if (!instance_methods) {
            plan.skipped.push_back("Class " + *row.name + " has too many parsed instance methods for project storage");
            continue;
        }
        if (!layouts[index].type) {
            plan.skipped.push_back("Class " + *row.name + ": " + layouts[index].reason);
            import_instance_methods_without_layout();
            continue;
        }
        auto class_type = types::Type::with_methods(layouts[index].type, *instance_methods);
        if (!class_type) { plan.skipped.push_back("Class " + *row.name + " has invalid method declarations"); continue; }
        add_definition(class_type_name, class_type.value(), "__objc_classlist",
                       row.classlist_index, row.class_address->offset, *row.instance_size);

    }
    // Category declarations have their own source records and provenance.
    // Category properties describe accessors; they do not prove instance
    // storage in the target class and must not be inserted into its layout.
    std::unordered_map<std::string, std::size_t> category_name_counts;
    for (const auto &category : scan.categories) {
        if (category.name && category.name_status == "resolved" && category.target_class_name &&
            category.target_class_link_status == "linked")
            ++category_name_counts[*category.target_class_name + "\n" + *category.name];
    }
    for (std::size_t index = 0; index < scan.categories.size(); ++index) {
        const auto &category = scan.categories[index];
        if (!category.complete || !category.address || category.pointer_status != "resolved" ||
            !category.name || category.name_status != "resolved" || !category.target_class_name ||
            category.target_class_link_status != "linked") {
            plan.skipped.push_back("Category record #" + std::to_string(index) +
                                   " lacks a complete validated record, name, or scanned target class");
            continue;
        }
        if (category_name_counts[*category.target_class_name + "\n" + *category.name] != 1) {
            plan.skipped.push_back("Category " + *category.target_class_name + "(" + *category.name +
                                   ") is ambiguous across runtime records");
            continue;
        }
        auto instance_methods = make_methods(category.instance_methods, false);
        auto class_methods = make_methods(category.class_methods, true);
        if (!instance_methods || !class_methods) {
            plan.skipped.push_back("Category " + *category.name + " has too many parsed methods for project storage");
            continue;
        }

        // A property declaration provides accessor selector/type semantics but
        // no proof of backing storage. Model the accessors as instance methods
        // on the category declaration and leave class instance layout alone.
        const auto class_reference = types::Type::named_reference(
            "ObjC2.Class." + objc_type_component(*category.target_class_name));
        const auto self_type = class_reference
            ? types::Type::pointer(class_reference.value(), scan.pointer_bytes, scan.pointer_bytes)
            : hexlab::Result<types::TypePtr>(class_reference.error());
        const auto selector_type = types::Type::pointer(types::Type::void_type(),
                                                        scan.pointer_bytes, scan.pointer_bytes);
        const auto accessor = [&](std::string selector, types::TypePtr return_type,
                                  const types::TypePtr &argument) -> bool {
            if (selector.empty()) return false;
            const auto already_declared = std::any_of(instance_methods->begin(), instance_methods->end(),
                [&](const auto &method) { return method.name == selector; });
            if (already_declared) return true;
            if (instance_methods->size() >= 100000 || !self_type || !selector_type || !return_type)
                return false;
            std::vector<types::Parameter> parameters;
            parameters.push_back({"self", self_type.value()});
            parameters.push_back({"_cmd", selector_type.value()});
            if (argument) parameters.push_back({"value", argument});
            auto signature = types::Type::function(std::move(return_type), std::move(parameters), false);
            if (!signature) return false;
            instance_methods->push_back({std::move(selector), signature.value(),
                                         types::MemberAccess::unknown,
                                         types::MemberDispatch::unknown, 0, false});
            return true;
        };
        for (const auto &property : category.instance_properties.properties) {
            if (!property.name || property.name_status != "resolved" || !property.type ||
                property.type_status != "parsed" ||
                (property.attribute_semantics_status != "parsed" &&
                 property.attribute_semantics_status != "parsed-with-unknown-attributes"))
                continue;
            auto getter = property.custom_getter.value_or(*property.name);
            if (!accessor(std::move(getter), property.type, {})) {
                plan.skipped.push_back("Category " + *category.name + " property " + *property.name +
                                       " getter could not be represented as a method signature");
                continue;
            }
            if (property.readonly) continue;
            std::string default_setter = "set";
            default_setter += *property.name;
            if (!default_setter.empty() && default_setter.size() > 3 &&
                default_setter[3] >= 'a' && default_setter[3] <= 'z')
                default_setter[3] = static_cast<char>(default_setter[3] - 'a' + 'A');
            default_setter.push_back(':');
            const auto setter = property.custom_setter.value_or(std::move(default_setter));
            if (!accessor(setter, types::Type::void_type(), property.type))
                plan.skipped.push_back("Category " + *category.name + " property " + *property.name +
                                       " setter could not be represented as a method signature");
        }
        // Class properties are accessors on the category's class-method list.
        // Their receiver is the target's metaclass object; they do not add
        // storage to either the class instance or the metadata aggregate.
        const auto meta_reference = types::Type::named_reference(
            "ObjC2.Meta." + objc_type_component(*category.target_class_name));
        const auto meta_self_type = meta_reference
            ? types::Type::pointer(meta_reference.value(), scan.pointer_bytes, scan.pointer_bytes)
            : hexlab::Result<types::TypePtr>(meta_reference.error());
        const auto class_accessor = [&](std::string selector, types::TypePtr return_type,
                                        const types::TypePtr &argument) -> bool {
            if (selector.empty()) return false;
            const auto already_declared = std::any_of(class_methods->begin(), class_methods->end(),
                [&](const auto &method) { return method.name == selector; });
            if (already_declared) return true;
            if (class_methods->size() >= 100000 || !meta_self_type || !selector_type || !return_type)
                return false;
            std::vector<types::Parameter> parameters;
            parameters.push_back({"self", meta_self_type.value()});
            parameters.push_back({"_cmd", selector_type.value()});
            if (argument) parameters.push_back({"value", argument});
            auto signature = types::Type::function(std::move(return_type), std::move(parameters), false);
            if (!signature) return false;
            class_methods->push_back({std::move(selector), signature.value(),
                                      types::MemberAccess::unknown,
                                      types::MemberDispatch::unknown, 0, true});
            return true;
        };
        for (const auto &property : category.class_properties.properties) {
            if (!property.name || property.name_status != "resolved" || !property.type ||
                property.type_status != "parsed" ||
                (property.attribute_semantics_status != "parsed" &&
                 property.attribute_semantics_status != "parsed-with-unknown-attributes"))
                continue;
            const auto getter = property.custom_getter.value_or(*property.name);
            if (!class_accessor(getter, property.type, {})) {
                plan.skipped.push_back("Category " + *category.name + " class property " + *property.name +
                                       " getter could not be represented as a method signature");
                continue;
            }
            if (property.readonly) continue;
            std::string default_setter = "set";
            default_setter += *property.name;
            if (default_setter.size() > 3 && default_setter[3] >= 'a' && default_setter[3] <= 'z')
                default_setter[3] = static_cast<char>(default_setter[3] - 'a' + 'A');
            default_setter.push_back(':');
            const auto setter = property.custom_setter.value_or(std::move(default_setter));
            if (!class_accessor(setter, types::Type::void_type(), property.type))
                plan.skipped.push_back("Category " + *category.name + " class property " + *property.name +
                                       " setter could not be represented as a method signature");
        }
        if (instance_methods->empty() && class_methods->empty()) {
            plan.skipped.push_back("Category " + *category.name +
                                   " has no parsed method signatures or representable property accessors to import");
            continue;
        }
        auto type_name = "ObjC2.Category." + objc_type_component(*category.target_class_name) + "." +
                         objc_type_component(*category.name);
        auto incomplete = types::Type::incomplete_aggregate(types::Kind::structure, type_name);
        auto with_instance = incomplete
            ? types::Type::with_methods(incomplete.value(), std::move(*instance_methods))
            : hexlab::Result<types::TypePtr>(incomplete.error());
        auto with_class = with_instance
            ? types::Type::with_methods(with_instance.value(), std::move(*class_methods))
            : hexlab::Result<types::TypePtr>(with_instance.error());
        if (!with_class) {
            plan.skipped.push_back("Category " + *category.name + " methods cannot form a project type");
            continue;
        }
        const auto section = "categorylist section #" + std::to_string(category.categorylist_section);
        add_definition(std::move(type_name), with_class.value(), section, category.categorylist_index,
                       category.address->offset, 1);
    }
    // Protocol declarations have contracts but no object storage. Preserve
    // parsed required and optional signatures in an incomplete aggregate so
    // project callers can reuse the types without inventing a layout.
    std::unordered_map<std::string, std::size_t> protocol_name_counts;
    for (const auto &protocol : scan.protocols)
        if (protocol.name && protocol.name_status == "resolved")
            ++protocol_name_counts[*protocol.name];
    for (const auto &protocol : scan.protocols) {
        if (!protocol.complete || !protocol.address ||
            !protocol.name || protocol.name_status != "resolved" || protocol_name_counts[*protocol.name] != 1) {
            plan.skipped.push_back("Protocol record #" + std::to_string(protocol.protolist_index) +
                                   " lacks a unique complete record and resolved name/address");
            continue;
        }
        const auto type_name = "ObjC2.Protocol." + objc_type_component(*protocol.name);
        std::vector<types::Method> methods;
        std::optional<std::string> conflicting_selector;
        const auto append_signature = [&](std::string selector, types::TypePtr signature,
                                          bool is_static) {
            const auto duplicate = std::find_if(methods.begin(), methods.end(), [&](const auto &prior) {
                return prior.name == selector && prior.is_static == is_static;
            });
            if (duplicate != methods.end()) {
                const auto prior_encoding = types::encode(*duplicate->signature);
                const auto candidate_encoding = types::encode(*signature);
                if (!prior_encoding || !candidate_encoding || prior_encoding.value() != candidate_encoding.value())
                    conflicting_selector = std::move(selector);
                return !conflicting_selector.has_value();
            }
            if (methods.size() == 100000) return false;
            methods.push_back({std::move(selector), std::move(signature), types::MemberAccess::unknown,
                               types::MemberDispatch::unknown, 0, is_static});
            return true;
        };
        const auto append_protocol_methods = [&](const MachOObjCList &list, bool is_static) {
            for (const auto &method : list.methods) {
                if (!method.selector || !method.signature || method.signature_status != "parsed")
                    continue;
                if (!append_signature(*method.selector, method.signature, is_static)) return false;
            }
            return true;
        };
        if (!append_protocol_methods(protocol.required_instance_methods, false) ||
            !append_protocol_methods(protocol.optional_instance_methods, false) ||
            !append_protocol_methods(protocol.required_class_methods, true) ||
            !append_protocol_methods(protocol.optional_class_methods, true)) {
            if (conflicting_selector) {
                plan.conflicts.push_back("Protocol " + *protocol.name +
                    " has conflicting declarations for selector " + *conflicting_selector);
                continue;
            }
            plan.skipped.push_back("Protocol " + *protocol.name + " exceeds the persistent method limit");
            continue;
        }
        const auto id_type = types::Type::pointer(types::Type::void_type(), scan.pointer_bytes, scan.pointer_bytes);
        const auto selector_type = id_type;
        const auto add_property_accessors = [&](const MachOObjCList &list, bool is_static) {
            for (const auto &property : list.properties) {
                if (!property.name || property.name_status != "resolved" || !property.type ||
                    property.type_status != "parsed" ||
                    (property.attribute_semantics_status != "parsed" &&
                     property.attribute_semantics_status != "parsed-with-unknown-attributes"))
                    continue;
                const auto add_accessor = [&](std::string selector, types::TypePtr result,
                                              const types::TypePtr &argument) {
                    if (selector.empty()) return false;
                    if (!id_type || !selector_type || !result) return false;
                    std::vector<types::Parameter> parameters{{"self", id_type.value()},
                                                              {"_cmd", selector_type.value()}};
                    if (argument) parameters.push_back({"value", argument});
                    auto signature = types::Type::function(std::move(result), std::move(parameters), false);
                    if (!signature) return false;
                    return append_signature(std::move(selector), signature.value(), is_static);
                };
                const auto getter = property.custom_getter.value_or(*property.name);
                if (!add_accessor(getter, property.type, {})) {
                    plan.skipped.push_back("Protocol " + *protocol.name + " property " + *property.name +
                                           " getter could not be represented");
                    continue;
                }
                if (property.readonly) continue;
                std::string default_setter = "set" + *property.name;
                if (default_setter.size() > 3 && default_setter[3] >= 'a' && default_setter[3] <= 'z')
                    default_setter[3] = static_cast<char>(default_setter[3] - 'a' + 'A');
                default_setter.push_back(':');
                if (!add_accessor(property.custom_setter.value_or(std::move(default_setter)),
                                  types::Type::void_type(), property.type))
                    plan.skipped.push_back("Protocol " + *protocol.name + " property " + *property.name +
                                           " setter could not be represented");
            }
        };
        add_property_accessors(protocol.instance_properties, false);
        add_property_accessors(protocol.class_properties, true);
        if (conflicting_selector) {
            plan.conflicts.push_back("Protocol " + *protocol.name +
                " has conflicting declarations for selector " + *conflicting_selector);
            continue;
        }
        if (methods.empty()) {
            plan.skipped.push_back("Protocol " + *protocol.name + " has no parsed method signatures");
            continue;
        }
        auto incomplete = types::Type::incomplete_aggregate(types::Kind::structure, type_name);
        auto with_methods = incomplete
            ? types::Type::with_methods(incomplete.value(), std::move(methods))
            : hexlab::Result<types::TypePtr>(incomplete.error());
        if (!with_methods) {
            plan.skipped.push_back("Protocol " + *protocol.name + " methods cannot form a project type");
            continue;
        }
        const auto section = "protolist section #" + std::to_string(protocol.protolist_section);
        add_definition(type_name, with_methods.value(), section, protocol.protolist_index,
                       protocol.address->offset, protocol.runtime_size.value_or(1));
    }
    return plan;
}

} // namespace hexlab::desktop
