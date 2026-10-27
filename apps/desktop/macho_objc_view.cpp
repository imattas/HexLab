#include "macho_objc_view.hpp"

#include "project_view.hpp"
#include "hexlab/analysis/macho_objc_types.hpp"
#include "hexlab/database/codec.hpp"
#include <algorithm>
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
        "name=" + property.name_status + "; attributes=" + property.attributes_status + "; type=" + property.type_status,
        "property entry " + number(property.entry.offset),
        "attributes=" + value(property.attributes) + "; encoding=" + value(property.type_encoding) +
            "; semantics=" + property.attribute_semantics_status +
            "; readonly=" + (property.readonly ? "yes" : "no") +
            "; memory=" + (property.copy ? "copy" : property.strong ? "strong" : property.weak ? "weak" : "default") +
            "; atomicity=" + (property.nonatomic ? "nonatomic" : "atomic/default") +
            "; dynamic=" + (property.dynamic ? "yes" : "no") +
            "; getter=" + property.custom_getter.value_or("default") +
            "; setter=" + property.custom_setter.value_or("default") +
            "; backing-ivar=" + property.backing_ivar.value_or("unspecified"), property.entry);
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
            "; instance-size=" + opt_number(c.instance_size) + "; flags=" + opt_number(c.flags) +
            "; flag-semantics=" + (c.flags ? class_ro_flag_names(*c.flags) : "unavailable"),
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
        const auto instance_methods = make_methods(row.methods, false);
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
        if (!row.instance_size || *row.instance_size == 0) {
            plan.skipped.push_back("Class " + *row.name + " has no proven instance extent");
            import_instance_methods_without_layout();
            continue;
        }
        const bool ivar_extent_validated = row.ivars.status == "null" ||
            row.ivars.status.ends_with("/extent-validated");
        if (!ivar_extent_validated) {
            plan.skipped.push_back("Class " + *row.name + " has no validated ivar-list extent");
            import_instance_methods_without_layout();
            continue;
        }
        std::vector<types::Member> members;
        std::uint64_t cursor = 0;
        bool valid = true;
        bool member_limit_exceeded = false;
        for (const auto &ivar : row.ivars.ivars) {
            if (!ivar.name || ivar.name_status != "resolved" || !ivar.type_encoding ||
                ivar.type_status != "resolved" || !ivar.offset || !ivar.size || *ivar.offset < cursor ||
                *ivar.offset > *row.instance_size || *ivar.size > *row.instance_size - *ivar.offset) {
                valid = false; break;
            }
            const std::size_t needed_members = 1 + (*ivar.offset > cursor ? 1 : 0);
            if (members.size() + needed_members > 100000) {
                member_limit_exceeded = true;
                valid = false;
                break;
            }
            auto parsed = parse_macho_objc_property_encoding(*ivar.type_encoding,
                MachOObjCEncodingLimits{4096, 32, 256, scan.pointer_bytes});
            if (!parsed || parsed.value().status != "parsed" || !parsed.value().type ||
                !parsed.value().type->size() || *parsed.value().type->size() != *ivar.size) {
                valid = false; break;
            }
            if (*ivar.offset > cursor) {
                auto byte = types::Type::integer("objc_byte", 1, 1, false);
                auto padding = byte ? types::Type::array(byte.value(), *ivar.offset - cursor) : hexlab::Result<types::TypePtr>(byte.error());
                if (!padding) { valid = false; break; }
                members.push_back({"__objc_opaque_" + std::to_string(cursor), padding.value(), cursor,
                                   {}, {}, 1});
            }
            members.push_back({*ivar.name, parsed.value().type, *ivar.offset, {}, {}, 1});
            cursor = static_cast<std::uint64_t>(*ivar.offset) + *ivar.size;
        }
        if (!valid) {
            plan.skipped.push_back(member_limit_exceeded
                ? "Class " + *row.name + " exceeds the persistent aggregate-member limit"
                : "Class " + *row.name + " has an ivar without a proven type, size, or non-overlapping offset");
            import_instance_methods_without_layout();
            continue;
        }
        if (cursor < *row.instance_size) {
            if (members.size() == 100000) {
                plan.skipped.push_back("Class " + *row.name + " exceeds the persistent aggregate-member limit");
                import_instance_methods_without_layout();
                continue;
            }
            auto byte = types::Type::integer("objc_byte", 1, 1, false);
            auto padding = byte ? types::Type::array(byte.value(), *row.instance_size - cursor) : hexlab::Result<types::TypePtr>(byte.error());
            if (!padding) { plan.skipped.push_back("Class " + *row.name + " has an unrepresentable instance extent"); continue; }
            members.push_back({"__objc_opaque_" + std::to_string(cursor), padding.value(), cursor, {}, {}, 1});
        }
        if (members.empty()) {
            plan.skipped.push_back("Class " + *row.name + " has no representable instance storage");
            import_instance_methods_without_layout();
            continue;
        }
        auto structure = types::Type::structure(class_type_name, std::move(members),
                                                *row.instance_size, 1);
        if (!structure) { plan.skipped.push_back("Class " + *row.name + ": " + structure.error().message); import_instance_methods_without_layout(); continue; }
        auto class_type = types::Type::with_methods(structure.value(), *instance_methods);
        if (!class_type) { plan.skipped.push_back("Class " + *row.name + " has invalid method declarations"); continue; }
        add_definition(class_type_name, class_type.value(), "__objc_classlist",
                       row.classlist_index, row.class_address->offset, *row.instance_size);

    }
    // Category declarations have their own source records and provenance. Keep
    // them as separate incomplete aggregates: merging category methods into a
    // class layout would falsely attribute those declarations to class_ro_t.
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
        if (instance_methods->empty() && class_methods->empty()) {
            plan.skipped.push_back("Category " + *category.name + " has no parsed method signatures to import");
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
    return plan;
}

} // namespace hexlab::desktop
