#include "hexlab/types/pdb_import.hpp"
#include "hexlab/core/sha256.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <tuple>

namespace hexlab::types {
namespace {
constexpr std::size_t max_odr_collision_definitions = 100'000;
constexpr std::size_t max_odr_identity_bytes = 16 * 1024 * 1024;
constexpr std::size_t max_odr_compare_pairs = 2'000'000;
constexpr std::size_t max_odr_compare_depth = 128;
bool valid_type_name(std::string_view text, std::size_t byte_limit = 512) {
    if (text.empty() || text.size() > byte_limit) return false;
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i]);
        if (first < 0x80) { ++i; continue; }
        const unsigned length = first >= 0xc2 && first <= 0xdf ? 2 :
            first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
        if (!length || text.size() - i < length) return false;
        std::uint32_t code = first & (length == 2 ? 0x1f : length == 3 ? 0x0f : 0x07);
        for (unsigned n = 1; n < length; ++n) {
            const auto next = static_cast<unsigned char>(text[i + n]);
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 0x3f);
        }
        if ((length == 2 && code < 0x80) || (length == 3 && code < 0x800) ||
            (length == 4 && code < 0x10000) || code > 0x10ffff ||
            (code >= 0xd800 && code <= 0xdfff) || code == 0) return false;
        i += length;
    }
    return true;
}

std::size_t utf8_prefix(std::string_view text, std::size_t byte_limit) {
    auto size = std::min(text.size(), byte_limit);
    while (size && size < text.size() &&
           (static_cast<unsigned char>(text[size]) & 0xc0) == 0x80) --size;
    return size;
}

Result<std::string> unique_storage_name(const CodeViewTypeRecord &record) {
    if (!valid_type_name(record.name) || !valid_type_name(record.unique_name, 4096))
        return Error{ErrorCode::unsupported, "PDB ODR collision has an invalid displayed or unique name"};
    Sha256 hash;
    const auto update_length = [&](std::size_t length) -> Result<std::uint64_t> {
        std::array<std::byte, 8> encoded{};
        for (std::size_t i = 0; i < encoded.size(); ++i)
            encoded[i] = static_cast<std::byte>((std::uint64_t{length} >> (i * 8)) & 0xff);
        return hash.update(encoded);
    };
    const auto display = std::as_bytes(std::span(record.name.data(), record.name.size()));
    if (!update_length(record.name.size()) || !hash.update(display))
        return Error{ErrorCode::overflow, "PDB type name exceeds the hash input limit"};
    const auto kind = static_cast<std::byte>(record.kind);
    if (!hash.update(std::span<const std::byte>(&kind, 1)))
        return Error{ErrorCode::overflow, "PDB type identity exceeds the hash input limit"};
    const auto identity = std::as_bytes(std::span(record.unique_name.data(), record.unique_name.size()));
    if (!update_length(record.unique_name.size()) || !hash.update(identity))
        return Error{ErrorCode::overflow, "PDB unique name exceeds the hash input limit"};
    const auto suffix = " [CodeView-" + digest_hex(hash.digest()) + "]";
    constexpr std::size_t max_name_bytes = 512;
    const auto prefix_bytes = utf8_prefix(record.name, max_name_bytes - suffix.size());
    return record.name.substr(0, prefix_bytes) + suffix;
}

Result<TypePtr> primitive(std::uint32_t index) {
    if (index >= 0x100 && index < 0x1000) {
        const auto mode = static_cast<std::uint8_t>((index >> 8) & 0x0f);
        const auto pointee_index = index & 0xff;
        std::uint64_t pointer_bytes = 0;
        switch (mode) {
        case 0x04: pointer_bytes = 4; break;  // NearPointer32
        case 0x05: pointer_bytes = 6; break;  // FarPointer32
        case 0x06: pointer_bytes = 8; break;  // NearPointer64
        case 0x07: pointer_bytes = 16; break; // NearPointer128
        default:
            return Error{ErrorCode::unsupported,
                         "PDB simple pointer type has a target-dependent or unsupported pointer mode"};
        }
        auto pointee = primitive(pointee_index);
        if (!pointee) return pointee.error();
        return Type::pointer(pointee.value(), pointer_bytes, std::min<std::uint64_t>(pointer_bytes, 8));
    }
    struct Scalar { std::uint32_t index; const char *name; std::uint8_t bytes; bool sign; };
    static constexpr Scalar scalars[] = {
        {0x10,"char",1,true},{0x20,"unsigned char",1,false},
        {0x11,"short",2,true},{0x21,"unsigned short",2,false},
        {0x12,"int32_t",4,true},{0x22,"uint32_t",4,false},
        {0x13,"int64_t",8,true},{0x23,"uint64_t",8,false},
        {0x68,"int8_t",1,true},{0x69,"uint8_t",1,false},
        {0x70,"int16_t",2,true},{0x71,"uint16_t",2,false},
        {0x72,"int32_t",4,true},{0x73,"uint32_t",4,false},
        {0x74,"int32_t",4,true},{0x75,"uint32_t",4,false},
        {0x76,"int64_t",8,true},{0x77,"uint64_t",8,false},
        {0x03,"void",0,false}
    };
    for (const auto &scalar : scalars) if (index == scalar.index) {
        if (!scalar.bytes) return Type::void_type();
        return Type::integer(scalar.name, scalar.bytes, scalar.bytes, scalar.sign);
    }
    if (index == 0x30) return Type::boolean(1, 1);
    if (index == 0x31) return Type::boolean(2, 2);
    if (index == 0x32) return Type::boolean(4, 4);
    if (index == 0x33) return Type::boolean(8, 8);
    if (index == 0x40) return Type::floating("float", 4, 4);
    if (index == 0x41) return Type::floating("double", 8, 8);
    return Error{ErrorCode::unsupported, "PDB import encountered an unsupported CodeView primitive type"};
}

Result<FunctionConvention> function_convention(std::uint8_t value) {
    switch (value) {
    case 0x00: return FunctionConvention::c_decl;       // CV_CALL_NEAR_C
    case 0x04: return FunctionConvention::fastcall;    // CV_CALL_NEAR_FAST
    case 0x07: return FunctionConvention::stdcall;     // CV_CALL_NEAR_STD
    case 0x0b: return FunctionConvention::thiscall;   // CV_CALL_THISCALL
    case 0x18: return FunctionConvention::vectorcall; // CV_CALL_NEAR_VECTOR
    default: return Error{ErrorCode::unsupported, "PDB procedure uses an unsupported CodeView calling convention"};
    }
}
}

Result<PdbTypeImportResult> import_pdb_type_graph(const PdbTypeGraph &graph) {
    using TypeKey = std::pair<std::uint8_t, std::uint32_t>;
    std::map<TypeKey, const PdbTypeGraphNode *> nodes;
    for (const auto &node : graph.nodes)
        if (!nodes.emplace(TypeKey{node.name_space, node.record.index}, &node).second)
            return Error{ErrorCode::malformed, "PDB type graph contains duplicate type indices"};
    enum class Visit { active, done };
    std::map<TypeKey, Visit> visits;
    std::map<TypeKey, TypePtr> converted;
    PdbTypeImportResult result;
    std::set<std::string, std::less<>> ambiguous_names;
    const auto aggregate_identity_kind = [](CodeViewTypeKind kind) {
        return kind == CodeViewTypeKind::structure || kind == CodeViewTypeKind::class_type ||
               kind == CodeViewTypeKind::union_type || kind == CodeViewTypeKind::enumeration;
    };
    std::map<std::string, std::vector<const PdbTypeGraphNode *>, std::less<>> full_definitions_by_name;
    for (const auto &node : graph.nodes) {
        const auto &record = node.record;
        if (!record.forward_declaration && record.kind != CodeViewTypeKind::unsupported &&
            record.kind != CodeViewTypeKind::field_list && record.kind != CodeViewTypeKind::argument_list &&
            record.kind != CodeViewTypeKind::method_list && valid_type_name(record.name))
            full_definitions_by_name[record.name].push_back(&node);
    }
    // Compare repeated complete UDT identities structurally before allowing
    // them to share a storage name. Type::id() is only a hash and cannot prove
    // equality. References are compared across namespace-aware graph nodes.
    std::map<std::pair<TypeKey, TypeKey>, bool> odr_pair_cache;
    std::set<std::pair<TypeKey, TypeKey>> odr_active_pairs;
    std::size_t odr_compared_pairs = 0;
    bool odr_comparison_exhausted = false;
    const auto resolve_odr_reference = [&](TypeKey source, std::uint32_t ref) -> std::optional<TypeKey> {
        if (ref < 0x1000) return std::nullopt;
        const auto ns = static_cast<std::uint8_t>(ref >> 24);
        const auto index = ref & 0x00ffffffu;
        const TypeKey local{ns ? ns : source.first, index};
        if (nodes.contains(local)) return local;
        const TypeKey same_namespace{source.first, ref};
        if (nodes.contains(same_namespace)) return same_namespace;
        return std::nullopt;
    };
    std::function<bool(TypeKey, TypeKey, std::size_t)> same_node;
    std::function<bool(TypeKey, std::uint32_t, TypeKey, std::uint32_t, std::size_t)> same_ref;
    same_ref = [&](TypeKey a, std::uint32_t ar, TypeKey b, std::uint32_t br, std::size_t depth) {
        if (ar < 0x1000 || br < 0x1000) return ar == br;
        const auto ak = resolve_odr_reference(a, ar), bk = resolve_odr_reference(b, br);
        return ak && bk && same_node(*ak, *bk, depth + 1);
    };
    same_node = [&](TypeKey a, TypeKey b, std::size_t depth) {
        if (a == b) return true;
        if (depth > max_odr_compare_depth || odr_compared_pairs >= max_odr_compare_pairs) {
            odr_comparison_exhausted = true; return false;
        }
        const auto pair = a < b ? std::pair{a,b} : std::pair{b,a};
        if (const auto cached = odr_pair_cache.find(pair); cached != odr_pair_cache.end()) return cached->second;
        if (odr_active_pairs.contains(pair)) return true; // coinductive cycle; outer frames compare remaining edges
        const auto ai = nodes.find(a), bi = nodes.find(b);
        if (ai == nodes.end() || bi == nodes.end()) return false;
        ++odr_compared_pairs; odr_active_pairs.insert(pair);
        const auto &x = ai->second->record, &y = bi->second->record;
        // These records do not retain enough decoded payload to establish
        // structural identity. Exact same-node references returned above.
        if (x.kind == CodeViewTypeKind::unsupported || y.kind == CodeViewTypeKind::unsupported ||
            x.kind == CodeViewTypeKind::type_server || y.kind == CodeViewTypeKind::type_server) {
            odr_active_pairs.erase(pair);
            odr_pair_cache.emplace(pair, false);
            return false;
        }
        bool equal = x.leaf == y.leaf && x.kind == y.kind && x.name == y.name && x.unique_name == y.unique_name &&
            x.forward_declaration == y.forward_declaration && x.size == y.size &&
            x.pointer_kind == y.pointer_kind && x.pointer_mode == y.pointer_mode && x.pointer_options == y.pointer_options &&
            x.qualifier_bits == y.qualifier_bits && x.bitfield_width == y.bitfield_width && x.bitfield_position == y.bitfield_position &&
            x.calling_convention == y.calling_convention && x.function_options == y.function_options &&
            x.vftable_vfptr_offset == y.vftable_vfptr_offset && x.vftable_slot_kinds == y.vftable_slot_kinds &&
            x.vftable_names == y.vftable_names && x.this_adjustment == y.this_adjustment && x.parameter_count == y.parameter_count &&
            x.fields.size() == y.fields.size() && x.field_list_continuations.size() == y.field_list_continuations.size();
        if (equal) equal = same_ref(a,x.referenced_type,b,y.referenced_type,depth) &&
            same_ref(a,x.field_list,b,y.field_list,depth) && same_ref(a,x.derivation_list,b,y.derivation_list,depth) &&
            same_ref(a,x.vtable_shape,b,y.vtable_shape,depth) && same_ref(a,x.underlying_type,b,y.underlying_type,depth) &&
            same_ref(a,x.member_class_type,b,y.member_class_type,depth) && same_ref(a,x.member_this_type,b,y.member_this_type,depth) &&
            same_ref(a,x.vftable_complete_class_type,b,y.vftable_complete_class_type,depth) &&
            same_ref(a,x.vftable_overridden_type,b,y.vftable_overridden_type,depth);
        const auto &xf = ai->second->expanded_fields.empty() ? x.fields : ai->second->expanded_fields;
        const auto &yf = bi->second->expanded_fields.empty() ? y.fields : bi->second->expanded_fields;
        if (equal) equal = xf.size() == yf.size();
        for (std::size_t i = 0; equal && i < xf.size(); ++i) {
            const auto &f=xf[i], &g=yf[i];
            equal = f.leaf==g.leaf && f.attributes==g.attributes && f.offset==g.offset && f.name==g.name && f.value==g.value &&
                same_ref(a,f.type,b,g.type,depth) && same_ref(a,f.auxiliary_type,b,g.auxiliary_type,depth);
        }
        if (equal) for (std::size_t i=0;i<x.field_list_continuations.size();++i)
            if (!same_ref(a,x.field_list_continuations[i],b,y.field_list_continuations[i],depth)) { equal=false; break; }
        odr_active_pairs.erase(pair);
        // A successful result may have used the coinductive active-pair rule;
        // avoid memoizing it because a later mismatch in the enclosing cycle
        // must not turn that provisional assumption into a proof.
        if (!equal) odr_pair_cache.emplace(pair,false);
        return equal;
    };
    std::map<std::string_view, std::vector<const PdbTypeGraphNode *>, std::less<>> definitions_by_odr;
    for (const auto &node : graph.nodes) {
        const auto &r=node.record;
        if (!r.forward_declaration && aggregate_identity_kind(r.kind) && valid_type_name(r.name) && valid_type_name(r.unique_name,4096))
            definitions_by_odr[std::string_view{r.unique_name}].push_back(&node);
    }
    std::set<std::string_view, std::less<>> equivalent_odr_names;
    for (const auto &[identity, defs] : definitions_by_odr) {
        if (defs.size() < 2) continue;
        bool equivalent=true;
        for (std::size_t i=1;i<defs.size();++i)
            if (defs[i]->record.kind != defs.front()->record.kind || defs[i]->record.name != defs.front()->record.name ||
                !same_node({defs.front()->name_space,defs.front()->record.index},{defs[i]->name_space,defs[i]->record.index},0)) { equivalent=false; break; }
        if (equivalent && !odr_comparison_exhausted) equivalent_odr_names.insert(identity);
        else for (const auto *def:defs) ambiguous_names.insert(def->record.name);
    }
    std::map<TypeKey, std::string> storage_names;
    std::map<std::string, std::vector<const PdbTypeGraphNode *>, std::less<>> generated_by_name;
    std::set<std::string, std::less<>> reserved_names;
    std::size_t generated_definition_count = 0;
    std::size_t generated_identity_bytes = 0;
    for (const auto &[display, definitions] : full_definitions_by_name) {
        if (ambiguous_names.contains(display)) continue;
        if (definitions.size() == 1) {
            storage_names.emplace(TypeKey{definitions.front()->name_space, definitions.front()->record.index}, display);
            reserved_names.insert(display);
            continue;
        }
        bool uniquely_identified = std::all_of(definitions.begin(), definitions.end(), [&](const auto *node) {
            return aggregate_identity_kind(node->record.kind) && valid_type_name(node->record.name) &&
                   valid_type_name(node->record.unique_name, 4096);
        });
        if (!uniquely_identified) {
            ambiguous_names.insert(display);
            continue;
        }
        std::size_t group_identity_bytes = 0;
        bool within_budget = definitions.size() <= max_odr_collision_definitions - generated_definition_count;
        for (const auto *node : definitions) {
            const auto record_name_bytes = node->record.unique_name.size() + node->record.name.size();
            if (record_name_bytes > max_odr_identity_bytes - group_identity_bytes) {
                within_budget = false;
                break;
            }
            group_identity_bytes += record_name_bytes;
        }
        if (group_identity_bytes > max_odr_identity_bytes - generated_identity_bytes) within_budget = false;
        if (!within_budget) {
            ambiguous_names.insert(display);
            continue;
        }
        generated_definition_count += definitions.size();
        generated_identity_bytes += group_identity_bytes;
        for (const auto *node : definitions) {
            const auto key = TypeKey{node->name_space, node->record.index};
            auto name = unique_storage_name(node->record);
            if (!name) { uniquely_identified = false; break; }
            storage_names.emplace(key, name.value());
            generated_by_name[name.value()].push_back(node);
        }
        if (!uniquely_identified) {
            ambiguous_names.insert(display);
            for (const auto *node : definitions) storage_names.erase({node->name_space, node->record.index});
        }
    }
    for (const auto &node : graph.nodes) {
        if (!node.record.forward_declaration || node.canonical_index || node.record.name.empty() ||
            !node.record.unique_name.empty() || ambiguous_names.contains(node.record.name)) continue;
        if (!full_definitions_by_name.contains(node.record.name)) reserved_names.insert(node.record.name);
    }
    // Hashed storage names are deterministic; still reject hash/prefix/name
    // collisions rather than allowing a shared project storage identity.
    for (const auto &[name, entries] : generated_by_name) {
        const bool same_odr_identity = entries.size() > 1 && std::all_of(entries.begin(), entries.end(), [&](const auto *entry) {
            return entry->record.unique_name == entries.front()->record.unique_name &&
                entry->record.kind == entries.front()->record.kind && entry->record.name == entries.front()->record.name &&
                equivalent_odr_names.contains(entry->record.unique_name);
        });
        if (reserved_names.contains(name) || (entries.size() > 1 && !same_odr_identity))
            for (const auto *entry : entries) ambiguous_names.insert(entry->record.name);
    }
    for (const auto &generated : generated_by_name)
        for (const auto *entry : generated.second)
            if (ambiguous_names.contains(entry->record.name))
                for (const auto *node : full_definitions_by_name[entry->record.name])
                    storage_names.erase({node->name_space, node->record.index});
    for (const auto &node : graph.nodes) {
        if (!node.record.forward_declaration || node.record.name.empty()) continue;
        const TypeKey key{node.name_space, node.record.index};
        if (node.canonical_index) {
            const auto canonical = storage_names.find({node.name_space, node.canonical_index});
            if (canonical != storage_names.end()) storage_names.emplace(key, canonical->second);
        } else if (!ambiguous_names.contains(node.record.name) && node.record.unique_name.empty()) {
            const auto same_display = full_definitions_by_name.find(node.record.name);
            if (same_display != full_definitions_by_name.end() && same_display->second.size() == 1) {
                if (same_display->second.front()->record.kind != node.record.kind) continue;
                const auto existing = storage_names.find({same_display->second.front()->name_space,
                                                          same_display->second.front()->record.index});
                if (existing != storage_names.end()) {
                    storage_names.emplace(key, existing->second);
                    continue;
                }
            } else if (same_display != full_definitions_by_name.end() && !same_display->second.empty()) {
                continue; // A display-name-only forward is ambiguous across ODR definitions.
            }
            if (same_display == full_definitions_by_name.end() || same_display->second.empty()) {
                storage_names.emplace(key, node.record.name);
                reserved_names.insert(node.record.name);
            }
        }
    }
    const auto forward_reference = [&](const CodeViewTypeRecord& record, TypeKey key) -> Result<TypePtr> {
        const bool named_aggregate = record.kind == CodeViewTypeKind::structure ||
            record.kind == CodeViewTypeKind::class_type || record.kind == CodeViewTypeKind::union_type;
        if (!named_aggregate || !valid_type_name(record.name))
            return Error{ErrorCode::unsupported,
                         "PDB forward declaration has no usable named aggregate identity"};
        const auto name = storage_names.find(key);
        if (name == storage_names.end())
            return Error{ErrorCode::unsupported, "PDB forward declaration has no unambiguous storage identity"};
        return Type::named_reference(name->second);
    };
    std::function<Result<TypePtr>(std::uint8_t, std::uint32_t)> convert =
        [&](std::uint8_t source_namespace, std::uint32_t encoded_index) -> Result<TypePtr> {
        if (encoded_index < 0x1000) return primitive(encoded_index);
        const auto encoded_namespace = static_cast<std::uint8_t>(encoded_index >> 24);
        const auto target_namespace = encoded_namespace ? encoded_namespace : source_namespace;
        const auto index = encoded_index & 0x00ffffffu;
        const TypeKey key{target_namespace, index};
        if (const auto found = converted.find(key); found != converted.end()) return found->second;
        const auto found = nodes.find(key);
        if (found == nodes.end())
            return Error{target_namespace == source_namespace ? ErrorCode::malformed : ErrorCode::unsupported,
                target_namespace == source_namespace
                    ? "PDB type reference is unresolved in its own TPI namespace"
                    : "PDB type reference targets an unresolved external TPI namespace"};
        const auto &node = *found->second;
        const auto &record = node.record;
        if (aggregate_identity_kind(record.kind) && !record.name.empty() &&
            ambiguous_names.contains(record.name))
            return Error{ErrorCode::unsupported, "PDB aggregate has an ambiguous CodeView identity"};
        if (const auto visit = visits.find(key); visit != visits.end() && visit->second == Visit::active) {
            const auto &active_record = node.record;
            if (!active_record.name.empty() && (active_record.kind == CodeViewTypeKind::structure ||
                active_record.kind == CodeViewTypeKind::class_type || active_record.kind == CodeViewTypeKind::union_type))
                return forward_reference(active_record, key);
            return Error{ErrorCode::unsupported, "PDB recursive type reference is not to a named aggregate"};
        }
        if (node.canonical_index && node.canonical_index != index) {
            if (!nodes.contains({target_namespace, node.canonical_index})) {
                if (record.forward_declaration) {
                    auto reference = forward_reference(record, key);
                    if (!reference) return reference.error();
                    converted.emplace(key, reference.value());
                    return reference.value();
                }
                return Error{ErrorCode::malformed, "PDB forward type has an unresolved canonical definition"};
            }
            auto canonical = convert(target_namespace, node.canonical_index);
            if (!canonical) return canonical.error();
            converted.emplace(key, canonical.value());
            return canonical.value();
        }
        if (record.forward_declaration) {
            auto reference = forward_reference(record, key);
            if (!reference) return reference.error();
            converted.emplace(key, reference.value());
            return reference.value();
        }
        visits[key] = Visit::active;
        const auto fail = [&](Error error) -> Result<TypePtr> {
            visits.erase(key);
            return error;
        };
        Result<TypePtr> made = Error{ErrorCode::unsupported, "PDB type kind is outside the import subset"};
        switch (record.kind) {
        case CodeViewTypeKind::primitive: made = primitive(record.leaf); break;
        case CodeViewTypeKind::typedef_type: made = convert(target_namespace, record.referenced_type); break;
        case CodeViewTypeKind::modifier: {
            if (!record.qualifier_bits || record.pointer_options != 0 || (record.qualifier_bits & ~std::uint8_t{3}))
                return fail(Error{ErrorCode::unsupported, "PDB LF_MODIFIER uses an unsupported or empty modifier set"});
            auto base = convert(target_namespace, record.referenced_type);
            if (!base) return fail(base.error());
            made = Type::qualified(base.value(), record.qualifier_bits);
            break;
        }
        case CodeViewTypeKind::array: {
            auto element = convert(target_namespace, record.referenced_type);
            if (!element) return fail(element.error());
            if (!record.size || !element.value()->size() || !*element.value()->size() || record.size % *element.value()->size())
                return fail(Error{ErrorCode::unsupported, "PDB array has an incomplete element, zero length, or incompatible size"});
            made = Type::array(element.value(), record.size / *element.value()->size());
            break;
        }
        case CodeViewTypeKind::structure:
        case CodeViewTypeKind::class_type:
        case CodeViewTypeKind::union_type: {
            std::vector<Member> members;
            std::uint64_t alignment = 1;
            std::set<std::string, std::less<>> names;
            std::map<std::string, std::size_t, std::less<>> virtual_base_names;
            for (const auto &field : node.expanded_fields) {
                const bool fixed_base = field.leaf == 0x1400 || field.leaf == 0x151a;
                const bool virtual_base = field.leaf == 0x1401 || field.leaf == 0x1402;
                if (field.leaf != 0x150d && !fixed_base && !virtual_base) continue;
                const auto access_bits = field.attributes & 3;
                const auto access = access_bits == 1 ? MemberAccess::private_ :
                                    access_bits == 2 ? MemberAccess::protected_ :
                                    access_bits == 3 ? MemberAccess::public_ : MemberAccess::unknown;
                if ((fixed_base || virtual_base) && record.kind == CodeViewTypeKind::union_type)
                    return fail(Error{ErrorCode::unsupported, "PDB union contains a base-class subobject"});
                std::string member_name = field.name;
                const auto field_namespace_tag = static_cast<std::uint8_t>(field.type >> 24);
                const auto field_namespace = field_namespace_tag ? field_namespace_tag : target_namespace;
                const auto field_index = field.type & 0x00ffffffu;
                if (fixed_base || virtual_base) {
                    const auto base = nodes.find({field_namespace, field_index});
                    if (base == nodes.end() || base->second->record.name.empty())
                        return fail(Error{ErrorCode::unsupported, "PDB base class is unresolved or unnamed"});
                    if (base->second->record.kind != CodeViewTypeKind::structure &&
                        base->second->record.kind != CodeViewTypeKind::class_type)
                        return fail(Error{ErrorCode::unsupported, "PDB base type is not a class or structure"});
                    if (virtual_base) {
                        auto &ordinal = virtual_base_names[base->second->record.name];
                        ++ordinal;
                        member_name = "$vbase$" + base->second->record.name;
                        if (ordinal > 1) member_name += "#" + std::to_string(ordinal);
                    } else {
                        member_name = "$base$" + base->second->record.name;
                    }
                }
                std::optional<std::uint32_t> bit_width, bit_offset;
                auto member_type_index = field.type;
                if (const auto bitfield = nodes.find({field_namespace, field_index}); bitfield != nodes.end() &&
                    bitfield->second->record.kind == CodeViewTypeKind::bitfield) {
                    const auto &bits = bitfield->second->record;
                    bit_width = bits.bitfield_width;
                    bit_offset = bits.bitfield_position;
                    member_type_index = bits.referenced_type;
                }
                auto member = convert(target_namespace, member_type_index);
                if (!member) return fail(member.error());
                if (virtual_base) {
                    const auto vbptr_namespace_tag = static_cast<std::uint8_t>(field.auxiliary_type >> 24);
                    const auto vbptr_namespace = vbptr_namespace_tag ? vbptr_namespace_tag : target_namespace;
                    auto vbptr_type = convert(vbptr_namespace, field.auxiliary_type & 0x00ffffffu);
                    if (!vbptr_type) return fail(vbptr_type.error());
                    const Type *vbptr_base = vbptr_type.value().get();
                    while (vbptr_base && vbptr_base->kind() == Kind::qualified)
                        vbptr_base = vbptr_base->element().get();
                    if (!vbptr_base || vbptr_base->kind() != Kind::pointer || !vbptr_base->size() ||
                        field.offset > record.size || *vbptr_base->size() > record.size - field.offset)
                        return fail(Error{ErrorCode::unsupported,
                            "PDB virtual base has an invalid vbptr type or vbptr field extent"});
                    if (member_name.empty() || !names.insert(member_name).second)
                        return fail(Error{ErrorCode::unsupported, "PDB aggregate has an ambiguous virtual base name"});
                    alignment = std::max(alignment, vbptr_base->alignment());
                    Member::VirtualBaseLocation location{vbptr_type.value(), field.offset, field.value,
                                                         field.leaf == 0x1402};
                    members.push_back({std::move(member_name), member.value(), 0, {}, {}, {}, std::move(location), access});
                    continue;
                }
                if (!member.value()->size() || field.offset > record.size || *member.value()->size() > record.size - field.offset)
                    return fail(Error{ErrorCode::unsupported,
                        "PDB member '" + field.name + "' in '" + record.name + "' at offset " +
                        std::to_string(field.offset) + " with size " +
                        std::to_string(member.value()->size().value_or(0)) + " exceeds aggregate size " +
                        std::to_string(record.size)});
                if (member_name.empty() || !names.insert(member_name).second)
                    return fail(Error{ErrorCode::unsupported, "PDB aggregate has an unnamed or duplicate data member"});
                alignment = std::max(alignment, member.value()->alignment());
                members.push_back({std::move(member_name), member.value(), record.kind == CodeViewTypeKind::union_type ? 0 : field.offset,
                                   bit_width, bit_offset, {}, {}, access});
            }
            auto aggregate = record.kind == CodeViewTypeKind::union_type
                ? Type::union_type(record.name, std::move(members), record.size, alignment)
                : Type::structure(record.name, std::move(members), record.size, alignment);
            if (!aggregate)
                return fail(Error{ErrorCode::unsupported,
                    "PDB aggregate '" + record.name + "' is not representable in the project type model: " +
                    aggregate.error().message});
            made = aggregate.value();
            break;
        }
        case CodeViewTypeKind::enumeration: {
            auto underlying = convert(target_namespace, record.underlying_type);
            if (!underlying) return fail(underlying.error());
            std::vector<Enumerator> values;
            for (const auto &field : node.expanded_fields) {
                if (field.leaf != 0x1502)
                    return fail(Error{ErrorCode::unsupported, "PDB enum contains an unsupported field-list entry"});
                values.push_back({field.name, field.value});
            }
            if (values.empty())
                return fail(Error{ErrorCode::unsupported, "PDB enum has no enumerators"});
            made = Type::enumeration_with_values(record.name, underlying.value(), std::move(values));
            break;
        }
        case CodeViewTypeKind::pointer: {
            // The project model represents ordinary object pointers. CodeView
            // reference and member-pointer modes have different source semantics.
            const bool flat_pointer = record.pointer_kind == 0x00 || record.pointer_kind == 0x0a ||
                                      record.pointer_kind == 0x0c;
            if (record.pointer_mode != 0 || !flat_pointer || !record.size ||
                (record.size & (record.size - 1)) != 0 ||
                (record.pointer_options & ~std::uint32_t{0x1700}) != 0)
                return fail(Error{ErrorCode::unsupported, "PDB pointer uses an unsupported kind, mode, or size"});
            auto pointee = convert(target_namespace, record.referenced_type);
            if (!pointee) return fail(pointee.error());
            auto pointer = Type::pointer(pointee.value(), record.size, record.size);
            if (!pointer) return fail(pointer.error());
            const auto pointer_qualifiers = static_cast<std::uint8_t>(record.qualifier_bits & 7);
            made = pointer_qualifiers ? Type::qualified(pointer.value(), pointer_qualifiers) : pointer;
            break;
        }
        case CodeViewTypeKind::bitfield: {
            if (!record.bitfield_width)
                return fail(Error{ErrorCode::unsupported, "PDB bitfield has zero width"});
            made = convert(target_namespace, record.referenced_type);
            break;
        }
        case CodeViewTypeKind::procedure:
        case CodeViewTypeKind::member_function: {
            if (record.function_options & ~std::uint8_t{0x07})
                return fail(Error{ErrorCode::unsupported, "PDB procedure uses unsupported function option flags"});
            auto convention = function_convention(record.calling_convention);
            if (!convention) return fail(convention.error());
            auto return_type = convert(target_namespace, record.referenced_type);
            if (!return_type) return fail(return_type.error());
            const auto arg_namespace_byte = static_cast<std::uint8_t>(record.field_list >> 24);
            const auto arg_namespace = arg_namespace_byte ? arg_namespace_byte : target_namespace;
            const auto arg_index = record.field_list & 0x00ffffffu;
            const auto argument_list = nodes.find({arg_namespace, arg_index});
            if (argument_list == nodes.end() || argument_list->second->record.kind != CodeViewTypeKind::argument_list)
                return fail(Error{ErrorCode::unsupported, "PDB function argument list is missing or unresolved"});
            const auto &arguments = argument_list->second->record.fields;
            bool variadic = false;
            std::size_t parameter_count = arguments.size();
            if (!arguments.empty() && arguments.back().type == 0) {
                if (arguments.size() == 1)
                    return fail(Error{ErrorCode::unsupported, "PDB function has an unprototyped argument list"});
                variadic = true;
                --parameter_count;
            }
            if (parameter_count != record.parameter_count)
                return fail(Error{ErrorCode::malformed, "PDB function parameter count disagrees with its argument list"});
            std::vector<Parameter> parameters;
            parameters.reserve(parameter_count);
            for (std::size_t i = 0; i < parameter_count; ++i) {
                if (arguments[i].type == 0)
                    return fail(Error{ErrorCode::malformed, "PDB variadic argument marker is not the final argument"});
                auto argument_type = convert(arg_namespace, arguments[i].type);
                if (!argument_type) return fail(argument_type.error());
                parameters.push_back({"arg" + std::to_string(i), argument_type.value()});
            }
            made = Type::function(return_type.value(), std::move(parameters), variadic, convention.value());
            break;
        }
        case CodeViewTypeKind::argument_list:
            return fail(Error{ErrorCode::unsupported, "PDB argument lists are not source-level types"});
        default: break;
        }
        if (!made) return fail(made.error());
        visits[key] = Visit::done;
        converted.emplace(key, made.value());
        return made.value();
    };

    // Import complete records first so an opaque forward declaration never
    // shadows a full definition with the same CodeView name.
    for (const bool forward_pass : {false, true}) {
        for (const auto &node : graph.nodes) {
            const auto &record = node.record;
            if (record.kind == CodeViewTypeKind::field_list ||
                record.kind == CodeViewTypeKind::argument_list ||
                record.kind == CodeViewTypeKind::method_list) continue;
            if (record.forward_declaration != forward_pass) continue;
            if (record.kind == CodeViewTypeKind::unsupported) {
                ++result.skipped_unsupported;
                continue;
            }
            if (!record.name.empty() && !valid_type_name(record.name)) {
                ++result.skipped_unsupported;
                continue;
            }
            if (ambiguous_names.contains(record.name)) {
                ++result.skipped_ambiguous;
                continue;
            }
            const auto storage = storage_names.find({node.name_space, record.index});
            if (!record.name.empty() && storage == storage_names.end()) {
                ++result.skipped_ambiguous;
                continue;
            }
            auto type = convert(node.name_space, record.index);
            if (!type) {
                if (type.error().code == ErrorCode::unsupported) {
                    ++result.skipped_unsupported;
                    continue;
                }
                return type.error();
            }
            if (record.name.empty()) {
                if (record.kind != CodeViewTypeKind::procedure &&
                    record.kind != CodeViewTypeKind::member_function) ++result.skipped_unnamed;
                continue;
            }
            const auto &name = storage->second;
            if (forward_pass && result.definitions.contains(name)) {
                ++result.skipped_duplicates;
                continue;
            }
            auto [existing, inserted] = result.definitions.emplace(name, type.value());
            if (!inserted) {
                if (existing->second->id() == type.value()->id()) {
                    ++result.skipped_duplicates;
                } else {
                    result.definitions.erase(existing);
                    ambiguous_names.insert(record.name);
                    ++result.skipped_ambiguous;
                }
            }
        }
    }
    for (const auto &node : graph.nodes) {
        if (node.record.kind != CodeViewTypeKind::procedure &&
            node.record.kind != CodeViewTypeKind::member_function) continue;
        const TypeKey key{node.name_space, node.record.index};
        auto signature = convert(node.name_space, node.record.index);
        if (!signature) {
            if (signature.error().code != ErrorCode::unsupported) return signature.error();
            continue;
        }
        result.function_types.emplace(key, signature.value());
    }
    const auto dispatch_kind = [](std::uint16_t attributes) {
        switch ((attributes >> 2) & 7) {
        case 0: case 2: case 3: return PdbVirtualDispatchKind::non_virtual;
        case 1: return PdbVirtualDispatchKind::virtual_method;
        case 4: return PdbVirtualDispatchKind::introducing_virtual;
        case 5: return PdbVirtualDispatchKind::pure_virtual;
        case 6: return PdbVirtualDispatchKind::pure_introducing_virtual;
        default: return PdbVirtualDispatchKind::unknown;
        }
    };
    for (const auto &node : graph.nodes) {
        const auto &record = node.record;
        if ((record.kind != CodeViewTypeKind::structure && record.kind != CodeViewTypeKind::class_type &&
             record.kind != CodeViewTypeKind::union_type) || record.forward_declaration) continue;
        std::uint32_t ordinal = 0;
        const auto append = [&](PdbAggregateDeclarationKind kind, const CodeViewField &field,
                                std::uint32_t type_index, std::uint16_t attributes,
                                std::optional<std::uint32_t> vtable_offset) -> Result<bool> {
            if (ordinal == std::numeric_limits<std::uint32_t>::max())
                return Error{ErrorCode::resource_limit, "PDB aggregate declaration ordinal exceeds limit"};
            ++ordinal;
            const auto encoded_namespace = static_cast<std::uint8_t>(type_index >> 24);
            const auto target_namespace = encoded_namespace ? encoded_namespace : node.name_space;
            auto type = convert(target_namespace, type_index & 0x00ffffffu);
            if (!type) return type.error();
            PdbAggregateDeclaration declaration;
            declaration.name_space = node.name_space;
            declaration.aggregate_type_index = record.index;
            declaration.declaration_ordinal = ordinal;
            declaration.kind = kind;
            declaration.name = kind == PdbAggregateDeclarationKind::vftable_pointer
                ? "implicit vfptr" : field.name;
            declaration.type = type.value();
            declaration.attributes = attributes;
            switch (attributes & 3) {
            case 1: declaration.access = MemberAccess::private_; break;
            case 2: declaration.access = MemberAccess::protected_; break;
            case 3: declaration.access = MemberAccess::public_; break;
            default: declaration.access = MemberAccess::unknown; break;
            }
            declaration.virtual_dispatch = kind == PdbAggregateDeclarationKind::method
                ? dispatch_kind(attributes) : PdbVirtualDispatchKind::non_virtual;
            declaration.introducing_vtable_offset = vtable_offset;
            if (kind == PdbAggregateDeclarationKind::method) {
                const auto method_namespace_byte = static_cast<std::uint8_t>(type_index >> 24);
                const auto method_namespace = method_namespace_byte ? method_namespace_byte : node.name_space;
                const auto method_index = type_index & 0x00ffffffu;
                const auto method_node = nodes.find({method_namespace, method_index});
                if (method_node != nodes.end() &&
                    method_node->second->record.kind == CodeViewTypeKind::procedure) {
                    declaration.is_static = true;
                } else if (method_node != nodes.end() &&
                    method_node->second->record.kind == CodeViewTypeKind::member_function) {
                    const auto &method_record = method_node->second->record;
                    const auto class_namespace_byte = static_cast<std::uint8_t>(method_record.member_class_type >> 24);
                    const auto class_namespace = class_namespace_byte ? class_namespace_byte : method_namespace;
                    const auto class_index = method_record.member_class_type & 0x00ffffffu;
                    const auto class_node = nodes.find({class_namespace, class_index});
                    if (class_node == nodes.end() ||
                        (class_node->second->record.kind != CodeViewTypeKind::structure &&
                         class_node->second->record.kind != CodeViewTypeKind::class_type &&
                         class_node->second->record.kind != CodeViewTypeKind::union_type))
                        return Error{ErrorCode::unsupported, "PDB member function has no supported owning class"};
                    const auto owner_node = nodes.find({node.name_space, record.index});
                    if (owner_node == nodes.end())
                        return Error{ErrorCode::malformed, "PDB method owner is absent from its type graph"};
                    const auto canonical = [](const PdbTypeGraphNode &value) {
                        return value.canonical_index ? value.canonical_index : value.record.index;
                    };
                    if (class_namespace != node.name_space || canonical(*class_node->second) != canonical(*owner_node->second))
                        return Error{ErrorCode::unsupported, "PDB member function owner does not match its aggregate declaration"};
                    if (!method_record.member_this_type)
                        return Error{ErrorCode::unsupported, "PDB member function has no this-pointer type"};
                    auto this_type = convert(method_namespace, method_record.member_this_type);
                    if (!this_type) return this_type.error();
                    const auto unqualified = [](const Type *type) {
                        while (type && type->kind() == Kind::qualified)
                            type = type->element().get();
                        return type;
                    };
                    const Type *this_pointer = unqualified(this_type.value().get());
                    if (!this_pointer || this_pointer->kind() != Kind::pointer || !this_pointer->element())
                        return Error{ErrorCode::unsupported, "PDB member function this type is not a pointer"};
                    auto class_type = convert(class_namespace, method_record.member_class_type);
                    if (!class_type) return class_type.error();
                    const Type *this_pointee = unqualified(this_pointer->element().get());
                    const Type *declared_class = unqualified(class_type.value().get());
                    if (!this_pointee || !declared_class || this_pointee->id() != declared_class->id())
                        return Error{ErrorCode::unsupported,
                                     "PDB member function this pointer does not point to its canonical owning class"};
                    declaration.member_this_type = this_type.value();
                    declaration.this_adjustment = method_record.this_adjustment;
                    declaration.function_options = method_record.function_options;
                }
            }
            result.aggregate_declarations.push_back(std::move(declaration));
            return true;
        };
        for (const auto &field : node.expanded_fields) {
            if (field.leaf == 0x150e || field.leaf == 0x1510 || field.leaf == 0x1511 || field.leaf == 0x1409) {
                const auto kind = field.leaf == 0x150e ? PdbAggregateDeclarationKind::static_data :
                    field.leaf == 0x1510 ? PdbAggregateDeclarationKind::nested_type :
                    field.leaf == 0x1409 ? PdbAggregateDeclarationKind::vftable_pointer :
                                          PdbAggregateDeclarationKind::method;
                const auto status = append(kind, field, field.type, field.attributes,
                    kind == PdbAggregateDeclarationKind::method &&
                    (dispatch_kind(field.attributes) == PdbVirtualDispatchKind::introducing_virtual ||
                     dispatch_kind(field.attributes) == PdbVirtualDispatchKind::pure_introducing_virtual)
                        ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(field.value)) : std::nullopt);
                if (!status) {
                    if (status.error().code == ErrorCode::unsupported) { ++result.skipped_unsupported; continue; }
                    return status.error();
                }
            } else if (field.leaf == 0x150f) {
                const auto encoded_namespace = static_cast<std::uint8_t>(field.type >> 24);
                const auto target_namespace = encoded_namespace ? encoded_namespace : node.name_space;
                const auto found = nodes.find({target_namespace, field.type & 0x00ffffffu});
                if (found == nodes.end() || found->second->record.kind != CodeViewTypeKind::method_list) {
                    ++result.skipped_unsupported;
                    continue;
                }
                const auto &methods = found->second->record.fields;
                if (field.value != methods.size()) { ++result.skipped_unsupported; continue; }
                for (const auto &method : methods) {
                    const auto status = append(PdbAggregateDeclarationKind::method,
                        CodeViewField{method.leaf, method.type, method.attributes, 0, field.name, method.value, 0},
                        method.type, method.attributes,
                        (dispatch_kind(method.attributes) == PdbVirtualDispatchKind::introducing_virtual ||
                         dispatch_kind(method.attributes) == PdbVirtualDispatchKind::pure_introducing_virtual)
                            ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(method.value)) : std::nullopt);
                    if (!status) {
                        if (status.error().code == ErrorCode::unsupported) { ++result.skipped_unsupported; continue; }
                        return status.error();
                    }
                }
            }
        }
    }
    using DeclarationKey = std::tuple<std::uint8_t, std::uint32_t, std::uint32_t>;
    using ClassMethodKey = std::tuple<std::uint8_t, std::uint32_t, std::string>;
    std::map<ClassMethodKey, std::vector<const PdbAggregateDeclaration *>> virtual_methods_by_name;
    const auto canonical_type_index = [&](const PdbTypeGraphNode &node) {
        return node.canonical_index ? node.canonical_index : node.record.index;
    };
    for (const auto &declaration : result.aggregate_declarations) {
        if (declaration.kind != PdbAggregateDeclarationKind::method || declaration.is_static ||
            declaration.virtual_dispatch == PdbVirtualDispatchKind::non_virtual ||
            declaration.virtual_dispatch == PdbVirtualDispatchKind::unknown) continue;
        const auto owner = nodes.find({declaration.name_space, declaration.aggregate_type_index});
        if (owner == nodes.end()) continue;
        virtual_methods_by_name[{declaration.name_space, canonical_type_index(*owner->second), declaration.name}]
            .push_back(&declaration);
    }
    std::map<DeclarationKey, std::vector<VTableSlot>> vtable_slots_by_declaration;
    constexpr std::size_t max_imported_vtable_slots = 1'000'000;
    for (const auto &node : graph.nodes) {
        const auto &record = node.record;
        if (record.kind != CodeViewTypeKind::vftable) continue;
        if (record.vftable_names.empty() || record.vftable_names.front().empty() ||
            !record.vftable_complete_class_type) {
            ++result.skipped_unsupported;
            continue;
        }
        const auto encoded_namespace = static_cast<std::uint8_t>(record.vftable_complete_class_type >> 24);
        const auto owner_namespace = encoded_namespace ? encoded_namespace : node.name_space;
        const auto owner_index = record.vftable_complete_class_type & 0x00ffffffu;
        const auto owner = nodes.find({owner_namespace, owner_index});
        if (owner == nodes.end() || owner->second->record.forward_declaration ||
            (owner->second->record.kind != CodeViewTypeKind::structure &&
             owner->second->record.kind != CodeViewTypeKind::class_type &&
             owner->second->record.kind != CodeViewTypeKind::union_type)) {
            ++result.skipped_unsupported;
            continue;
        }
        const auto canonical_owner = canonical_type_index(*owner->second);
        for (std::size_t name_index = 1; name_index < record.vftable_names.size(); ++name_index) {
            if (result.vtable_slots.size() >= max_imported_vtable_slots)
                return Error{ErrorCode::resource_limit, "PDB virtual-table slot import exceeds limit"};
            const auto slot_index = name_index - 1;
            if (slot_index > std::numeric_limits<std::uint32_t>::max())
                return Error{ErrorCode::resource_limit, "PDB virtual-table slot index exceeds limit"};
            PdbImportedVTableSlot imported_slot;
            imported_slot.owner_namespace = owner_namespace;
            imported_slot.owner_type_index = owner_index;
            imported_slot.source_namespace = node.name_space;
            imported_slot.source_type_index = record.index;
            imported_slot.source_record_offset = record.record_offset;
            imported_slot.vfptr_offset = record.vftable_vfptr_offset;
            imported_slot.slot_index = static_cast<std::uint32_t>(slot_index);
            imported_slot.table_name = record.vftable_names.front();
            imported_slot.method_name = record.vftable_names[name_index];
            const auto candidates = virtual_methods_by_name.find(
                {owner_namespace, canonical_owner, imported_slot.method_name});
            if (candidates != virtual_methods_by_name.end()) {
                for (const auto *declaration : candidates->second) {
                    imported_slot.matched_declaration_ordinals.push_back(declaration->declaration_ordinal);
                    vtable_slots_by_declaration[{declaration->name_space,
                        declaration->aggregate_type_index, declaration->declaration_ordinal}].push_back({
                            imported_slot.vfptr_offset, imported_slot.slot_index,
                            imported_slot.table_name, imported_slot.method_name,
                            imported_slot.source_namespace, imported_slot.source_type_index,
                            imported_slot.source_record_offset});
                }
            }
            result.vtable_slots.push_back(std::move(imported_slot));
        }
    }

    std::map<TypeKey, std::vector<Method>> methods_by_owner;
    std::map<TypeKey, std::vector<StaticDataMember>> static_data_by_owner;
    for (const auto &declaration : result.aggregate_declarations) {
        const TypeKey owner_key{declaration.name_space, declaration.aggregate_type_index};
        const auto owner_name = storage_names.find(owner_key);
        if (owner_name == storage_names.end()) continue;
        if (declaration.kind == PdbAggregateDeclarationKind::static_data) {
            if (!declaration.type) continue;
            StaticDataMember member;
            member.name = declaration.name;
            member.type = declaration.type;
            member.access = declaration.access;
            member.source_attributes = declaration.attributes;
            member.declaration_ordinal = declaration.declaration_ordinal;
            static_data_by_owner[owner_key].push_back(std::move(member));
            continue;
        }
        if (declaration.kind != PdbAggregateDeclarationKind::method || !declaration.type ||
            declaration.type->kind() != Kind::function) continue;
        Method method;
        method.name = declaration.name;
        method.signature = declaration.type;
        method.access = declaration.access;
        method.source_attributes = declaration.attributes;
        method.is_static = declaration.is_static;
        method.introducing_vtable_offset = declaration.introducing_vtable_offset;
        method.this_type = declaration.member_this_type;
        method.this_adjustment = declaration.this_adjustment;
        method.function_options = declaration.function_options;
        method.declaration_ordinal = declaration.declaration_ordinal;
        if (const auto slots = vtable_slots_by_declaration.find(
                {declaration.name_space, declaration.aggregate_type_index, declaration.declaration_ordinal});
            slots != vtable_slots_by_declaration.end())
            method.vtable_slots = slots->second;
        switch (declaration.virtual_dispatch) {
        case PdbVirtualDispatchKind::non_virtual: method.dispatch = MemberDispatch::non_virtual; break;
        case PdbVirtualDispatchKind::virtual_method: method.dispatch = MemberDispatch::virtual_method; break;
        case PdbVirtualDispatchKind::introducing_virtual: method.dispatch = MemberDispatch::introducing_virtual; break;
        case PdbVirtualDispatchKind::pure_virtual: method.dispatch = MemberDispatch::pure_virtual; break;
        case PdbVirtualDispatchKind::pure_introducing_virtual: method.dispatch = MemberDispatch::pure_introducing_virtual; break;
        default: method.dispatch = MemberDispatch::unknown; break;
        }
        methods_by_owner[owner_key].push_back(std::move(method));
    }
    std::set<TypeKey> aggregate_metadata_owners;
    for (const auto &[owner_key, unused] : methods_by_owner) { (void)unused; aggregate_metadata_owners.insert(owner_key); }
    for (const auto &[owner_key, unused] : static_data_by_owner) { (void)unused; aggregate_metadata_owners.insert(owner_key); }
    std::set<std::string, std::less<>> applied_metadata_names;
    for (const auto &owner_key : aggregate_metadata_owners) {
        const auto owner_name = storage_names.find(owner_key);
        if (owner_name == storage_names.end()) continue;
        if (!applied_metadata_names.insert(owner_name->second).second) continue;
        const auto definition = result.definitions.find(owner_name->second);
        if (definition == result.definitions.end() ||
            (definition->second->kind() != Kind::structure && definition->second->kind() != Kind::union_type)) continue;
        auto aggregate = definition->second;
        if (const auto methods = methods_by_owner.find(owner_key); methods != methods_by_owner.end()) {
            auto with_methods = Type::with_methods(aggregate, std::move(methods->second));
            if (!with_methods) return with_methods.error();
            aggregate = std::move(with_methods).value();
        }
        if (const auto members = static_data_by_owner.find(owner_key); members != static_data_by_owner.end()) {
            auto with_static_data = Type::with_static_data_members(aggregate, std::move(members->second));
            if (!with_static_data) return with_static_data.error();
            aggregate = std::move(with_static_data).value();
        }
        definition->second = std::move(aggregate);
    }
    for (const auto &[key, type] : converted)
        result.types_by_index.emplace(key, type);
    for (const auto &[key, name] : storage_names) {
        const auto definition = result.definitions.find(name);
        if (definition != result.definitions.end())
            result.types_by_index.insert_or_assign(key, definition->second);
    }
    return result;
}

Result<PdbFunctionIdImportResult> import_pdb_function_ids(const PdbIdStream &ids,
        const PdbTypeStream &types, const PdbTypeImportResult &imported) {
    if (ids.type_index_begin < 0x1000 || ids.type_index_end < ids.type_index_begin ||
        ids.type_index_end - ids.type_index_begin != ids.records.size())
        return Error{ErrorCode::malformed, "PDB IPI index range does not match its records"};
    if (types.type_index_begin < 0x1000 || types.type_index_end < types.type_index_begin ||
        types.type_index_end - types.type_index_begin != types.records.size())
        return Error{ErrorCode::malformed, "PDB TPI index range does not match its records"};

    std::map<std::uint32_t, const CodeViewIdRecord *> id_by_index;
    for (std::size_t i = 0; i < ids.records.size(); ++i) {
        const auto &record = ids.records[i];
        if (record.index != ids.type_index_begin + i)
            return Error{ErrorCode::malformed, "PDB IPI records are not in index order"};
        if (!id_by_index.emplace(record.index, &record).second)
            return Error{ErrorCode::malformed, "PDB IPI contains duplicate type indices"};
    }
    std::map<std::uint32_t, const CodeViewTypeRecord *> type_by_index;
    for (std::size_t i = 0; i < types.records.size(); ++i) {
        const auto &record = types.records[i];
        if (record.index != types.type_index_begin + i)
            return Error{ErrorCode::malformed, "PDB TPI records are not in index order"};
        if (!type_by_index.emplace(record.index, &record).second)
            return Error{ErrorCode::malformed, "PDB TPI contains duplicate type indices"};
    }
    // LF_MFUNC_ID may name a forward declaration while LF_MFUNCTION records
    // the completed UDT index. Normalize only by CodeView's ODR identity;
    // display-name matching alone is unsafe when same-named types coexist.
    const auto is_aggregate = [](CodeViewTypeKind kind) {
        return kind == CodeViewTypeKind::class_type || kind == CodeViewTypeKind::structure ||
               kind == CodeViewTypeKind::union_type;
    };
    std::map<std::string, std::optional<std::uint32_t>, std::less<>> definition_by_unique_name;
    for (const auto &record : types.records) {
        if (record.forward_declaration || record.unique_name.empty() || !is_aggregate(record.kind))
            continue;
        const auto [it, inserted] = definition_by_unique_name.emplace(record.unique_name, record.index);
        if (!inserted)
            it->second.reset();
    }
    const auto canonical_aggregate = [&](std::uint32_t encoded) -> std::optional<std::uint32_t> {
        if ((encoded >> 24) != 0)
            return {};
        const auto found = type_by_index.find(encoded);
        if (found == type_by_index.end())
            return {};
        const auto &record = *found->second;
        if (!is_aggregate(record.kind))
            return {};
        if (!record.forward_declaration)
            return encoded;
        if (record.unique_name.empty())
            return {};
        const auto canonical = definition_by_unique_name.find(record.unique_name);
        return canonical == definition_by_unique_name.end() ? std::nullopt : canonical->second;
    };

    PdbFunctionIdImportResult result;
    result.records.reserve(ids.records.size());
    for (const auto &record : ids.records) {
        if (record.kind == CodeViewIdKind::unsupported) {
            ++result.unsupported;
            continue;
        }
        PdbImportedFunctionId imported_id;
        imported_id.local_function_type = record.function_type;
        imported_id.index = record.index;
        imported_id.leaf = record.leaf;
        imported_id.kind = record.kind;
        imported_id.parent_scope = record.parent_scope;
        imported_id.class_type = record.class_type;
        imported_id.function_type = record.function_type;
        imported_id.name = record.name;
        imported_id.record_offset = record.record_offset;
        imported_id.record_size = record.record_size;

        auto reject = [&](std::string message) {
            imported_id.resolved = false;
            imported_id.diagnostic = std::move(message);
        };
        if (record.name.empty()) {
            reject("CodeView function ID has an empty name");
        } else if (record.kind == CodeViewIdKind::function && record.parent_scope &&
                   !id_by_index.contains(record.parent_scope)) {
            reject("CodeView function ID parent scope is outside the IPI stream");
        } else if (record.kind == CodeViewIdKind::function && record.parent_scope &&
                   id_by_index.at(record.parent_scope)->kind != CodeViewIdKind::function &&
                   id_by_index.at(record.parent_scope)->kind != CodeViewIdKind::member_function) {
            reject("CodeView function ID parent scope is not a supported function ID");
        } else if (record.kind == CodeViewIdKind::member_function &&
                   !type_by_index.contains(record.class_type)) {
            reject("CodeView member-function ID class is outside the TPI stream");
        } else {
            const auto target = type_by_index.find(record.function_type);
            const auto expected_kind = record.kind == CodeViewIdKind::function
                ? CodeViewTypeKind::procedure : CodeViewTypeKind::member_function;
            const std::pair<std::uint8_t, std::uint32_t> signature_key{std::uint8_t{0}, record.function_type};
            if (target == type_by_index.end()) {
                reject("CodeView function ID type is outside the TPI stream");
            } else if (target->second->kind != expected_kind) {
                reject("CodeView function ID refers to the wrong TPI record kind");
            } else {
                const auto signature = imported.function_types.find(signature_key);
                if (signature == imported.function_types.end() || !signature->second) {
                    reject("CodeView function ID signature could not be represented by the project type model");
                } else if (record.kind == CodeViewIdKind::member_function) {
                    const auto class_record = type_by_index.find(record.class_type);
                    const auto &function_record = *target->second;
                    if (class_record == type_by_index.end() ||
                        (class_record->second->kind != CodeViewTypeKind::class_type &&
                         class_record->second->kind != CodeViewTypeKind::structure &&
                         class_record->second->kind != CodeViewTypeKind::union_type)) {
                        reject("CodeView member-function ID owner is not a supported aggregate");
                    } else if (!canonical_aggregate(function_record.member_class_type) ||
                               canonical_aggregate(function_record.member_class_type) !=
                                   canonical_aggregate(record.class_type)) {
                        reject("CodeView member-function ID owner disagrees with LF_MFUNCTION");
                    }
                }
            }
        }
        if (imported_id.diagnostic.empty()) {
            imported_id.signature = imported.function_types.at({std::uint8_t{0}, record.function_type});
            imported_id.resolved = true;
        } else {
            ++result.unresolved;
        }
        result.records.push_back(std::move(imported_id));
    }

    // Parent scopes form a finite IPI reference graph. Use a linear tri-color
    // walk so a malicious deep chain cannot cause quadratic ancestry checks.
    std::map<std::uint32_t, std::size_t> imported_by_id;
    for (std::size_t i = 0; i < result.records.size(); ++i)
        imported_by_id.emplace(result.records[i].index, i);
    std::vector<std::uint8_t> scope_state(ids.records.size(), 0);
    for (auto &entry : result.records) {
        const auto root_offset = entry.index - ids.type_index_begin;
        if (root_offset >= scope_state.size() || scope_state[root_offset] != 0) continue;
        std::vector<std::uint32_t> path;
        auto current = entry.index;
        bool cycle = false;
        for (;;) {
            if (current < ids.type_index_begin || current >= ids.type_index_end) break;
            const auto offset = static_cast<std::size_t>(current - ids.type_index_begin);
            if (scope_state[offset] == 2) break;
            if (scope_state[offset] == 1) { cycle = true; break; }
            const auto found = id_by_index.find(current);
            if (found == id_by_index.end() || found->second->kind != CodeViewIdKind::function) break;
            scope_state[offset] = 1;
            path.push_back(current);
            current = found->second->parent_scope;
            if (!current) break;
        }
        for (const auto id : path) {
            const auto offset = static_cast<std::size_t>(id - ids.type_index_begin);
            scope_state[offset] = 2;
            if (!cycle) continue;
            const auto imported_row = imported_by_id.find(id);
            if (imported_row == imported_by_id.end()) continue;
            auto &affected = result.records[imported_row->second];
            if (affected.resolved) {
                affected.signature.reset();
                affected.resolved = false;
                affected.diagnostic = "CodeView function ID parent-scope cycle";
                ++result.unresolved;
            }
        }
    }
    return result;
}

Result<PdbFunctionIdImportResult> import_pdb_function_ids(const PdbIdStream &root_ids,
        const std::array<std::byte, 16> &root_guid, std::uint32_t root_age,
        const PdbTypeServerSet &servers, const PdbTypeGraph &graph,
        const PdbTypeImportResult &imported) {
    PdbFunctionIdImportResult result;
    std::map<std::pair<std::uint8_t, std::uint32_t>, const CodeViewTypeRecord *> types;
    for (const auto &node : graph.nodes)
        if (!types.emplace(std::pair{node.name_space, node.record.index}, &node.record).second)
            return Error{ErrorCode::malformed, "Combined PDB TPI graph has duplicate namespaced indices"};

    const auto selector_map = [](const std::vector<std::pair<std::uint8_t, std::uint8_t>> &mapping,
                                 std::uint8_t local) -> std::optional<std::uint8_t> {
        std::optional<std::uint8_t> value;
        for (const auto &[from, to] : mapping) if (from == local) {
            if (value) return {};
            value = to;
        }
        if (value) return value;
        return local == 0 ? std::optional<std::uint8_t>{0} : std::nullopt;
    };
    const auto append = [&](const PdbIdStream &ids, std::uint8_t owner_ns,
                            const std::array<std::byte, 16> &guid, std::uint32_t age,
                            const std::vector<std::pair<std::uint8_t, std::uint8_t>> &mapping) -> std::optional<Error> {
        if (ids.type_index_begin < 0x1000 || ids.type_index_end < ids.type_index_begin ||
            ids.type_index_end - ids.type_index_begin != ids.records.size())
            return Error{ErrorCode::malformed, "PDB IPI index range does not match its records"};
        std::map<std::uint32_t, const CodeViewIdRecord *> id_index;
        for (std::size_t i = 0; i < ids.records.size(); ++i) {
            const auto &id = ids.records[i];
            if (id.index != ids.type_index_begin + i || !id_index.emplace(id.index, &id).second)
                return Error{ErrorCode::malformed, "PDB IPI records are not uniquely ordered"};
        }
        for (const auto &id : ids.records) {
            PdbImportedFunctionId row;
            row.owner_guid = guid; row.owner_age = age; row.owner_namespace = owner_ns;
            row.index = id.index; row.leaf = id.leaf; row.kind = id.kind;
            row.parent_scope = id.parent_scope; row.class_type = id.class_type;
            row.local_function_type = id.function_type; row.name = id.name;
            row.record_offset = id.record_offset; row.record_size = id.record_size;
            if (id.kind == CodeViewIdKind::unsupported) {
                ++result.unsupported;
                row.diagnostic = "Unsupported CodeView IPI leaf retained without a function join";
                result.records.push_back(std::move(row));
                continue;
            }
            const auto target_ns = selector_map(mapping, static_cast<std::uint8_t>(id.function_type >> 24));
            row.function_namespace = target_ns.value_or(0xff);
            const auto target_index = id.function_type & 0x00ffffffu;
            const auto type = target_ns ? types.find({*target_ns, target_index}) : types.end();
            if (id.name.empty()) row.diagnostic = "CodeView function ID has an empty name";
            else if (id.kind == CodeViewIdKind::function && id.parent_scope && !id_index.contains(id.parent_scope))
                row.diagnostic = "CodeView function ID parent scope is outside its owning IPI stream";
            else if (id.kind == CodeViewIdKind::function && id.parent_scope &&
                     id_index.at(id.parent_scope)->kind != CodeViewIdKind::function &&
                     id_index.at(id.parent_scope)->kind != CodeViewIdKind::member_function)
                row.diagnostic = "CodeView function ID parent scope is not a supported function ID";
            else if (!target_ns) row.diagnostic = "CodeView function ID targets an unmapped or ambiguous TPI namespace";
            else if (type == types.end()) row.diagnostic = "CodeView function ID target type is missing from the exact TPI namespace";
            else if ((id.kind == CodeViewIdKind::function && type->second->kind != CodeViewTypeKind::procedure) ||
                     (id.kind == CodeViewIdKind::member_function && type->second->kind != CodeViewTypeKind::member_function))
                row.diagnostic = "CodeView function ID refers to the wrong TPI record kind";
            else if (id.kind == CodeViewIdKind::member_function) {
                const auto owner_ns_target = selector_map(mapping, static_cast<std::uint8_t>(id.class_type >> 24));
                const auto owner_idx = id.class_type & 0x00ffffffu;
                const auto member_class_ns = selector_map(mapping,
                    static_cast<std::uint8_t>(type->second->member_class_type >> 24));
                const auto member_class_idx = type->second->member_class_type & 0x00ffffffu;
                const auto owner = owner_ns_target ? types.find({*owner_ns_target, owner_idx}) : types.end();
                const auto function_owner = member_class_ns ? types.find({*member_class_ns, member_class_idx}) : types.end();
                if (owner == types.end() || function_owner == types.end())
                    row.diagnostic = "CodeView member-function owner is missing or unmapped";
                else if (*owner_ns_target != *member_class_ns || owner_idx != member_class_idx)
                    row.diagnostic = "CodeView member-function ID owner disagrees with LF_MFUNCTION";
                else if (owner->second->kind != CodeViewTypeKind::class_type &&
                         owner->second->kind != CodeViewTypeKind::structure &&
                         owner->second->kind != CodeViewTypeKind::union_type)
                    row.diagnostic = "CodeView member-function owner is not an aggregate";
                else if (!imported.function_types.contains({*target_ns, target_index}))
                    row.diagnostic = "CodeView function signature is unavailable in the project type model";
                else row.signature = imported.function_types.at({*target_ns, target_index});
            } else if (!imported.function_types.contains({*target_ns, target_index}))
                row.diagnostic = "CodeView function signature is unavailable in the project type model";
            else row.signature = imported.function_types.at({*target_ns, target_index});
            row.resolved = row.signature != nullptr;
            if (!row.resolved) ++result.unresolved;
            result.records.push_back(std::move(row));
        }
        // Parent scopes are local to each IPI stream. Mark every member of a
        // detected cycle unresolved without allowing one server's IDs to alias another's.
        std::map<std::uint32_t, std::size_t> row_by_index;
        for (std::size_t i = result.records.size(); i > 0; --i) {
            const auto &row = result.records[i - 1];
            if (row.owner_namespace == owner_ns && row.owner_guid == guid && row.owner_age == age)
                row_by_index.emplace(row.index, i - 1);
        }
        std::vector<std::uint8_t> state(ids.records.size(), 0);
        for (std::size_t start = 0; start < ids.records.size(); ++start) {
            if (state[start]) continue;
            std::vector<std::size_t> path;
            auto current = ids.records[start].index;
            bool cycle = false;
            for (;;) {
                if (current < ids.type_index_begin || current >= ids.type_index_end) break;
                const auto offset = static_cast<std::size_t>(current - ids.type_index_begin);
                if (state[offset] == 2) break;
                if (state[offset] == 1) { cycle = true; break; }
                const auto found = id_index.find(current);
                if (found == id_index.end() || found->second->kind != CodeViewIdKind::function) break;
                state[offset] = 1; path.push_back(offset);
                current = found->second->parent_scope;
                if (!current) break;
            }
            for (const auto offset : path) {
                state[offset] = 2;
                if (!cycle) continue;
                const auto row = row_by_index.find(ids.records[offset].index);
                if (row != row_by_index.end() && result.records[row->second].resolved) {
                    auto &affected = result.records[row->second];
                    affected.signature.reset(); affected.resolved = false;
                    affected.diagnostic = "CodeView function ID parent-scope cycle";
                    ++result.unresolved;
                }
            }
        }
        return {};
    };
    auto root = append(root_ids, 0, root_guid, root_age, servers.root_namespace_map);
    if (root) return *root;
    for (const auto &server : servers.namespaces) {
        auto ids = parse_pdb_ids(server.database);
        if (!ids) {
            // Keep the exact server identity visible even when its IPI stream is absent or malformed.
            PdbImportedFunctionId row;
            row.owner_guid = server.request.guid; row.owner_age = server.request.age;
            row.owner_namespace = server.index; row.diagnostic = ids.error().message;
            ++result.unresolved; result.records.push_back(std::move(row));
            continue;
        }
        auto added = append(ids.value(), server.index, server.request.guid, server.request.age, server.namespace_map);
        if (added) return *added;
    }
    return result;
}

Result<PdbDataSymbolImportResult> import_pdb_data_symbols(
        const PdbSymbolTable &symbols, const PdbTypeImportResult &imported) {
    constexpr std::size_t max_symbols = 2'000'000;
    if (symbols.symbols.size() > max_symbols)
        return Error{ErrorCode::resource_limit, "PDB data-symbol import exceeds symbol limit"};
    PdbDataSymbolImportResult result;
    result.symbols.reserve(symbols.symbols.size());
    for (const auto &symbol : symbols.symbols) {
        if (symbol.kind == PdbSymbolKind::procedure) continue;
        if (symbol.kind != PdbSymbolKind::data)
            return Error{ErrorCode::malformed, "PDB symbol has an invalid kind"};
        PdbImportedDataSymbol row;
        row.symbol = symbol;
        if (!symbol.type_index) {
            row.diagnostic = "PDB data symbol has no CodeView type index";
            ++result.unresolved;
        } else if (symbol.type_index < 0x1000) {
            auto type = primitive(symbol.type_index);
            if (type) {
                row.type = std::move(type).value();
                row.resolved = true;
            } else {
                row.diagnostic = type.error().message;
                ++result.unsupported;
            }
        } else {
            const auto name_space = static_cast<std::uint8_t>(symbol.type_index >> 24);
            const auto index = symbol.type_index & 0x00ffffffu;
            const auto found = imported.types_by_index.find({name_space, index});
            if (found != imported.types_by_index.end() && found->second) {
                row.type = found->second;
                row.resolved = true;
            } else {
                row.diagnostic = "PDB data symbol type index is unresolved or its type was unsupported";
                ++result.unresolved;
            }
        }
        result.symbols.push_back(std::move(row));
    }
    return result;
}
} // namespace hexlab::types
