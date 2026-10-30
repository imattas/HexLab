#include "hexlab/types/type_library.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace hexlab::types {
namespace {
Error unsupported(std::string message) { return {ErrorCode::unsupported, std::move(message)}; }
Error invalid(std::string message) { return {ErrorCode::invalid_argument, std::move(message)}; }

bool identifier(std::string_view text) {
    if (text.empty() || !(std::isalpha(static_cast<unsigned char>(text[0])) || text[0] == '_')) return false;
    if (!std::all_of(text.begin() + 1, text.end(), [](char c) {
        const auto value = static_cast<unsigned char>(c);
        return std::isalnum(value) || value == '_';
    })) return false;
    static constexpr std::string_view keywords[] = {
        "auto","break","case","char","const","continue","default","do","double","else","enum","extern",
        "float","for","goto","if","inline","int","long","register","restrict","return","short","signed",
        "sizeof","static","struct","switch","typedef","union","unsigned","void","volatile","while",
        "_Alignas","_Alignof","_Atomic","_Bool","_Complex","_Generic","_Imaginary","_Noreturn","_Static_assert","_Thread_local",
        "alignas","alignof","and","and_eq","asm","bitand","bitor","bool","catch","char8_t","char16_t","char32_t",
        "class","compl","concept","const_cast","consteval","constexpr","constinit","co_await","co_return","co_yield",
        "decltype","delete","dynamic_cast","explicit","export","false","friend","mutable","namespace","new","noexcept",
        "not","not_eq","nullptr","operator","or","or_eq","private","protected","public","reinterpret_cast","requires",
        "static_assert","static_cast","synchronized","template","this","thread_local","throw","true","try","typeid","typename",
        "using","virtual","wchar_t","xor","xor_eq"
    };
    return std::find(std::begin(keywords), std::end(keywords), text) == std::end(keywords);
}

std::string integer_name(const Type &type) {
    const auto size = type.size().value_or(0);
    if (type.kind() == Kind::boolean) return "_Bool";
    if (type.kind() == Kind::enumeration) return {};
    if (type.kind() != Kind::integer) return {};
    switch (size) {
    case 1: return type.is_signed() ? "int8_t" : "uint8_t";
    case 2: return type.is_signed() ? "int16_t" : "uint16_t";
    case 4: return type.is_signed() ? "int32_t" : "uint32_t";
    case 8: return type.is_signed() ? "int64_t" : "uint64_t";
    default: return {};
    }
}

std::string float_name(const Type &type) {
    switch (type.size().value_or(0)) {
    case 4: return "float";
    case 8: return "double";
    case 10: return "long double";
    default: return {};
    }
}

std::string qualifiers(std::uint8_t bits) {
    std::string out;
    if (bits & static_cast<std::uint8_t>(Qualifier::const_)) out += "const ";
    if (bits & static_cast<std::uint8_t>(Qualifier::volatile_)) out += "volatile ";
    if (bits & static_cast<std::uint8_t>(Qualifier::restrict_)) out += "restrict ";
    if (bits & static_cast<std::uint8_t>(Qualifier::atomic_)) out += "_Atomic ";
    return out;
}

using EntryMap = std::map<std::string, const LibraryEntry *, std::less<>>;
using TypeNames = std::unordered_map<const Type *, std::string>;

bool is_opaque_typedef(const Type &source, const EntryMap &entries,
                       const std::set<std::string, std::less<>> &incomplete,
                       std::set<std::string, std::less<>> &seen, unsigned depth = 0) {
    if (depth > 128) return false;
    if (source.kind() == Kind::qualified && source.element())
        return is_opaque_typedef(*source.element(), entries, incomplete, seen, depth + 1);
    if (source.kind() != Kind::named_reference) return false;
    const auto &name = source.name();
    if (incomplete.contains(name)) return true;
    const auto found = entries.find(name);
    if (found == entries.end() || found->second->declaration_kind != LibraryDeclarationKind::type ||
        !found->second->type || !seen.insert(name).second)
        return false;
    return is_opaque_typedef(*found->second->type, entries, incomplete, seen, depth + 1);
}

bool has_incomplete_by_value(const Type &root, const EntryMap &entries,
                             const std::set<std::string, std::less<>> &incomplete,
                             std::size_t &work) {
    std::vector<const Type *> pending{&root};
    std::unordered_set<const Type *> visited;
    while (!pending.empty()) {
        if (++work > 1'000'000) throw std::length_error("Incomplete-type validation exceeds its work budget");
        const auto *type = pending.back();
        pending.pop_back();
        if (!type || !visited.insert(type).second) continue;
        if (type->kind() == Kind::pointer) {
            // A pointer to an incomplete object type is valid. Function
            // declarators still need their own parameter/result completeness.
            if (type->element() && type->element()->kind() == Kind::function)
                pending.push_back(type->element().get());
            continue;
        }
        if (type->kind() == Kind::named_reference) {
            const auto &name = type->name();
            if (incomplete.contains(name)) return true;
            const auto found = entries.find(name);
            if (found != entries.end() && found->second->declaration_kind == LibraryDeclarationKind::type &&
                found->second->type && found->second->type->kind() != Kind::structure &&
                found->second->type->kind() != Kind::union_type &&
                found->second->type->kind() != Kind::enumeration) {
                pending.push_back(found->second->type.get());
            }
            continue;
        }
        if ((type->kind() == Kind::structure || type->kind() == Kind::union_type) && !type->size())
            return true;
        if (type->element()) pending.push_back(type->element().get());
        if (type->result_type()) pending.push_back(type->result_type().get());
        for (const auto &member : type->members())
            if (member.type) pending.push_back(member.type.get());
        for (const auto &parameter : type->parameters())
            if (parameter.type) pending.push_back(parameter.type.get());
    }
    return false;
}

struct Renderer {
    const EntryMap &entries;
    const TypeNames &type_names;
    std::size_t work = 0;

    Result<std::string> declaration(const Type &type, std::string name, unsigned depth = 0) {
        if (++work > 1'000'000 || depth > 128)
            return Error{ErrorCode::resource_limit, "C header rendering exceeds its work or depth budget"};
        switch (type.kind()) {
        case Kind::qualified: {
            if (!type.element()) return invalid("Qualified portable type has no base type");
            if (type.element()->kind() == Kind::function)
                return unsupported("C header export does not model qualified function types");
            if (type.element()->kind() == Kind::pointer) {
                const auto &pointer = *type.element();
                if (!pointer.element()) return invalid("Portable pointer type has no pointee");
                auto modifier = std::string("*") + qualifiers(type.qualifiers()) + name;
                if (pointer.element()->kind() == Kind::array || pointer.element()->kind() == Kind::function)
                    modifier = "(" + modifier + ")";
                return declaration(*pointer.element(), std::move(modifier), depth + 1);
            }
            return declaration(*type.element(), qualifiers(type.qualifiers()) + name, depth + 1);
        }
        case Kind::pointer: {
            if (!type.element()) return invalid("Portable pointer type has no pointee");
            auto modifier = "*" + name;
            if (type.element()->kind() == Kind::array || type.element()->kind() == Kind::function)
                modifier = "(" + modifier + ")";
            return declaration(*type.element(), std::move(modifier), depth + 1);
        }
        case Kind::array: {
            if (!type.element()) return invalid("Portable array type has no element");
            name += "[";
            if (type.count()) name += std::to_string(type.count());
            name += "]";
            return declaration(*type.element(), std::move(name), depth + 1);
        }
        case Kind::function: {
            if (!type.result_type()) return invalid("Portable function type has no result");
            std::string_view convention_name;
            switch (type.function_convention()) {
            case FunctionConvention::platform_default: break;
            case FunctionConvention::c_decl: convention_name = "__cdecl"; break;
            case FunctionConvention::stdcall: convention_name = "__stdcall"; break;
            case FunctionConvention::fastcall: convention_name = "__fastcall"; break;
            case FunctionConvention::thiscall: convention_name = "__thiscall"; break;
            case FunctionConvention::vectorcall: convention_name = "__vectorcall"; break;
            case FunctionConvention::sysv_abi: convention_name = "HXTL_SYSV_ABI"; break;
            case FunctionConvention::ms_abi: convention_name = "HXTL_MS_ABI"; break;
            case FunctionConvention::aapcs32: convention_name = "HXTL_AAPCS32"; break;
            case FunctionConvention::aapcs32_vfp: convention_name = "HXTL_AAPCS32_VFP"; break;
            default:
                return unsupported("C header export does not model this function calling convention");
            }
            if (type.variadic() && type.parameters().empty())
                return unsupported("C header export rejects variadic functions without a named parameter");
            std::string params;
            for (std::size_t i = 0; i < type.parameters().size(); ++i) {
                const auto &parameter = type.parameters()[i];
                if (!parameter.type || !identifier(parameter.name))
                    return unsupported("C header export requires named C-identifier function parameters");
                Result<std::string> item = unsupported("C header export cannot adjust this parameter type");
                if (parameter.type->kind() == Kind::array) {
                    if (!parameter.type->element()) return invalid("Portable array parameter has no element type");
                    auto adjusted_name = parameter.name;
                    if (parameter.type->element()->kind() == Kind::array ||
                        parameter.type->element()->kind() == Kind::function)
                        adjusted_name = "(*" + adjusted_name + ")";
                    else
                        adjusted_name = "*" + adjusted_name;
                    item = declaration(*parameter.type->element(), std::move(adjusted_name), depth + 1);
                } else if (parameter.type->kind() == Kind::function) {
                    item = declaration(*parameter.type, "(*" + parameter.name + ")", depth + 1);
                } else if (parameter.type->kind() == Kind::qualified && parameter.type->element() &&
                           (parameter.type->element()->kind() == Kind::array ||
                            parameter.type->element()->kind() == Kind::function)) {
                    return unsupported("C header export does not model qualified array/function parameter adjustment");
                } else {
                    item = declaration(*parameter.type, parameter.name, depth + 1);
                }
                if (!item) return item.error();
                if (i) params += ", ";
                params += item.value();
            }
            if (type.variadic()) {
                if (!params.empty()) params += ", ";
                params += "...";
            }
            if (params.empty()) params = "void";
            auto declarator = name;
            if (!convention_name.empty()) {
                // Microsoft-compatible placement differs between a direct
                // function declarator and a parenthesized pointer declarator.
                if (name.starts_with("(")) declarator = "(" + std::string(convention_name) + " " + name.substr(1);
                else declarator = std::string(convention_name) + " " + name;
            }
            return declaration(*type.result_type(), declarator + "(" + params + ")", depth + 1);
        }
        case Kind::void_type: return "void " + name;
        case Kind::boolean:
        case Kind::integer: {
            const auto base = integer_name(type);
            if (base.empty()) return unsupported("C header export supports integer widths of 8, 16, 32 and 64 bits");
            return base + " " + name;
        }
        case Kind::floating: {
            const auto base = float_name(type);
            if (base.empty()) return unsupported("C header export supports 32-bit, 64-bit and binary80 floating scalars");
            return base + " " + name;
        }
        case Kind::named_reference:
            if (!entries.contains(type.name())) return invalid("C header has unresolved named reference " + type.name());
            if (entries.at(type.name())->declaration_kind != LibraryDeclarationKind::type)
                return unsupported("C header type reference names an object or function declaration");
            return type.name() + " " + name;
        case Kind::structure:
        case Kind::union_type: {
            const auto found = type_names.find(&type);
            if (found == type_names.end()) return unsupported("Nested anonymous or unbundled aggregates cannot be rendered in C headers");
            return std::string(type.kind() == Kind::structure ? "struct " : "union ") + found->second + " " + name;
        }
        case Kind::enumeration: {
            const auto found = type_names.find(&type);
            if (found == type_names.end()) return unsupported("Nested or unbundled enums cannot be rendered in C headers");
            return found->second + " " + name;
        }
        case Kind::vector: return unsupported("C header export does not model compiler-specific vector types");
        }
        return unsupported("C header export encountered an unknown type kind");
    }
};

void collect_refs(const Type &root, std::set<std::string, std::less<>> &refs,
                  std::unordered_set<const Type *> &visited, std::size_t &work) {
    std::vector<const Type *> pending{&root};
    while (!pending.empty()) {
        if (++work > 1'000'000) throw std::length_error("C header dependency walk exceeds node budget");
        const auto *type = pending.back(); pending.pop_back();
        if (!visited.insert(type).second) continue;
        if (type->kind() == Kind::named_reference) {
            refs.insert(type->name());
            continue;
        }
        if (type->kind() == Kind::structure || type->kind() == Kind::union_type || type->kind() == Kind::enumeration)
            continue;
        if (type->element()) pending.push_back(type->element().get());
        if (type->result_type()) pending.push_back(type->result_type().get());
        for (const auto &member : type->members()) {
            if (member.type) pending.push_back(member.type.get());
            if (member.virtual_base && member.virtual_base->vbptr_type) pending.push_back(member.virtual_base->vbptr_type.get());
        }
        for (const auto &parameter : type->parameters()) if (parameter.type) pending.push_back(parameter.type.get());
        for (const auto &method : type->methods()) {
            if (method.signature) pending.push_back(method.signature.get());
            if (method.this_type) pending.push_back(method.this_type.get());
        }
        for (const auto &member : type->static_data_members()) if (member.type) pending.push_back(member.type.get());
    }
}

struct AbiAttributeRequirements {
    bool sysv = false;
    bool microsoft = false;
    bool aapcs32 = false;
    bool aapcs32_vfp = false;
};

void collect_abi_attributes(const Type &root, AbiAttributeRequirements &required,
                            std::unordered_set<const Type *> &visited, std::size_t &work) {
    std::vector<const Type *> pending{&root};
    while (!pending.empty()) {
        if (++work > 1'000'000) throw std::length_error("C header ABI scan exceeds node budget");
        const auto *type = pending.back(); pending.pop_back();
        if (!visited.insert(type).second) continue;
        if (type->kind() == Kind::function) {
            required.sysv |= type->function_convention() == FunctionConvention::sysv_abi;
            required.microsoft |= type->function_convention() == FunctionConvention::ms_abi;
            required.aapcs32 |= type->function_convention() == FunctionConvention::aapcs32;
            required.aapcs32_vfp |= type->function_convention() == FunctionConvention::aapcs32_vfp;
        }
        if (type->element()) pending.push_back(type->element().get());
        if (type->result_type()) pending.push_back(type->result_type().get());
        for (const auto &member : type->members()) {
            if (member.type) pending.push_back(member.type.get());
            if (member.virtual_base && member.virtual_base->vbptr_type)
                pending.push_back(member.virtual_base->vbptr_type.get());
        }
        for (const auto &parameter : type->parameters())
            if (parameter.type) pending.push_back(parameter.type.get());
        for (const auto &method : type->methods()) {
            if (method.signature) pending.push_back(method.signature.get());
            if (method.this_type) pending.push_back(method.this_type.get());
        }
        for (const auto &member : type->static_data_members())
            if (member.type) pending.push_back(member.type.get());
    }
}

std::string assertion(std::string expression, std::string message) {
    return "HXTL_STATIC_ASSERT(" + expression + ", \"" + message + "\");\n";
}

} // namespace

Result<std::string> render_library_c_header(const LibraryBundle &bundle, std::string_view include_guard) {
    if (!identifier(include_guard)) return invalid("C header include guard must be a C identifier");
    auto references = validate_library_references(bundle, {});
    if (!references) return references.error();
    try {
        EntryMap entries;
        TypeNames type_names;
        std::set<std::string, std::less<>> tags;
        std::set<std::string, std::less<>> incomplete_aggregates;
        std::set<std::string, std::less<>> ordinary_names{
            std::string(include_guard), "HXTL_STATIC_ASSERT", "HXTL_ALIGNOF", "HXTL_ALIGNAS",
            "HXTL_SYSV_ABI", "HXTL_MS_ABI", "HXTL_AAPCS32", "HXTL_AAPCS32_VFP"};
        for (const auto &entry : bundle.entries) {
            if (!identifier(entry.name)) return unsupported("C header export requires C-identifier definition names");
            if (!entries.emplace(entry.name, &entry).second) return invalid("C header bundle has duplicate definition names");
            if (!ordinary_names.insert(entry.name).second)
                return invalid("C header definition name collides with an emitted helper macro");
            if (entry.declaration_kind == LibraryDeclarationKind::type && entry.type &&
                (entry.type->kind() == Kind::structure || entry.type->kind() == Kind::union_type ||
                 entry.type->kind() == Kind::enumeration)) {
                if (!tags.insert(entry.name).second) return invalid("C header aggregate names are not unique");
                if (!type_names.emplace(entry.type.get(), entry.name).second)
                    return invalid("One aggregate definition is exposed under multiple C names");
                if ((entry.type->kind() == Kind::structure || entry.type->kind() == Kind::union_type) &&
                    !entry.type->size()) {
                    if (!entry.type->members().empty() || !entry.type->methods().empty() ||
                        !entry.type->static_data_members().empty())
                        return unsupported("Incomplete C header aggregates cannot carry members or C++ declarations");
                    incomplete_aggregates.insert(entry.name);
                }
            }
        }
        AbiAttributeRequirements abi_attributes;
        std::unordered_set<const Type *> abi_visited;
        std::size_t abi_work = 0;
        for (const auto &entry : bundle.entries)
            if (entry.type) collect_abi_attributes(*entry.type, abi_attributes, abi_visited, abi_work);
        Renderer renderer{entries, type_names};
        std::ostringstream out;
        const auto within_output_budget = [&]() {
            const std::streamoff position = static_cast<std::streamoff>(out.tellp());
            return position >= 0 && static_cast<std::uint64_t>(position) <= 16u * 1024u * 1024u;
        };
        const auto check_output_budget = [&]() -> Result<bool> {
            if (!within_output_budget())
                return Error{ErrorCode::resource_limit, "Generated C header exceeds the 16 MiB limit"};
            return true;
        };
        out << "#ifndef " << include_guard << "\n#define " << include_guard << "\n\n"
            << "#include <stddef.h>\n#include <stdint.h>\n\n"
            << "#ifdef __cplusplus\n#define HXTL_STATIC_ASSERT(c, m) static_assert((c), m)\n#define HXTL_ALIGNOF(t) alignof(t)\n#define HXTL_ALIGNAS(n) alignas(n)\n#else\n#define HXTL_STATIC_ASSERT(c, m) _Static_assert((c), m)\n#define HXTL_ALIGNOF(t) _Alignof(t)\n#define HXTL_ALIGNAS(n) _Alignas(n)\n#endif\n\n";
        if (abi_attributes.sysv) {
            out << "#if (defined(__GNUC__) || defined(__clang__)) && "
                   "(defined(__x86_64__) || defined(__i386__))\n"
                   "#define HXTL_SYSV_ABI __attribute__((sysv_abi))\n"
                   "#else\n#error \"This type library requires sysv_abi on an x86 GNU-compatible compiler\"\n#endif\n";
        }
        if (abi_attributes.microsoft) {
            out << "#if (defined(__GNUC__) || defined(__clang__)) && "
                   "(defined(__x86_64__) || defined(__i386__))\n"
                   "#define HXTL_MS_ABI __attribute__((ms_abi))\n"
                   "#elif defined(_MSC_VER) && defined(_M_X64)\n"
                   "#define HXTL_MS_ABI\n"
                   "#else\n#error \"This type library requires ms_abi on an x86 compiler\"\n#endif\n";
        }
        if (abi_attributes.aapcs32) {
            out << "#if (defined(__GNUC__) || defined(__clang__)) && "
                   "(defined(__arm__) || defined(__thumb__))\n"
                   "#define HXTL_AAPCS32 __attribute__((pcs(\"aapcs\")))\n"
                   "#else\n#error \"This type library requires AAPCS32 on an ARM GNU-compatible compiler\"\n#endif\n";
        }
        if (abi_attributes.aapcs32_vfp) {
            out << "#if (defined(__GNUC__) || defined(__clang__)) && "
                   "(defined(__arm__) || defined(__thumb__))\n"
                   "#define HXTL_AAPCS32_VFP __attribute__((pcs(\"aapcs-vfp\")))\n"
                   "#else\n#error \"This type library requires AAPCS32 VFP PCS on an ARM GNU-compatible compiler\"\n#endif\n";
        }
        if (abi_attributes.sysv || abi_attributes.microsoft || abi_attributes.aapcs32 ||
            abi_attributes.aapcs32_vfp) out << '\n';

        // Predeclare tags and typedef scalar aliases for named aggregate types.
        for (const auto &[name, entry] : entries) {
            if (entry->declaration_kind != LibraryDeclarationKind::type) continue;
            const auto kind = entry->type->kind();
            if (kind == Kind::structure || kind == Kind::union_type)
                out << "typedef " << (kind == Kind::structure ? "struct " : "union ") << name << " " << name << ";\n";
            else if (kind == Kind::enumeration) {
                const auto underlying = entry->type->element();
                if (!underlying) return invalid("Portable enum has no underlying type");
                auto decl = renderer.declaration(*underlying, name);
                if (!decl) return decl.error();
                out << "typedef " << decl.value() << ";\n";
            }
        }
        out << '\n';

        // Other named typedefs can refer to any predeclared aggregate/enum,
        // but alias-to-alias dependencies are emitted in deterministic order.
        std::set<std::string, std::less<>> aliases;
        for (const auto &[name, entry] : entries)
            if (entry->declaration_kind == LibraryDeclarationKind::type &&
                entry->type->kind() != Kind::structure && entry->type->kind() != Kind::union_type &&
                entry->type->kind() != Kind::enumeration)
                aliases.insert(name);
        std::map<std::string, std::set<std::string, std::less<>>, std::less<>> dependencies;
        std::size_t ref_work = 0, incomplete_validation_work = 0;
        for (const auto &name : aliases) {
            std::set<std::string, std::less<>> opaque_alias_chain;
            if (!is_opaque_typedef(*entries.at(name)->type, entries, incomplete_aggregates,
                                   opaque_alias_chain)) {
                if (has_incomplete_by_value(*entries.at(name)->type, entries,
                                            incomplete_aggregates, incomplete_validation_work))
                    return unsupported("C header alias uses an incomplete aggregate by value");
            }
            std::set<std::string, std::less<>> refs;
            std::unordered_set<const Type *> visited;
            collect_refs(*entries.at(name)->type, refs, visited, ref_work);
            for (const auto &ref : refs) {
                const auto found = entries.find(ref);
                if (found == entries.end()) return invalid("C header refers to missing definition " + ref);
                if (aliases.contains(ref)) dependencies[name].insert(ref);
                else if (found->second->declaration_kind != LibraryDeclarationKind::type)
                    return unsupported("C header type reference names an object or function declaration");
            }
        }
        std::vector<std::string> ordered_aliases;
        std::map<std::string, unsigned, std::less<>> marks;
        std::function<Result<bool>(const std::string &)> visit = [&](const std::string &name) -> Result<bool> {
            if (marks[name] == 2) return true;
            if (marks[name] == 1) return unsupported("C header contains a cyclic typedef alias dependency");
            marks[name] = 1;
            for (const auto &dep : dependencies[name]) {
                auto ok = visit(dep);
                if (!ok) return ok.error();
            }
            marks[name] = 2;
            ordered_aliases.push_back(name);
            return true;
        };
        for (const auto &name : aliases) { auto ok = visit(name); if (!ok) return ok.error(); }
        for (const auto &name : ordered_aliases) {
            auto decl = renderer.declaration(*entries.at(name)->type, name);
            if (!decl) return decl.error();
            out << "typedef " << decl.value() << ";\n";
            if (entries.at(name)->type->kind() != Kind::function && entries.at(name)->type->size()) {
                out << assertion("sizeof(" + name + ") == " + std::to_string(*entries.at(name)->type->size()), "portable alias size mismatch")
                    << assertion("HXTL_ALIGNOF(" + name + ") == " + std::to_string(entries.at(name)->type->alignment()), "portable alias alignment mismatch");
            }
            auto within = check_output_budget();
            if (!within) return within.error();
        }

        // Enums use fixed-width typedefs plus typed constant macros. This
        // preserves values wider than C's implementation-defined enum range.
        for (const auto &[name, entry] : entries) if (entry->declaration_kind == LibraryDeclarationKind::type &&
                                                       entry->type->kind() == Kind::enumeration) {
            std::set<std::string, std::less<>> enumerator_names;
            for (const auto &value : entry->type->enumerator_values()) {
                if (!identifier(value.name) || !enumerator_names.insert(value.name).second)
                    return unsupported("C header enum values require unique C-identifier names");
                const auto constant = name + "_" + value.name;
                if (!identifier(constant)) return unsupported("C header enum constant name exceeds C identifier rules");
                if (!ordinary_names.insert(constant).second)
                    return invalid("Generated C enum constant collides with another declaration name");
                const auto underlying = entry->type->element();
                if (!underlying || !underlying->size() || !*underlying->size() || *underlying->size() > 8)
                    return unsupported("C header enum constants are limited to 64-bit underlying types");
                const auto bits = static_cast<unsigned>(*underlying->size() * 8);
                const auto mask = bits == 64 ? UINT64_MAX : (std::uint64_t{1} << bits) - 1;
                const auto stored = value.value & mask;
                std::string literal;
                if (underlying->is_signed()) {
                    const auto sign = std::uint64_t{1} << (bits - 1);
                    const auto extended = (stored & sign) ? (stored | ~mask) : stored;
                    const auto signed_value = std::bit_cast<std::int64_t>(extended);
                    if (signed_value == std::numeric_limits<std::int64_t>::min())
                        literal = "(-INT64_C(9223372036854775807) - INT64_C(1))";
                    else if (signed_value < 0)
                        literal = "(-INT64_C(" + std::to_string(-signed_value) + "))";
                    else
                        literal = "INT64_C(" + std::to_string(signed_value) + ")";
                } else {
                    literal = "UINT64_C(" + std::to_string(stored) + ")";
                }
                out << "#define " << constant << " ((" << name << ") " << literal << ")\n";
                auto within = check_output_budget();
                if (!within) return within.error();
            }
            out << assertion("sizeof(" + name + ") == " + std::to_string(entry->type->size().value_or(0)), "portable enum size mismatch")
                << assertion("HXTL_ALIGNOF(" + name + ") == " + std::to_string(entry->type->alignment()), "portable enum alignment mismatch");
        }
        out << '\n';

        for (const auto &[name, entry] : entries) {
            const auto &type = *entry->type;
            if (entry->declaration_kind != LibraryDeclarationKind::type ||
                (type.kind() != Kind::structure && type.kind() != Kind::union_type)) continue;
            if (!type.size()) continue; // The tag typedef above is a valid opaque forward declaration.
            if (!type.methods().empty() || !type.static_data_members().empty())
                return unsupported("C header export does not model C++ methods or static data declarations");
            if (type.packing_alignment()) {
                const auto pack = *type.packing_alignment();
                if (!pack || pack > 16 || (pack & (pack - 1)))
                    return unsupported("C header export supports packing alignments 1, 2, 4, 8 and 16 only");
                out << "#pragma pack(push, " << pack << ")\n";
            }
            out << (type.kind() == Kind::structure ? "struct " : "union ") << name << " {\n";
            for (const auto &member : type.members()) {
                if (!member.type || !identifier(member.name)) return unsupported("C header aggregate member requires a C identifier and type");
                if (has_incomplete_by_value(*member.type, entries, incomplete_aggregates,
                                            incomplete_validation_work))
                    return unsupported("C header aggregate member uses an incomplete aggregate by value");
                if (member.virtual_base) return unsupported("C header export does not model virtual base classes");
                if (member.bit_width) return unsupported("C header export does not claim portable bitfield layout");
                if (member.effective_alignment) {
                    const auto alignment = *member.effective_alignment;
                    if (!alignment || alignment > 16 || (alignment & (alignment - 1)))
                        return unsupported("C header member alignment is not portable to C11");
                    out << "    HXTL_ALIGNAS(" << alignment << ") ";
                } else out << "    ";
                auto decl = renderer.declaration(*member.type, member.name);
                if (!decl) return decl.error();
                out << decl.value();
                out << ";\n";
                auto within = check_output_budget();
                if (!within) return within.error();
            }
            out << "};\n";
            if (type.packing_alignment()) out << "#pragma pack(pop)\n";
            out << assertion("sizeof(" + name + ") == " + std::to_string(*type.size()), "portable type size mismatch")
                << assertion("HXTL_ALIGNOF(" + name + ") == " + std::to_string(type.alignment()), "portable type alignment mismatch");
            for (const auto &member : type.members()) if (!member.bit_width) {
                out << assertion("offsetof(" + name + ", " + member.name + ") == " + std::to_string(member.offset), "portable member offset mismatch");
                auto within = check_output_budget();
                if (!within) return within.error();
            }
            auto within = check_output_budget();
            if (!within) return within.error();
            out << '\n';
        }

        for (const auto &[name, entry] : entries) {
            if (entry->declaration_kind == LibraryDeclarationKind::type) continue;
            const auto &type = *entry->type;
            if (has_incomplete_by_value(type, entries, incomplete_aggregates,
                                        incomplete_validation_work))
                return unsupported("C header object or function declaration uses an incomplete aggregate by value");
            if (entry->declaration_kind == LibraryDeclarationKind::function) {
                if (type.kind() != Kind::function) return invalid("Portable function declaration does not contain a function type");
                auto decl = renderer.declaration(type, name);
                if (!decl) return decl.error();
                out << decl.value() << ";\n";
            } else {
                auto decl = renderer.declaration(type, name);
                if (!decl) return decl.error();
                out << "extern " << decl.value() << ";\n";
            }
            auto within = check_output_budget();
            if (!within) return within.error();
        }
        out << "\n#undef HXTL_STATIC_ASSERT\n#undef HXTL_ALIGNOF\n#undef HXTL_ALIGNAS\n";
        if (abi_attributes.sysv) out << "#undef HXTL_SYSV_ABI\n";
        if (abi_attributes.microsoft) out << "#undef HXTL_MS_ABI\n";
        if (abi_attributes.aapcs32) out << "#undef HXTL_AAPCS32\n";
        if (abi_attributes.aapcs32_vfp) out << "#undef HXTL_AAPCS32_VFP\n";
        out << "\n#endif /* " << include_guard << " */\n";
        return out.str();
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot render portable type-library C header"};
    } catch (const std::length_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    }
}
} // namespace hexlab::types
