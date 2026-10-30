#pragma once

#include "hexlab/types/types.hpp"
#include "hexlab/types/layout.hpp"

#include <cstdint>
#include <map>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab::types {

struct HeaderInclude {
    // Stable identity used as including_id for nested include resolution.
    std::string id;
    std::string contents;
};

struct HeaderImportOptions {
    // Required to import bitfields: their storage-unit rules are target ABI
    // specific. Other declarations retain the historical data-model fields.
    std::optional<Abi> target_abi;
    std::uint8_t pointer_bytes = 8;
    std::uint8_t char_bytes = 1;
    std::uint8_t short_bytes = 2;
    std::uint8_t int_bytes = 4;
    std::uint8_t long_bytes = 8;
    std::uint8_t long_long_bytes = 8;
    std::uint8_t float_bytes = 4;
    std::uint8_t double_bytes = 8;
    std::uint8_t long_double_bytes = 16;
    // Zero keeps the legacy natural-width alignment for float and double.
    // ABI profiles can set explicit alignments, including for x87 extended
    // precision where storage width and alignment differ.
    std::uint8_t float_alignment = 0;
    std::uint8_t double_alignment = 0;
    std::uint8_t long_double_alignment = 0;
    std::uint32_t max_input_bytes = 4u * 1024u * 1024u;
    std::uint32_t max_tokens = 250000;
    std::uint16_t max_nesting = 64;
    std::uint32_t max_array_elements = 1000000;
    std::uint16_t max_include_depth = 32;
    std::uint32_t max_include_files = 256;
    std::uint32_t max_expanded_bytes = 16u * 1024u * 1024u;
    std::uint32_t max_macros = 4096;
    std::uint16_t max_macro_expansion_depth = 32;
    std::uint32_t max_macro_expansions = 100000;
    std::uint16_t max_macro_arguments = 64;
    std::map<std::string, std::string, std::less<>> predefined_macros;
    // The caller controls include lookup (filesystem, project VFS, etc.). Return
    // nullopt for an unresolved include. No filesystem access is implicit.
    std::function<std::optional<HeaderInclude>(std::string_view include_name,
        std::string_view including_id, bool angled)> include_resolver;
};

enum class HeaderSymbolKind { typedef_name, object, function, tag };
enum class HeaderTemplateParameterKind : std::uint8_t { type, non_type, template_template };
struct HeaderTemplateParameter {
    std::string name;
    HeaderTemplateParameterKind kind = HeaderTemplateParameterKind::type;
    bool pack = false;
    TypePtr value_type;
    std::string default_argument;
    std::vector<HeaderTemplateParameter> nested_parameters;
};
struct HeaderTemplateDeclaration {
    std::string name;
    bool is_union = false;
    bool is_alias = false;
    bool is_function = false;
    TypePtr function_type;
    std::vector<HeaderTemplateParameter> parameters;
};
struct HeaderSymbol {
    HeaderSymbolKind kind;
    TypePtr type;
    // Declaration-level object alignment when it cannot be folded into the
    // type itself (currently over-aligned array objects).
    std::optional<std::uint64_t> effective_alignment;
};
struct HeaderImportResult {
    // Ordered maps make results reproducible and convenient to serialize.
    // Namespace-scoped symbols use fully qualified keys such as "outer::T";
    // aggregate and enum tag keys also retain their keyword, e.g. "struct outer::S".
    // Member typedef/using aliases and static data declarations use Owner::Name
    // keys; static declaration access/order is retained on the owning Type.
    std::map<std::string, HeaderSymbol, std::less<>> symbols;
    std::map<std::string, std::int64_t, std::less<>> enum_constants;
    // Line number in the preprocessed token stream for each enumerator name.
    std::map<std::string, std::uint32_t, std::less<>> enum_constant_source_lines;
    // Template declarations retain their parameter kinds and pack shape even
    // when no concrete specialization is instantiated in the imported header.
    std::map<std::string, HeaderTemplateDeclaration, std::less<>> templates;
    // Non-fatal pragma diagnostics, including recognized `#pragma pack(show)`.
    std::vector<std::string> diagnostics;
};

// Parses a deliberately bounded C declaration subset. #include lookup is
// delegated to include_resolver; literal and macro-expanded header names,
// #pragma once, object-like and bounded function-like macros, and simple feature
// guards are handled under the configured limits. Function
// bodies, unrecognized attributes and unknown declarators fail
// explicitly; packed/aligned layout attributes, alignas/_Alignas, and
// #pragma pack forms are supported where the type model can retain their ABI
// effects. Named nested and inline namespaces, qualified aggregate/enum/typedef names,
// namespace aliases, bounded using-namespace lookup, qualified using-declarations, and scoped using type
// aliases, scoped enums with default int representation or a fixed integral
// underlying type, and nested function pointers
// are supported. Class/struct/union declarations may contain method prototypes,
// class-scoped typedef/using type aliases, static data declarations, and access
// labels. Aliases resolve from their declaration onward and export Owner::Alias;
// concrete templates and bound aggregate types can qualify those aliases.
// Static data preserves type/access/source order separately from object layout;
// incomplete static object/array declarations are retained without inventing
// storage. Initializers, inline static definitions, static alignment attributes,
// nested aggregate/enum definitions, method bodies and constructors fail explicitly.
// Bounded alias
// and class/struct/union templates support type, integral non-type, and template-
// template parameters, defaults, and a trailing parameter pack. Integral arguments
// are non-negative integer literals or forwarded bound arguments; integral
// defaults remain literals. These values can drive array extents. A direct
// Pack... template argument expands bound
// type, integral, or template-name packs (including empty packs), with at most 32
// concrete arguments. Alias <> lists can apply defaults or bind empty packs.
// Compound argument patterns may substitute one bound pack into abstract types,
// supported nested template-ids, or bounded integral expressions. Empty packs
// contribute no arguments; every result is checked against its destination
// parameter. Multiple distinct packs in one pattern, nested ellipses, and
// member/function-parameter pack expansions fail explicitly. Concrete aggregate
// names retain their expanded arguments.
// Explicit/partial class-template specializations support type and integral
// non-type parameters with fixed integer literals or direct parameter binding;
// template-template parameters and compound non-type expression patterns remain
// unsupported. Partial specializations of a primary consisting of one type pack
// support one type-pack expansion pattern in the forms T*... and const T*...;
// mixed primary parameters, explicit specializations of primary packs, non-type
// packs, template-template packs, and compound pack patterns remain unsupported.
// Template declarations and parameter kind/pack metadata are preserved in
// HeaderImportResult::templates. Class templates use the structure layout model;
// access labels are retained for methods and static data. Instance data-member
// and member-alias access are not represented by the shared Type model.
// Packing pragmas must occur between declarations, before the aggregates they affect.
// No system compiler is invoked.
HEXLAB_TYPES_EXPORT hexlab::Result<HeaderImportResult>
import_c_header(std::string_view source, const HeaderImportOptions &options = {});

} // namespace hexlab::types
