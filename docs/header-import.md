# C header type import

`hexlab/types/header_import.hpp` provides `import_c_header`, a local, bounded
parser for declarations. It does not invoke a compiler or access the filesystem.
The caller may select pointer and scalar sizes for the target ABI, provide
predefined macros, and supply an `include_resolver` callback. The resolver
receives the include spelling, the including source's stable ID, and whether
the spelling used angle brackets; it returns the contents and stable ID of the
selected header. This lets a project provide its own filesystem or virtual-file
policy without giving the importer ambient file access. Source bytes, total
expanded bytes, include depth and count, macro count and expansion depth,
invocation count and argument count, token count, parser nesting, and fixed
array extents all have configurable limits. Macro expansion depth has a hard
ceiling of 256 even if a caller requests a larger value, to bound recursive
expansion stack use.
Results use ordered symbol and enum-value maps for stable output.

Named nested namespaces can be reopened and may contain qualified type
using-declarations (`using api::Handle;`), `using` type aliases
(`using Handle = api::Handle;`), namespace aliases
(`namespace api_v2 = vendor::api;`), and `using namespace` directives. Alias
types are stored under their fully qualified symbol names and retain the same
immutable type identity as their target. Namespace aliases expand in qualified
type names, and `using namespace` directives participate in unqualified type
lookup within their declaring namespace and nested namespaces. Lookup follows
transitive using-directives with a visited set; if distinct type identities
match the same unqualified name, import fails with an ambiguity diagnostic.
Qualified type using-declarations import a known type into the current
namespace under its final name; they do not import functions or enumerators.
Unknown or conflicting targets fail explicitly.
Namespace alias chains and transitive lookup are bounded, and namespace targets
must already have been declared in the input. Inline namespace definitions are
supported in the form `inline namespace v1 { ... }`. Types and supported
templates declared there remain stored under their full name such as
`api::v1::Handle`, while lookup also accepts `api::Handle` and unqualified
lookup from `api` or its nested namespaces. A qualified lookup that finds
different declarations through the enclosing and inline namespace is ambiguous
and fails instead of choosing one. An inline namespace cannot alias a namespace
that was previously declared without `inline`; it can be reopened normally.
Anonymous namespaces and namespace members other than types remain unsupported.

An integer constant-expression evaluator supports decimal, octal, and
hexadecimal literals; previously bound integral template parameters;
`true`/`false`; parentheses; unary `+`, `-`, `~`; arithmetic `+`, `-`, `*`,
`/`, `%`; and bitwise `&`, `^`, `|`. It is used for non-type template
arguments, non-type defaults (which may refer to earlier parameters), and
fixed array extents in instantiated templates. Final non-type values and array
extents must be non-negative; negative results, division by zero, overflow,
unknown names, and unsupported operators fail explicitly. Each expression is
limited to 4096 tokens and operations and the configured parser nesting limit.
No compiler is invoked.

Alias and `class`/`struct`/`union` templates support type parameters,
integral non-type parameters, template-template parameters, and a trailing
parameter pack. Type parameters may have type defaults. Alias
non-type parameters accept non-negative integer literals and literal defaults,
and those values can supply fixed array extents in the alias target. See
[integral non-type alias templates](header-non-type-alias-templates.md) for alias
examples and limits. Type arguments may be named types,
qualified types, pointers, arrays, function pointers, or nested supported
templates. Struct and union templates are instantiated when referenced; the
resulting concrete layout is stored under a name such as `Box<int>`. An explicit
specialization such as `template<> struct Box<int> { ... };` overrides the
primary template for that exact argument identity. Partial specializations
support direct type parameters (`Box<T>`), pointer parameters (`Box<T*>`),
`const T*` patterns, integral non-type arguments that are direct parameter
names, integer literals, or bounded constant expressions, and
template-template arguments that are direct
template parameter names or fixed template names. See
[integral non-type class-template specializations](header-non-type-specializations.md)
for examples. Specializations must follow a previously declared primary
template. Default arguments are applied from left to right. A direct `Pack...`
argument forwards a bound type, integral, or template-name pack into a nested
template argument list, checking every expanded argument against its destination
parameter. Empty packs and alias `<>` argument lists are supported. Template-
template parameters can name and forward previously declared class or alias
templates; nested parameter shapes must match exactly. See
[C++ template declarations](cpp-template-import.md) for examples and limits.
Class templates
instantiate as structure layouts; `class` bodies default methods to private,
while `struct` bodies default methods to public. Data-member visibility is not
retained in the shared type model, but does not affect imported offsets or size.

Template-template parameters are supported in class-template specializations
when they are matched as a direct template name or parameter. Parameter packs
cannot be used in specializations; compound pack patterns, member/parameter pack expansions,
function-template
specializations, explicit alias-template specializations, forward-declared
templates, and nested class-template definitions are unsupported. Type
specialization patterns outside `T`, `T*`, `const T*`, and fixed types are also
unsupported.
Dependent integral non-type specialization expressions are supported when
every referenced parameter is deduced by another pattern argument. Expressions
are checked only after other pattern arguments have deduced their values; the
importer does not invert expressions or perform general C++ template argument
deduction. Negative results, unknown names, unsupported operators, and values
outside the bounded signed expression range fail explicitly.
Partial-specialization patterns are compared per primary argument; a candidate
must be at least as strong for every argument and strictly stronger for one to
be preferred. Incomparable or equivalent matches fail as ambiguous. Fixed
template-template names use normal namespace, using-directive, and inline-
namespace resolution and must match the primary parameter's nested shape.
Dependent arithmetic patterns do not add a specificity advantage over direct
parameter patterns, so overlapping arithmetic candidates may remain ambiguous.
Template argument and parameter counts are capped at 32;
recursive alias expansion and template instantiation obey the configured parser
nesting bound. Unsupported syntax returns an explicit error.

The supported subset includes common C integer and floating scalar spellings,
standard fixed-width and pointer-width aliases, typedef aliases, qualified
pointers, fixed arrays, named structs and unions, enums (including integer
constant assignments), function prototypes, and pointer-to-function declarators
(including typedefs and variadic signatures), arrays of function pointers,
pointers to arrays, and nested combinations. Declarator binding follows C
precedence: `int *table[2]` is an array of pointers, while `int (*row)[2]` is a
pointer to an array. Aggregate field offsets, alignment, and final size are
computed with ordinary natural alignment. Array parameters are adjusted to
pointers. Unnamed prototype parameters receive
stable `argN` names because the type graph requires parameter names.

Ordinary `class` declarations and class/struct/union member typedefs, type
aliases, and static data declarations are retained as described in
[C++ member declaration import](header-cpp-member-import.md). Member aliases
remain under the declaring aggregate's scope, including concrete template
instances. Static data uses existing declaration metadata and contributes no
instance size, alignment, field offset, or bitfield allocation unit.


GNU/Clang `__attribute__((packed))` (also spelled
`__attribute__((__packed__))`) is accepted between `struct` or `union` and
its tag. Packed aggregate fields are laid out at byte alignment and the
aggregate alignment is one. The same attribute on an individual member lowers
that member's alignment to one while preserving natural alignment for other
members. An explicit `aligned(n)` or `__declspec(align(n))` on a member records
its exact effective alignment, including over-alignment beyond the scalar's
natural alignment. Explicit member alignment overrides the active pack cap for
that field and raises the containing aggregate alignment as needed. Effective
alignment survives type serialization and is used by the reusable layout
calculator.

`#pragma pack(n)`, `#pragma pack()`, push/pop, and named MSVC-style
`#pragma pack(push, name, n)` / `#pragma pack(pop, name)` are supported between
declarations. Named pop restores the saved cap and discards nested entries up
through the named push, matching the compiler stack behavior. GCC/Clang
`__attribute__((aligned(n)))` and MSVC `__declspec(align(n))` are supported on
aggregate declarations, including prefix, tag, and trailing placements. The
alignment must be a power of two from 1 through 4096. It raises aggregate
alignment and tail padding while `packed` and active pack caps still control
member placement. Combined GNU attributes such as `packed, aligned(16)` are
accepted. GNU `aligned` without an explicit value and aligned scalar objects
remain unsupported and fail explicitly. Prefix, between-type-and-declarator,
and trailing aligned/packed attributes on named aggregate members are
supported. Named integral bitfields are supported when the caller supplies an
explicit target ABI (`x86_32`, `x86_64`, or `aarch64`) in
`HeaderImportOptions::target_abi`. The importer accepts positive-width named
fields and unnamed zero-width struct barriers. It stores an LSB-relative bit
offset and a byte offset to the allocation unit. Consecutive fields share a
unit only when their exact type, storage size, and effective alignment match;
otherwise a fresh unit is aligned and allocated. This is a deliberately narrow
allocation policy, not a promise to reproduce every compiler's ABI rules.
Unnamed nonzero fields, zero-width union fields, non-integral bases, and widths
larger than their declared storage type are rejected. Anonymous members remain
unsupported.

Unknown Microsoft `__declspec` layout attributes are rejected explicitly.
Microsoft `__cdecl`, `__stdcall`,
`__fastcall`, `__thiscall`, and `__vectorcall` keywords are retained on the
resulting function type. The equivalent GNU/Clang attributes `cdecl`,
`stdcall`, `fastcall`, `thiscall`, and `vectorcall` are also retained, together
with x86 `sysv_abi` and `ms_abi` attributes. Both the ordinary and GCC alias
spellings (for example, `sysv_abi` and `__sysv_abi__`) are accepted. Attributes
may precede the base type, appear between the base type and declarator, or
follow a function or function-pointer declarator. Conflicting conventions,
non-function placement, and ambiguous nested function declarators are rejected.
The immutable type graph stores this metadata in codec version 7; importing the
attribute does not infer target ABI register or stack behavior, nor validate
that the selected target supports that convention. GCC documents the x86
`sysv_abi` and `ms_abi` attributes as function-specific calling conventions
([x86 Function Attributes](https://gcc.gnu.org/onlinedocs/gcc/x86-Attributes.html)).

GNU/Clang `vector_size(bytes)` and `__vector_size__(bytes)` are supported on
typedef declarations with a complete integer or floating scalar base. The size
must be a power of two from 1 through 4096 bytes and an exact multiple of the
scalar size; the importer represents the result as an existing fixed-lane
vector type, using the vector width for its alignment. Vector types can then be
used in ordinary pointer and array declarators. The bounded importer does not
support variable declarations, function-return placement, an attribute applied
after an array or pointer declarator, non-scalar bases, or target-specific
vector ABI rules.
GCC specifies the attribute size in bytes and requires a power-of-two multiple
of the base type size ([Common Attributes: `vector_size`](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html#Common-Attributes)).

The bounded preprocessor applies C backslash-newline line splicing, removes
comments outside string and character literals while preserving line breaks,
then reads directives and expands object-like macros, fixed-parameter
function-like macros, and standard variadic function-like macros using
`...`/`__VA_ARGS__`. Arguments are parsed across nested parentheses, expanded
before substitution, substituted only at identifier-token boundaries, and
rescanned under the same depth, invocation-count, and output-size limits.
The `defined` operator is recognized as a complete identifier, so names such as
`definedness` still undergo ordinary macro expansion. It supports
`#undef`, `#ifdef`, `#ifndef`, `#if` and `#elif` integer constant expressions,
`#else`, `#endif`, and quoted or angled includes through the resolver. Include
operands may be object-like macro expansions such as `#define API_HEADER
"api.h"` followed by `#include API_HEADER`; directly written header names are
passed to the resolver without expanding identifiers inside the name. The
compiler extension `#pragma once` is honored using the resolver's stable header
ID, so repeated and recursive includes after the pragma are skipped even when
they use different spellings. The
preprocessor supports C++20 `__VA_OPT__(tokens)` inside variadic macro
replacements. It includes the parenthesized token sequence when the expanded
variadic arguments contain tokens and removes the complete construct when
they are empty; nested `__VA_OPT__` constructs are bounded by the configured
macro expansion depth. Use of `__VA_OPT__` in a non-variadic macro, or without
its required parenthesized sequence, fails explicitly.
The expression evaluator supports 64-bit signed and unsigned integer literals with
decimal, octal, or hexadecimal spelling and standard `U`/`L`/`LL` suffix
combinations. Unsuffixed nondecimal constants use unsigned interpretation when
their value exceeds the signed 64-bit range. Ordinary character constants use
the selected execution-character byte values; standard simple, octal, and
hexadecimal escapes are accepted, and up to four bytes are packed in source
order as an implementation-defined multi-character constant. Wide and UTF-
prefixed character constants are rejected. Parentheses,
unary `+ - ! ~`, multiplicative and additive arithmetic, shifts, comparisons,
equality, bitwise operators, logical operators, and `?:` with C-like precedence.
Logical and conditional branches are parsed but only the selected side is
evaluated, avoiding false division-by-zero errors in skipped branches. Undefined
identifiers evaluate to zero after macro expansion. Signed overflow,
division by zero, invalid shifts, and values outside the supported 64-bit
domain produce explicit errors; unsigned arithmetic follows modulo-2^64
semantics. Comma expressions and compiler-specific operators remain
unsupported. Function-like macros support parameter stringification (`#`) and
token pasting (`##`) with raw arguments at those operators and rescanning of
the resulting replacement. Pasted spellings must form one bounded token; empty
placemarker pastes and complex multi-token paste operands are rejected. The
preprocessor also rejects `#include_next`, unresolved includes, and recursive
unguarded includes explicitly with an unsupported, malformed, or resource-limit
error. Predefined macros use
`HeaderImportOptions::predefined_macros` and are treated as object-like macros.

Function bodies and other unsupported syntax are rejected. The importer
supports pointer references to aggregates declared later, including self-
recursive and mutually recursive structures. Forward struct/union tags are
retained as incomplete aggregate definitions, while references from pointers
remain symbolic named references so a later full definition can resolve them.
Completing a forward tag replaces its incomplete tag entry. An incomplete
aggregate cannot be laid out, and an object declared by value before a complete
definition is rejected. A flexible array is accepted only as the final member
of a structure. Recursive by-value fields, bitfields, anonymous aggregates,
incomplete arrays outside supported static declarations, initializers,
unrecognized attributes, and
unsupported scalar/declarator syntax remain unsupported.
These errors are returned explicitly; no partial symbol table is returned.

The enum type graph retains every enumerator name and its exact numeric value,
including negative signed values and the full signed 64-bit minimum. The same
values are also returned in the ordered `HeaderImportResult::enum_constants`
map for convenient lookup. `types::format_enumerators` renders exact stored
values with signed decimal notation when appropriate. Native project header
import persists enum bodies alongside typedefs, tags, object declarations, and
function prototypes; ABI 1.14 exposes paged exact values through `enum_values`,
while the legacy import summary keeps its typedef/tag and enum-constant counts.
This is a declaration importer rather than a complete C front end: arbitrary
platform header trees may still use unsupported preprocessor features, C++
syntax, anonymous/nested tag scopes, and other compiler-specific layout
extensions.
