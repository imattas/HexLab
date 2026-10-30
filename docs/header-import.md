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

Scalar declarations include `float`, `double`, and `long double`. The caller
selects their storage widths with `float_bytes`, `double_bytes`, and
`long_double_bytes`; `long double` defaults to 16 bytes. The corresponding
`*_alignment` options override natural-width alignment when an ABI uses a
different alignment. This allows extended formats such as 80-bit values stored
in a 10-byte object with a 4-byte alignment. A non-power-of-two storage width
requires an explicit power-of-two alignment. These options describe storage
and layout only; the type model does not claim an IEEE encoding or
floating-point calling convention.

Function prototype parameters may use default arguments. The importer skips the
default expression and retains only the parameter's declared type and name;
defaults do not affect the imported function type. The skipped spelling is
bounded by the overall token and nesting limits. Parentheses, brackets, and
braces are balanced, so calls and braced defaults can contain commas. A
top-level comma ends the default and starts the next parameter. Default
expressions containing template-ids with commas are not supported by this
bounded skipping rule. Default values are not evaluated or exported.

The importer also consumes the standard attribute specifiers `[[maybe_unused]]`,
`[[nodiscard]]`, and `[[deprecated]]`, including `[[nodiscard("reason")]]`
and `[[deprecated("message")]]`. These attributes are accepted before a
declaration, between its type and declarator, and after a declarator. They are
discarded because the imported type and layout model does not retain standard
attribute metadata. Other standard attributes, attribute namespaces such as
`[[gnu::...]]`, and arguments other than the optional single string literal
for `nodiscard` or `deprecated` are rejected explicitly.

During class-template instantiation, a function prototype parameter may expand
one bound type pack using the direct spelling `Ts... values`. Each type in the
pack becomes one parameter in the imported function signature, with a
deterministic synthetic parameter name. Empty packs produce no parameters;
expansions are capped at 32 parameters. This supports direct type packs only:
compound patterns, integral/template-name packs, default arguments on an
expanded pack, and parameter-pack expansions in function definitions are not
supported. The shared type model retains the resulting signature, not pack
source metadata.

Class-template bodies also accept the direct data-member pack declaration
`Ts... members;`. Each bound type creates one laid-out data member, with names
`members__pack0`, `members__pack1`, and so on in source order. Expansion is
capped at 32 fields; an empty pack contributes no fields. Only complete object
types are accepted, and member-pack layout uses the aggregate's active packing
cap. Prefix `packed`, `alignas(n)`, `__attribute__((aligned(n)))`, and
`__declspec(align(n))` attributes apply to each expanded field using the same
bounded member-alignment rules as ordinary fields. `vector_size` attributes,
bitfield widths, initializers, compound type patterns, dependent expressions,
and integral or template-name packs on this form remain unsupported. The
synthetic names are importer identifiers for separate layout fields; the type
model does not preserve C++ member-pack lookup semantics.

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
The C++20 form `using enum QualifiedEnum;` imports each named enumerator into
the current namespace as an integral constant, preserving its source value and
source-line metadata. The target must resolve to a modeled enum and every
introduced name must be unambiguous in the destination scope; conflicts fail
the import rather than shadowing another declaration. This adds lookup and
constant-expression visibility only: it does not create replacement enumerator
types or model language linkage.
Namespace aliases are also expanded while resolving qualified enumerator names
in enum value expressions, so forms such as `namespace short_name = api; enum
Flags { combined = short_name::FlagsBase::read | short_name::FlagsBase::write
};` resolve against the original namespace. Alias chains use the same bounded
expansion as qualified type lookup. Enumerator lookup remains source ordered;
an alias does not make a later declaration visible early.
Namespace alias chains and transitive lookup are bounded, and namespace targets
must already have been declared in the input. Inline namespace definitions are
supported in the form `inline namespace v1 { ... }`. Types and supported
templates declared there remain stored under their full name such as
`api::v1::Handle`, while lookup also accepts `api::Handle` and unqualified
lookup from `api` or its nested namespaces. A qualified lookup that finds
different declarations through the enclosing and inline namespace is ambiguous
and fails instead of choosing one. An inline namespace cannot alias a namespace
that was previously declared without `inline`; it can be reopened normally.
Anonymous namespace definitions are supported with stable synthetic components
for declarations in the same lexical namespace scope. Their supported type names
are made visible through the enclosing namespace's implicit using-directive; the
synthetic component remains in the stored qualified name. Namespace members
other than supported types and declarations remain unsupported.

`extern "C"` and `extern "C++"` linkage specifications are accepted in either
single-declaration or braced form when their contents use supported declaration
syntax. The importer preserves the declared type and symbol, but does not model
language-linkage mangling or ABI differences between the two forms. Other
linkage string literals are rejected explicitly.

An integer constant-expression evaluator supports decimal, octal, and
hexadecimal literals; previously bound integral template parameters;
`true`/`false`; parentheses; unary `+`, `-`, `~`; arithmetic `+`, `-`, `*`,
`/`, `%`; shifts `<<`, `>>`; relational `<`, `>`, `<=`, `>=`; equality `==`,
`!=`; logical `&&`, `||`; and bitwise `&`, `^`, `|`, with C++-style operator
precedence. It is used for non-type template
arguments, non-type defaults (which may refer to earlier parameters), and
fixed array extents in instantiated templates. Final non-type values and array
extents must be non-negative; negative results, division by zero, overflow,
unknown names, and unsupported operators fail explicitly. Each expression is
limited to 4096 tokens and operations and the configured parser nesting limit.
Logical operators evaluate both operands; conditional `?:`, comma expressions,
unsigned expression arithmetic, and general C++ constant evaluation are not
implemented. In template argument and default expressions, operators spelled
with `<` or `>` must be parenthesized so they are not confused with template
delimiters. No compiler is invoked.

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
parameter. Compound argument patterns such as `const Types*...`,
`Box<Types>...`, and `(Counts+1)...` can also expand one bound pack. See
[compound template-argument pack expansion](header-compound-pack-expansions.md)
for type, array, callback, integral, and template-name-pack examples and bounds.
Empty packs and alias `<>` argument lists are supported. Template-
template parameters can name and forward previously declared class or alias
templates; nested parameter shapes must match exactly. See
[C++ template declarations](cpp-template-import.md) for examples and limits.
Explicit full specializations may omit the trailing primary-template argument
list as `X<>` when every primary parameter has a default; defaults are bound
left-to-right and matched as concrete specialization arguments. Partial
specialization argument lists may omit trailing primary arguments with defaults
when references in those defaults can be substituted from earlier direct
parameter patterns. Defaults depending on a non-direct earlier pattern fail
explicitly. Default template arguments declared on a partial specialization's
own parameter list remain unsupported because C++ forbids them.
Class templates
instantiate as structure layouts; `class` bodies default methods to private,
while `struct` bodies default methods to public. Data-member visibility is not
retained in the shared type model, but does not affect imported offsets or size.

Template-template parameters are supported in class-template specializations
when they are matched as a direct template name or parameter. Parameter packs
cannot be used in specializations; multiple distinct packs in one argument pattern,
nested ellipses, member/parameter pack expansions,
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

Anonymous structure and union definitions are supported when they provide an
object body, including common C forms such as `typedef struct { int x; } S;`,
`union { int i; float f; } value;`, a named nested field such as
`struct Outer { struct { int x; } inner; };`, and C11 promoted members such as
`struct Outer { int tag; union { int i; float f; }; };`. The importer assigns a
deterministic internal tag to each anonymous definition so the recursive type
graph retains the child layout. A no-declarator anonymous member is represented
as an explicitly flagged, unnamed physical member at its ABI-correct offset;
the child aggregate remains available for recursive field-path inspection.
`Type::member_paths(name)` returns the physical member-index path and cumulative
byte offset for direct or promoted names, retaining each anonymous member in
the path. Multiple paths are reported as ambiguity by the type model; header
import rejects such collisions before publishing the result.
Names promoted through nested anonymous structs/unions are checked against
each other and against directly declared fields and methods. A collision is an
ambiguity error rather than an arbitrary lookup choice. Anonymous member
nesting is bounded to 64 levels. Anonymous tags are scoped under their owning
aggregate, and an anonymous tag cannot be forward-declared without a body.
Layout attributes on no-declarator anonymous members, anonymous aggregate
members inside C++ classes, and nested named aggregate definitions remain
unsupported.

The supported subset includes common C integer and floating scalar spellings,
standard fixed-width and pointer-width aliases, typedef aliases, qualified
pointers, fixed arrays, named structs and unions, enums (including integer
constant assignments and explicit integral underlying types), function prototypes, and pointer-to-function declarators
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
explicit target ABI (`x86_32`, `x86_64`, `aarch64`, or `aarch32`) in
`HeaderImportOptions::target_abi`. The importer accepts positive-width named
and unnamed fields, plus unnamed zero-width struct barriers. Unnamed positive-
width fields consume storage and retain their width/offset in the type graph
with an empty field name. It stores an LSB-relative bit
offset and a byte offset to the allocation unit. Consecutive fields share a
unit only when their exact type, storage size, and effective alignment match;
otherwise a fresh unit is aligned and allocated. This is a deliberately narrow
allocation policy, not a promise to reproduce every compiler's ABI rules.
Bitfield widths may be bounded integer constant expressions, including prior
enum constants and integral template parameters; the expression is capped at
4096 tokens and must evaluate to a nonnegative value within the declared
storage type. General macros are handled by the existing preprocessor, while
unbound names and unsupported operators fail explicitly.
Zero-width union fields, non-integral bases, and widths larger than their
declared storage type are rejected. Anonymous members remain unsupported.

The desktop header-import dialog exposes an AArch32 AAPCS32 ILP32 profile;
it sets pointer and `long` widths to four bytes and selects the existing
AArch32 type-layout ABI. This selects data-model sizes and aggregate layout,
not a compiler-specific calling-convention or bitfield-allocation emulation.

Unknown Microsoft `__declspec` layout attributes are rejected explicitly.

The importer also accepts a bounded set of GNU/Clang declaration attributes
that affect linkage or code generation but do not change the imported type
layout: `visibility("default|hidden|internal|protected")`, `section("...")`,
`alias("...")`, `weakref` (with an optional symbol string), and the no-argument
attributes `weak`, `used`, `unused`, `retain`, `noinline`, `always_inline`,
`cold`, `hot`, `flatten`, `artificial`, `nothrow`, `leaf`, `pure`, `const`,
`malloc`, `returns_nonnull`, and `warn_unused_result`. `deprecated` may have an
optional string message. GCC's double-underscore aliases are accepted for
these spellings. The corresponding bounded MSVC forms `__declspec(dllimport)`,
`dllexport`, `noinline`, `noreturn`, `deprecated`, `restrict`, and `selectany`
are accepted as well. These attributes are discarded because the type graph
does not preserve linker or code-generation metadata. Unknown attributes and
arguments outside this subset still fail; layout and calling-convention
attributes retain their existing semantic handling.

Microsoft `__cdecl`, `__stdcall`,
`__fastcall`, `__thiscall`, and `__vectorcall` keywords are retained on the
resulting function type. The equivalent GNU/Clang attributes `cdecl`,
`stdcall`, `fastcall`, `thiscall`, and `vectorcall` are also retained, together
with x86 `sysv_abi` and `ms_abi` attributes. Both the ordinary and GCC alias
spellings (for example, `sysv_abi` and `__sysv_abi__`) are accepted. Attributes
may precede the base type, appear between the base type and declarator, or
follow a function or function-pointer declarator. Conflicting conventions,
non-function placement, and ambiguous nested function declarators are rejected.
The GNU/Clang `pcs("aapcs-vfp")` attribute is also retained on function types.
The immutable type graph stores calling-convention metadata in codec version
17, and earlier type-record versions remain readable. Importing a convention
does not infer target ABI register or stack behavior, nor validate that the
selected target supports that convention. ABI classification recognizes
`aapcs32_vfp` only with an AArch32 platform default. GCC documents the x86
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
of a structure. Recursive by-value fields, bitfields, incomplete arrays
outside supported static declarations, initializers,
unrecognized attributes, and
unsupported scalar/declarator syntax remain unsupported.
These errors are returned explicitly; no partial symbol table is returned.

File-scope and aggregate-scope `static_assert` and `_Static_assert`
declarations are checked using the bounded integer-constant-expression parser.
Assertions may use previously imported enum constants and expanded object-like
macros, and may include an optional adjacent string-literal message. A false
assertion returns a conflict with its source line and message. Expressions
outside the supported constant-expression subset, including type-form `sizeof`,
are rejected explicitly rather than ignored.

Enum assignments accept bounded integer constant expressions using the
supported evaluator above, including references to earlier
enumerators in the same enum and qualified references to earlier enumerators.
For example, `enum class Mode { read = 1, write = Mode::read << 1 };` and
`enum State { ready = 1, done = State::ready + 1 };` retain exact values.
Qualified names may use their canonical namespace-relative path or begin with
`::`; a leading `::` forces global lookup and never falls back to the current
namespace. Namespace aliases are resolved at each enclosing lexical namespace,
so `namespace api_v2 = vendor::api; enum Mode { read = api_v2::Access::read };`
binds the alias-qualified name to the earlier canonical enumerator. Absolute
alias-qualified names are supported when the alias is visible from global
scope; a leading `::` never uses a namespace-local alias.
Logical `&&` and `||` expressions short-circuit constant evaluation. For
example, `false && (1 / 0)` and `true || (1 / 0)` are accepted as `false` and
`true`; both operands are still parsed, and names in a skipped operand must
still resolve. This prevents an unevaluated divide-by-zero from rejecting an
otherwise valid enumerator expression.
References must name an enumerator already declared in the same enum or a
previously parsed enum visible through the current/enclosing namespace or its
explicit qualified name.
The importer retains each enumerator's line in the preprocessed token stream in
`HeaderImportResult::enum_constant_source_lines`, keyed by the same qualified
name as `enum_constants`; included headers carry their own expanded-stream line
numbers. Expressions outside the evaluator subset remain unsupported. The enum
type graph retains every enumerator name and its exact numeric value,
including negative signed values and the full signed 64-bit minimum. The same
values are also returned in the ordered
`HeaderImportResult::enum_constants`
map for convenient lookup. `types::format_enumerators` renders exact stored
values with signed decimal notation when appropriate. Native project header
import persists enum bodies alongside typedefs, tags, object declarations, and
function prototypes; ABI 1.14 exposes paged exact values through `enum_values`,
while the legacy import summary keeps its typedef/tag and enum-constant counts.
An enum may declare a fixed underlying type, for example
`enum class Opcode : unsigned short { add = 1, jump = 0x8000 };`. The base must
resolve to an unqualified integer type of one through eight bytes, and every
enumerator must fit that exact signed or unsigned range. The selected base is
retained in the type graph and controls the enum size and alignment. Forward
enum declarations and unsigned values above `INT64_MAX` remain unsupported by
the import result's signed enumerator lookup map.
This is a declaration importer rather than a complete C front end: arbitrary
platform header trees may still use unsupported preprocessor features, C++
syntax, anonymous/nested tag scopes, and other compiler-specific layout
extensions.
