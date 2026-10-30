# Symbol demangling

HexLab keeps imported and user-provided symbol spellings unchanged. The reusable
`hexlab::symbols::demangle_symbol_name` dispatcher returns a bounded
presentation result; `demangle_cpp_name` remains available for callers that
want C++ ABI parsing only. Demangling never replaces names in loader metadata, project storage, or symbol
identity/index keys. Workspace-generated labels and CLI ELF, Mach-O, and PE PDB
symbol rows display a demangled spelling only when parsing succeeds. These
presentation call sites use the dispatcher, so supported Rust v0 spellings
receive the same bounded display treatment as supported C++ ABI names.

The same presentation layer dispatches Rust v0 symbols (`_R...`) to a
separate bounded parser. This subset renders crate roots and recursively nested
paths with UTF-8 identifiers, ignores nonzero identifier disambiguators for
named items, and labels closure (`C`) and shim (`S`) namespace paths. Unicode
identifiers marked with `u` are decoded with the Rust v0 modified Punycode
encoding, including its underscore escape for the final Punycode delimiter.
The decoder bounds output by the existing demangler limit and rejects invalid
digits, arithmetic overflow, surrogate values, and out-of-range Unicode
scalars. It validates UTF-8 but does not enforce Rust's Unicode XID identifier
profile or normalization. Impl and trait paths, generic arguments, backreferences,
and other namespace-specific forms remain unsupported and preserve the raw
name. An optional direct instantiating-crate path and opaque `.suffix`/`$suffix`
are accepted and omitted from display. Rust symbols remain untouched in stored
metadata and identity keys. The format is documented in the
[rustc book](https://doc.rust-lang.org/stable/rustc/symbol-mangling/v0.html).

The current parser recognizes common Itanium ABI `_Z` names: length-prefixed
identifiers, nested namespaces/classes, template identifier arguments, common
operator names, ordinary function parameter lists, and built-in, pointer,
reference, rvalue-reference, const, and volatile types. Function and
member-function pointer declarators preserve C++ precedence, rendering forms
such as `int (*)(float)` and `int (Widget::*)(float)`. Itanium function types
retain the bounded `Do` non-throwing exception specification as `noexcept`,
including when combined with cv-qualified member-function types and pointer
declarators. Template arguments
support bounded integer literals and recursive `X <expression> E` arithmetic,
comparison, bitwise, logical, assignment, unary, and conditional (`qu`)
expression forms. The
supported expression operands are themselves integer literals; calls, casts,
template-parameter references inside expressions, and other expression
productions remain unsupported. Vendor-qualified types
using `U <source-name> <type>` are presented as a GNU-style
`__attribute__((name))` suffix. Vendor qualifiers may also carry the bounded
template argument list `I...E`; these render with their arguments, for example
as `__attribute__((address_space<1>))`. Type, integral, expression, and pack
arguments use the same bounded presentation grammar as ordinary template
arguments. It recognizes a
bounded Itanium ABI-tag suffix `B<source-name>` on ordinary names and tagged
standard substitutions. Tags are shown explicitly as `[abi:name]` (multiple
tags retain their encoded order) and remain part of the demangler's semantic
substitution key. The syntax follows the
[Itanium ABI tag production](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#abi-tags).
A bounded set of additional encoded floating types is also recognized:
`Df`/`Dd`/`De` for
decimal32/decimal64/decimal128, `Dh` for `_Float16`, `Du` for `char8_t`, and
`DF<number>_` for `_Float<number>`. It also recognizes the bounded Itanium
pack-expansion type form `Dp <type>` and renders its ellipsis after the
expanded type. The GNU/Clang vector extension `Dv<lane-count>_<element-type>`
is rendered symbolically as `vector<element-type, lane-count>`. Lane counts
must be positive and are retained as a number in the display, so their size
does not cause dimension-sized allocation. This presentation identifies the
encoded vector shape only; the parser does not infer target ABI, register
class, alignment, target availability, or floating representation. It recognizes a
bounded C99 complex and imaginary type wrapper: `C <type>` and `G <type>` are
shown with `_Complex` and `_Imaginary` prefixes (for example, `Cf` becomes
`_Complex float`). This reports the encoded type spelling and does not infer
whether a target compiler supports that extension. It recognizes a
bounded subset of Microsoft decorated free and member functions. In addition
to `?name@scope@@Y...` global functions, it parses ordinary
`?method@Class@@...` and nested namespace/class names, access and
static/virtual member-function classes, `const`/`volatile` and
lvalue/rvalue-ref-qualified members, common scalar/pointer/reference types,
bounded rank/dimension encoded array types, non-member and member-function
pointer types with supported calling conventions and parameter lists, and simple type-parameter
class/function template names. Template arguments now recurse through nested
class/struct/union/enum types and nested template instantiations. The bounded
integral non-type subset recognizes MSVC `$0` arguments using single-digit
biased values or rebased hexadecimal `A`Ã¢â‚¬â€œ`P` nibbles terminated by `@`, with
the optional `?` negative marker (for example, `?$Buffer@$03@@` presents as
`Buffer<4>`). MSVC variable symbols now support storage classes `0` through
`4`: private/protected/public static members, globals, and static locals.
Their bounded type grammar covers the same scalar, pointer, reference, array,
and named types as function signatures, with the encoded top-level `const`,
`volatile`, and `const volatile` qualifiers. Unsupported trailing type
qualifiers and malformed or truncated encodings preserve the original symbol.
Common overloaded
operators are rendered from their Microsoft operator codes, including arithmetic,
comparisons, shifts, logical/bitwise operators, indexing, calls, comma,
compound assignments, allocation, and deallocation. The bounded MSVC special-name
subset also renders vftables (`??_7`), vbtables (`??_8`), RTTI type descriptors
(`??_R0`), RTTI base-class descriptors (`??_R1`), RTTI base-class arrays
(`??_R2`), RTTI class-hierarchy descriptors
(`??_R3`), and RTTI complete-object locators (`??_R4`) when their complete
terminators and name/type encodings are valid. Scalar and vector deleting
destructor symbols (`??_G` and `??_E`) are also rendered from their member
function encoding, including access/virtual qualifiers, return type, calling
convention, and the hidden `unsigned int` parameter when present. Microsoft
local-static guard symbols (`??_B`) are rendered from a bounded qualified name,
as are thread-local local-static guard symbols (`??__J`). Both forms accept the
visibility marker (`5` or `4IA`) and an optional encoded scope-depth value.
The marker and depth are presented as encoded metadata; they do not describe
runtime guard behavior. The parser accepts ordinary and supported simple
template scope components here. Local vftables (`??_S`) parse the owner, the
`6B` table qualifiers, and an optional bounded base-path name. Dynamic
initializers (`??__E`) and dynamic atexit destructors (`??__F`) parse qualified
global or static-data-member names and require the exact generated `void
__cdecl()` stub signature. These labels identify compiler-generated symbols;
they do not infer initialization or destruction behavior. Vcall thunks parse the owning scope, the `$B`
marker, the encoded vftable byte offset, the `A` marker, and a supported
calling-convention code. The rendered label reports the offset and convention
without resolving the target or inferring dispatch behavior. Adjustment thunks
and other special names remain unsupported.
For `??_R1`, the bounded presentation grammar is
`??_R1<number><signed-number><number><number><qualified-name>8`; the numeric
fields follow the MSVC number syntax below, and only the second field accepts
the optional negative marker. The result presents their encoded values in ABI
order as `RTTI Base Class Descriptor at (n,n,n,n)`. The parser does not infer
runtime object-layout adjustment semantics from those values. Qualified names
use the existing bounded MSVC scope/template-name subset. LLVM's Microsoft
demangler parses this intrinsic's field order and signedness in its
[parser implementation](https://github.com/microsoft/llvm/blob/master/llvm/lib/Demangle/MicrosoftDemangle.cpp).
It renders recognized
calling-convention markers. The raw spelling
remains available in CLI output next to the rendered form.

The bounded special-member subset also recognizes ordinary MSVC constructor
(`?0`), destructor (`?1`), and conversion-operator (`?B`) names. Constructors
and destructors must be non-static class members and use the encoded `@`
return-type placeholder; conversion targets use the existing bounded type
grammar. These names retain the original spelling on unsupported or malformed
encodings, like other parser results.

The result status distinguishes ordinary names (`not_mangled`), successful
parses (`demangled`), recognized-prefix encodings that this grammar cannot
interpret (`unsupported`), malformed encodings (`malformed`), and configured
input/output/depth/component caps (`resource_limit`). Every unsuccessful result
contains the original input unchanged. Default caps are 4096 input bytes,
16384 rendered bytes, nesting depth 32, and 128 components. The Itanium
parser counts components across the complete parse and separately limits its
substitution dictionary to 256 entries and 64 KiB of retained strings by default
(`max_substitutions` and `max_substitution_bytes`).

Local Itanium names now parse their enclosing function encoding, entity name,
and both decimal discriminator spellings (`_<number>` for values below 10 and
`__<number>_` for values 10 and above). A string-literal local entity (`s`)
is rendered as `<string literal>` with its optional discriminator. The ABI
does not encode the literal contents, so the demangler cannot recover them.
The discriminator is rendered as a decimal suffix on the local entity. Lambda
closure type names (`Ul...E_`) and numbered unnamed types (`Ut..._`) are
rendered as stable placeholders such as
`<lambda(int)#0>` and `<unnamed-type#2>`; this preserves the distinction
between closures without pretending to reconstruct source capture syntax.
These forms remain bounded by the usual input, depth, component, and output
limits. Nested local entities and lambda signatures use the same supported
type grammar as ordinary names.
Discriminator decimals must use canonical spelling (no leading zeroes); the
short `_<number>` form is accepted only below 10, and `__<number>_` only from
10 onward. Noncanonical or incomplete discriminator encodings are malformed
and preserve the original symbol.

This is not a complete implementation of either ABI. The Itanium substitutions
described below, array/function/member-pointer types, and selected template
parameters are recognized; vector support covers the bounded GNU/Clang
`Dv<count>_<type>` production, while other vendor extensions,
default-argument local-name
forms, expression-valued template arguments beyond the bounded integer
expression grammar, and broader operator/type
encodings remain incomplete, including expression calls/casts,
template parameter references inside expressions, and unrecognized vendor
qualifiers. Other Itanium builtin extensions and newer instantiation-dependent
builtin encodings remain unsupported. Microsoft adjustment thunks and other special names,
non-integral template values (including pointers, member pointers, symbol
references, `auto` values, and parameter packs), template backreferences,
many calling-convention/type codes remain unsupported in the Microsoft grammar.
Data-member pointers support the `Q`/`R`/`S`/`T` member-cv qualifier forms with
a bounded owner name and a pointee accepted by the existing type grammar.
Function-pointer support covers non-member
`P`/`Q`/`R`/`S` pointer types with the `6` marker and member-function pointers
with the `8` marker, a bounded owning-class name, supported calling conventions,
and recognized `const`/`volatile` and `&`/`&&` qualifiers. Unsupported owner,
calling-convention, qualifier, or nested declarator forms retain the raw name.
The Itanium pointer forms
described above are supported. Malformed numeric values, missing hexadecimal terminators,
and configured size/depth/component overflows retain the original symbol text.
The `??_R1` integer fields use MSVC's `<number> ::= [?] <non-negative integer>`
encoding: `0` through `9` represent 1 through 10; otherwise one or more `A`–`P`
hexadecimal digits terminated by `@` represent the value (`A` is zero). A
negative marker is accepted only for the second descriptor field. Numeric
values are checked against `uint64_t`; a negative magnitude is limited to
`INT64_MAX`, and the final rendered label is subject to `max_output_bytes`.
Numeric overflow, a negative unsigned field, incomplete encoding, or a missing
final `8` preserves the raw symbol. LLVM documents and implements this grammar in its
[Microsoft demangler](https://github.com/microsoft/llvm/blob/master/llvm/lib/Demangle/MicrosoftDemangle.cpp).
Array ranks and dimensions use ABI-encoded integer forms and remain bounded by
the configured nesting/component limits. The parser deliberately
does not invoke platform demangling libraries or external processes, so results
are consistent across platforms and unsupported names safely remain raw.

The Itanium ABI special-name subset recognizes `TV`, `TT`, `TI`, and `TS` for
virtual tables, VTTs, typeinfo objects, and typeinfo-name objects. The encoded
type is parsed with the same bounded type grammar as ordinary names. It also
recognizes `GV`, `TH`, and `TW` as guard-variable, TLS-initializer, and
thread-local wrapper names, respectively. Those forms parse one complete
mangled object name and reject trailing bytes. Non-virtual (`Th`), virtual
(`Tv`), and covariant-return (`Tc`) thunks parse bounded signed call offsets
and a complete target function encoding. Their rendered names include the
encoded `this` and optional vcall/return adjustments, for example
`virtual thunk [this=-8, vcall=+16] to Widget::run()`. Offset values are
reported as encoded; HexLab does not infer runtime adjustment behavior.
`GR` lifetime-extended temporary names parse their complete object name and
optional base-36 sequence ID; the first temporary has no encoded sequence ID.
Output labels distinguish the first temporary from later sequence IDs without
guessing source-level object contents. Construction vtables (`TC`) are also
recognized in the bounded form `TC <complete-type> <offset>_ <base-type>` and
render as `construction vtable for Base in Complete [offset=+N]`. The signed
offset is reported as encoded; it is not interpreted as a runtime object-layout
adjustment. Both types use the ordinary bounded type grammar, the offset must
fit the signed 64-bit limit, and trailing bytes or malformed encodings preserve
the raw symbol. Other Itanium special names remain unsupported. These
encodings follow the [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html),
which specifies the special-name and lifetime-extended temporary productions.

The ABI transaction-safe entry-point special name `GTt <encoding>` is rendered
as **transaction-safe entry point to** the bounded ordinary function spelling.
Transaction-safe function types encoded with `DxF...E` retain a
`transaction_safe` qualifier in pointer and other declarator contexts; the
combined `DoDxF...E` form preserves both `noexcept` and the transaction-safe
qualifier. These labels report mangled type/name facts only and do not assert
that HexLab can execute the function transactionally. The productions follow
the Itanium ABI's [transaction-safe function entry-point and type rules](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#transaction-safe-function-entry-points).

## Itanium compression and backreferences

The Itanium parser supports all seven standard abbreviations: `St` (`std`),
`Sa` (`std::allocator`), `Sb` (`std::basic_string`), `Ss` (the complete char
basic_string specialization), and `Si`/`So`/`Sd` (the corresponding char
basic_istream/basic_ostream/basic_iostream specializations). The complete forms
are rendered explicitly, including character traits and allocator arguments.
`St` works in both unscoped standard names and nested prefixes; allocator and
basic_string template prefixes require template arguments.

General substitutions use `S_` for dictionary entry zero and `S<seq-id>_` for
entry `seq-id + 1`, with checked uppercase base-36 decoding. Missing terminators,
invalid digits, noncanonical leading zeroes, forward/out-of-range references,
and substitutions used in incompatible name/template/type positions preserve
the original symbol with a failure status. Index arithmetic and configured
dictionary caps are checked before lookup; no storage is allocated by index.

The dictionary follows component-before-composite ordering for supported name
prefixes, template prefixes/specializations, and non-builtin compound types.
Builtins, terminal function/operator names, repeated entities, and predefined
standard abbreviations do not consume new slots. Entries retain structured
function/array/member-pointer declarators, including their insertion point,
rather than flattened display strings. Reusing a type therefore preserves
parentheses, indirection and qualifier placement. Member-function types retain
their owning-class identity separately from namespace function types.

Function-template names consume their encoded return type before parameters.
Supported decimal `T_`/`T<number>_` references retain type structure and remain
distinct dictionary entities from their concrete display types. Nested type
arguments restore the enclosing template-argument scope. Non-type arguments
and packs remain presentation-only and cannot be substituted as a type.

Every intermediate string and expanded backreference is bounded by the output
limit, and retained dictionary strings have a separate aggregate byte budget.
Parsing depth and total component work remain bounded even when a symbol uses
many references. Unsupported productions fail the complete parse; no partial
presentation replaces raw identity. Unrecognized local/lambda/special forms,
dependent qualified/template-template names, ref-qualified function-type
encodings, and expression calls/casts remain outside this slice.
Incomplete/cv-qualified array declarators, dependent `noexcept(expression)` and
dynamic exception specifications, and other unproven qualifier forms also fail
closed.

Source review covered substitution ordering, kind checks, standard forms,
base-36 overflow and indexes, nested template scope, declarator reuse, member
function identity, and intermediate/output/dictionary limits against the
[Itanium ABI compression rules](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-compression).
No tests were added or run for this slice; serial symbols/consumer compilation
is a separate integration check.
