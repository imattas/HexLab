# C++ symbol presentation

HexLab keeps imported and user-provided symbol spellings unchanged. The reusable
`hexlab::symbols::demangle_cpp_name` helper returns a bounded presentation
result; it never replaces names in loader metadata, project storage, or symbol
identity/index keys. Workspace-generated labels and CLI ELF, Mach-O, and PE PDB
symbol rows display a demangled spelling only when parsing succeeds.

The current parser recognizes common Itanium ABI `_Z` names: length-prefixed
identifiers, nested namespaces/classes, template identifier arguments, common
operator names, ordinary function parameter lists, and built-in, pointer,
reference, rvalue-reference, const, and volatile types. Function and
member-function pointer declarators preserve C++ precedence, rendering forms
such as `int (*)(float)` and `int (Widget::*)(float)`. Template arguments
support bounded integer literals and recursive `X <expression> E` arithmetic,
comparison, bitwise, logical, assignment, unary, and conditional (`qu`)
expression forms. The
supported expression operands are themselves integer literals; calls, casts,
template-parameter references inside expressions, and other expression
productions remain unsupported. Vendor-qualified types
using `U <source-name> <type>` are presented as a GNU-style
`__attribute__((name))` suffix. It recognizes a
bounded subset of Microsoft decorated free and member functions. In addition
to `?name@scope@@Y...` global functions, it parses ordinary
`?method@Class@@...` and nested namespace/class names, access and
static/virtual member-function classes, `const`/`volatile` and
lvalue/rvalue-ref-qualified members, common scalar/pointer/reference types,
bounded rank/dimension encoded array types, and simple type-parameter
class/function template names. Template arguments now recurse through nested
class/struct/union/enum types and nested template instantiations. The bounded
integral non-type subset recognizes MSVC `$0` arguments using single-digit
biased values or rebased hexadecimal `A`Ã¢â‚¬â€œ`P` nibbles terminated by `@`, with
the optional `?` negative marker (for example, `?$Buffer@$03@@` presents as
`Buffer<4>`). Common overloaded
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
convention, and the hidden `unsigned int` parameter when present. Vcall and
adjustment thunks, local tables, and other special names remain unsupported.
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
and both decimal discriminator spellings (`_<number>` and `__<number>_`). The
discriminator is rendered as a decimal suffix on the local entity. Lambda closure type names (`Ul...E_`) and numbered
unnamed types (`Ut..._`) are rendered as stable placeholders such as
`<lambda(int)#0>` and `<unnamed-type#2>`; this preserves the distinction
between closures without pretending to reconstruct source capture syntax.
These forms remain bounded by the usual input, depth, component, and output
limits. Nested local entities and lambda signatures use the same supported
type grammar as ordinary names.

This is not a complete implementation of either ABI. The Itanium substitutions
described below, array/function/member-pointer types, and selected template
parameters are recognized; vendor extensions, local-name discriminator
variants beyond these two discriminator productions, string-literal local
names, expression-valued template arguments beyond the bounded integer
expression grammar, and broader operator/type
encodings remain incomplete, including expression calls/casts,
template parameter references inside expressions, and unrecognized vendor
qualifiers. Microsoft thunks and other special names,
non-integral template values (including pointers, member pointers, symbol
references, `auto` values, and parameter packs), template backreferences,
pointer-to-member and function-pointer types, and many calling-convention/type
codes are unsupported in the Microsoft grammar. The Itanium pointer forms
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
presentation replaces raw identity. Local/lambda/special names, dependent
qualified/template-template names, ref-qualified function-type encodings,
expression calls/casts, and vendor qualifier template arguments
remain outside this slice. Incomplete/cv-qualified array declarators and other
unproven qualifier forms also fail closed.

Source review covered substitution ordering, kind checks, standard forms,
base-36 overflow and indexes, nested template scope, declarator reuse, member
function identity, and intermediate/output/dictionary limits against the
[Itanium ABI compression rules](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-compression).
No tests were added or run for this slice; serial symbols/consumer compilation
is a separate integration check.
